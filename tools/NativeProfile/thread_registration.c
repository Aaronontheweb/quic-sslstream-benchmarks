#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

extern void ProfilerRegisterThread(void);
extern int ProfilerStart(const char *path);
extern void ProfilerStop(void);
static int (*real_create)(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
static int audit_fd = -1;
static int control_fd = -1;
static int control_write_fd = -1;
static int acknowledgement_fd = -1;
static pthread_t control_thread;
static int control_started;
static int control_joined;
static pthread_mutex_t join_lock = PTHREAD_MUTEX_INITIALIZER;

struct entry
{
    void *(*start)(void *);
    void *argument;
};

static void audit(const char *kind)
{
    if (audit_fd < 0) return;
    char line[128];
    int length = snprintf(line, sizeof(line), "%s %ld\n", kind, syscall(SYS_gettid));
    if (length <= 0 || length >= (int)sizeof(line) || write(audit_fd, line, length) != length)
        _exit(90);
}

static void *registered_entry(void *argument)
{
    struct entry entry = *(struct entry *)argument;
    free(argument);
    // Exactly once at pthread entry. Gperftools owns the per-thread timer and TLS cleanup.
    ProfilerRegisterThread();
    audit("registered");
    return entry.start(entry.argument);
}

static void acknowledge(const char *kind, const char *path)
{
    struct timespec stamp;
    struct rusage usage;
    if (clock_gettime(CLOCK_MONOTONIC, &stamp) != 0 || getrusage(RUSAGE_SELF, &usage) != 0) _exit(94);
    char line[PATH_MAX + 256];
    int length = snprintf(line, sizeof(line), "%s %s %.9f %.9f %.9f\n", kind, path,
        stamp.tv_sec + stamp.tv_nsec / 1e9,
        usage.ru_utime.tv_sec + usage.ru_utime.tv_usec / 1e6,
        usage.ru_stime.tv_sec + usage.ru_stime.tv_usec / 1e6);
    if (length <= 0 || length >= (int)sizeof(line) || write(acknowledgement_fd, line, length) != length) _exit(95);
}

static void *control(void *unused)
{
    (void)unused;
    if (pthread_setname_np(pthread_self(), "profiler ctl") != 0) _exit(96);
    FILE *input = fdopen(control_fd, "r");
    if (input == NULL) _exit(97);
    char command[PATH_MAX + 16];
    char active[PATH_MAX] = "";
    while (fgets(command, sizeof(command), input) != NULL)
    {
        command[strcspn(command, "\r\n")] = '\0';
        if (strncmp(command, "START ", 6) == 0 && active[0] == '\0' && strlen(command + 6) < sizeof(active))
        {
            if (!ProfilerStart(command + 6)) _exit(98);
            strcpy(active, command + 6);
            acknowledge("STARTED", active);
        }
        else if (strcmp(command, "STOP") == 0 && active[0] != '\0')
        {
            ProfilerStop();
            acknowledge("STOPPED", active);
            active[0] = '\0';
        }
        else if (strcmp(command, "QUIT") == 0)
        {
            if (active[0] != '\0')
            {
                ProfilerStop();
                acknowledge("STOPPED", active);
            }
            acknowledge("QUITTED", "-");
            break;
        }
        else
            _exit(99);
    }
    fclose(input);
    return NULL;
}

void diagnostic_control_join(void)
{
    if (pthread_mutex_lock(&join_lock) != 0) _exit(102);
    if (control_started && !control_joined)
    {
        if (pthread_join(control_thread, NULL) != 0) _exit(103);
        control_joined = 1;
    }
    if (pthread_mutex_unlock(&join_lock) != 0) _exit(104);
}

__attribute__((constructor)) static void initialize(void)
{
    real_create = dlsym(RTLD_NEXT, "pthread_create");
    if (real_create == NULL) _exit(91);
    const char *path = getenv("PROFILER_THREAD_AUDIT");
    if (path != NULL)
    {
        audit_fd = open(path, O_CREAT | O_WRONLY | O_APPEND | O_CLOEXEC, 0600);
        if (audit_fd < 0) _exit(92);
    }
    // The dependency's own initializer registered main; registering it again creates a second timer.
    audit("main_observed");
    const char *fifo = getenv("PROFILER_CONTROL_FIFO");
    const char *acknowledgement = getenv("PROFILER_CONTROL_ACK");
    if (fifo != NULL && acknowledgement != NULL)
    {
        control_fd = open(fifo, O_RDWR | O_CLOEXEC);
        control_write_fd = dup(control_fd);
        acknowledgement_fd = open(acknowledgement, O_CREAT | O_WRONLY | O_APPEND | O_CLOEXEC, 0600);
        if (control_fd < 0 || control_write_fd < 0 || acknowledgement_fd < 0) _exit(100);
        if (pthread_create(&control_thread, NULL, control, NULL) != 0) _exit(101);
        control_started = 1;
    }
}

__attribute__((destructor)) static void finalize(void)
{
    if (control_started && !control_joined)
    {
        if (write(control_write_fd, "QUIT\n", 5) != 5) _exit(105);
        diagnostic_control_join();
    }
    if (control_write_fd >= 0) close(control_write_fd);
    if (acknowledgement_fd >= 0) close(acknowledgement_fd);
    if (audit_fd >= 0) close(audit_fd);
}

int pthread_create(pthread_t *thread, const pthread_attr_t *attributes, void *(*start)(void *), void *argument)
{
    if (real_create == NULL) _exit(93);
    struct entry *entry = malloc(sizeof(*entry));
    if (entry == NULL) return ENOMEM;
    entry->start = start;
    entry->argument = argument;
    int status = real_create(thread, attributes, registered_entry, entry);
    if (status != 0) free(entry);
    return status;
}

double diagnostic_thread_cpu(void)
{
    struct timespec value;
    if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &value) != 0) abort();
    return value.tv_sec + value.tv_nsec / 1e9;
}

static __thread volatile uint64_t observed;
__attribute__((noinline, noclone)) void diagnostic_native_burn(double cpu_seconds)
{
    double start = diagnostic_thread_cpu();
    do
    {
        uint64_t value = observed + 1;
        for (unsigned i = 0; i < 100000; ++i)
            value = value * 2862933555777941757ULL + 3037000493ULL;
        observed = value;
    } while (diagnostic_thread_cpu() - start < cpu_seconds);
}

const char *diagnostic_signal_owner(int signal_number)
{
    struct sigaction action;
    if (sigaction(signal_number, NULL, &action) != 0) return "sigaction_failed";
    if (action.sa_handler == SIG_DFL) return "default";
    if (action.sa_handler == SIG_IGN) return "ignored";
    Dl_info info;
    void *handler = (action.sa_flags & SA_SIGINFO) ? (void *)action.sa_sigaction : (void *)action.sa_handler;
    return dladdr(handler, &info) && info.dli_fname != NULL ? info.dli_fname : "unresolved";
}
