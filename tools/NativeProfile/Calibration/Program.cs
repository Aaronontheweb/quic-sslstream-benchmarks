#nullable enable
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text.Json;

internal static class Program
{
    private const string Bridge = "qss-profile-bridge";

    static Program()
    {
        NativeLibrary.SetDllImportResolver(typeof(Program).Assembly, (name, _, _) =>
            name == Bridge ? NativeLibrary.Load(Environment.GetEnvironmentVariable("QSS_PROFILE_BRIDGE")
                ?? throw new InvalidOperationException("QSS_PROFILE_BRIDGE is required")) : nint.Zero);
    }

    [DllImport(Bridge, EntryPoint = "diagnostic_thread_id")]
    private static extern int NativeThreadId();
    private static long _observed;

    [DllImport(Bridge, EntryPoint = "diagnostic_native_burn")]
    private static extern void NativeBurn(double seconds);
    [DllImport(Bridge, EntryPoint = "diagnostic_thread_cpu")]
    private static extern double ThreadCpu();
    [DllImport(Bridge, EntryPoint = "diagnostic_signal_owner")]
    private static extern nint SignalOwner(int signal);
    [DllImport(Bridge, EntryPoint = "diagnostic_control_join")]
    private static extern void JoinControl();

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void ManagedAlpha(double seconds)
    {
        var start = ThreadCpu();
        var value = 1L;
        do
        {
            for (var i = 0; i < 100_000; ++i)
                value = unchecked(value * 6364136223846793005L + 1442695040888963407L);
            Volatile.Write(ref _observed, value);
        } while (ThreadCpu() - start < seconds);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void ManagedAllocate(double seconds)
    {
        var start = ThreadCpu();
        var retained = new byte[64][];
        var index = 0;
        do
        {
            retained[index++ % retained.Length] = new byte[4096];
        } while (ThreadCpu() - start < seconds);
        GC.KeepAlive(retained);
    }

    private static void Control(string command, string expected, string profile)
    {
        var fifo = Environment.GetEnvironmentVariable("PROFILER_CONTROL_FIFO")!;
        var acknowledgement = Environment.GetEnvironmentVariable("PROFILER_CONTROL_ACK")!;
        using (var output = new StreamWriter(new FileStream(fifo, FileMode.Open, FileAccess.Write)))
            output.WriteLine(command);
        var deadline = Stopwatch.StartNew();
        while (deadline.Elapsed < TimeSpan.FromSeconds(5))
        {
            if (File.Exists(acknowledgement) && File.ReadLines(acknowledgement).Any(line => line.StartsWith(expected + " " + profile + " ", StringComparison.Ordinal)))
                return;
            Thread.Sleep(1);
        }
        throw new TimeoutException("Profiler acknowledgement missing");
    }

    private static async Task Main()
    {
        Console.WriteLine(JsonSerializer.Serialize(new { pid = Environment.ProcessId, framework = RuntimeInformation.FrameworkDescription,
            signal27Owner = Marshal.PtrToStringAnsi(SignalOwner(27)), signal12Owner = Marshal.PtrToStringAnsi(SignalOwner(12)) }));
        if (!(Marshal.PtrToStringAnsi(SignalOwner(27))?.Contains("libprofiler", StringComparison.Ordinal) ?? false))
            throw new InvalidOperationException("CoreCLR signal ownership conflicts with profiler");
        ManagedAlpha(.05);
        NativeBurn(.05);
        await Task.Run(() => ManagedAllocate(.05));
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        using var process = Process.GetCurrentProcess();
        foreach (var phase in new[] { "native", "managed", "sleep", "mixed", "filtered-native", "filtered-managed" })
        {
            process.Refresh();
            var cpuStart = process.TotalProcessorTime;
            var wall = Stopwatch.StartNew();
            var profile = Path.Combine(Environment.GetEnvironmentVariable("PROFILER_OUTPUT_ROOT")!, phase + ".prof");
            using var go = new ManualResetEventSlim();
            using var ready = new ManualResetEventSlim();
            var selectedTid = 0;
            var nativeCpu = 0.0;
            var managedCpu = 0.0;
            Thread? nativeControl = null;
            Thread? managedControl = null;
            var filtered = phase.StartsWith("filtered-", StringComparison.Ordinal);
            if (filtered)
            {
                nativeControl = new Thread(() =>
                {
                    if (phase == "filtered-native")
                    {
                        Volatile.Write(ref selectedTid, NativeThreadId());
                        ready.Set();
                    }
                    go.Wait();
                    var started = ThreadCpu();
                    NativeBurn(1);
                    nativeCpu = ThreadCpu() - started;
                }) { Name = "filtered native" };
                managedControl = new Thread(() =>
                {
                    if (phase == "filtered-managed")
                    {
                        Volatile.Write(ref selectedTid, NativeThreadId());
                        ready.Set();
                    }
                    go.Wait();
                    var started = ThreadCpu();
                    ManagedAlpha(1);
                    managedCpu = ThreadCpu() - started;
                }) { Name = "filtered managed" };
                nativeControl.Start();
                managedControl.Start();
                ready.Wait();
            }
            Control(filtered ? $"START_TID {selectedTid} {profile}" : "START " + profile, "STARTED", profile);
            Console.WriteLine("PHASE_STARTED " + phase);
            if (filtered)
            {
                go.Set();
                nativeControl!.Join();
                managedControl!.Join();
            }
            else if (phase == "native")
            {
                var thread = new Thread(() => NativeBurn(1)) { Name = "calib native" };
                thread.Start();
                thread.Join();
            }
            else if (phase == "managed")
            {
                var thread = new Thread(() => ManagedAlpha(1)) { Name = "calib managed" };
                thread.Start();
                thread.Join();
            }
            else if (phase == "sleep")
                // Deliberate sleeping negative control: should produce almost no CPU samples.
                Thread.Sleep(1000);
            else
            {
                var native = new Thread(() => NativeBurn(1)) { Name = "calib mixednat" };
                var managed = new Thread(() => ManagedAlpha(2)) { Name = "calib mixedman" };
                native.Start();
                managed.Start();
                Thread.Sleep(300);
                await Task.Run(() => ManagedAllocate(.5));
                native.Join();
                managed.Join();
            }
            Control("STOP", "STOPPED", profile);
            wall.Stop();
            process.Refresh();
            Console.WriteLine("PHASE_FINISHED " + JsonSerializer.Serialize(new { phase, wallMilliseconds = wall.Elapsed.TotalMilliseconds,
                processCpuMilliseconds = (process.TotalProcessorTime - cpuStart).TotalMilliseconds,
                selectedThreadId = filtered ? selectedTid : (int?)null,
                selectedThreadCpuMilliseconds = filtered ? (phase == "filtered-native" ? nativeCpu : managedCpu) * 1000 : (double?)null }));
        }
        Control("QUIT", "QUITTED", "-");
        JoinControl();
        Console.WriteLine("CONTROL_JOINED");
        Console.WriteLine("COMPLETE_WAITING_FOR_MAP_COPY");
        Console.WriteLine("EXIT_READ_BEGIN");
        if (await Console.In.ReadLineAsync() != "exit")
            throw new InvalidOperationException("Missing explicit capture cleanup acknowledgement");
        Console.WriteLine("EXIT_ACKNOWLEDGED");
    }
}
