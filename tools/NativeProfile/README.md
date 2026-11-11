# Native-aware diagnostic capture (Linux x64)

This optional tool uses gperftools' BSD-licensed `libprofiler` and a small MIT-licensed
pthread registrar in this repository. Install/build gperftools separately; no profiler,
native binary, debug symbols or trace is distributed here. It does not change MsQuic.
The registrar wraps pthread creation and registers each thread once for CPU timers;
the library already registers the initial thread. FIFO commands bound sampling after
warmup. Control acknowledgments record monotonic and process user/system CPU.

Build the registrar against your installed library, for example:

```sh
cc -shared -fPIC -O2 -o .local/thread_registration.so tools/NativeProfile/thread_registration.c -lprofiler -ldl -lpthread
```

Ensure its dynamic dependency can resolve `libprofiler.so.0` (use an appropriate
rpath at build time for a private installation). Verify a known native/managed CPU
burn, sleep and mixed-thread calibration before trusting a new tool/runtime combination.
One timer per thread, SIGPROF ownership, clean exit and sample/CPU agreement matter.

Run each transport separately, outside all primary timing, builds and analysis:

```sh
python3 profile_spike.py evidence/profile-quic --transport quic --build builds/current/TransportSpike.dll --dotnet-launcher /path/to/dotnet-launcher --registrar /path/to/thread_registration.so --profiler /path/to/libprofiler.so.0
python3 profile_spike.py evidence/profile-tls --transport tls --build builds/current/TransportSpike.dll --dotnet-launcher /path/to/dotnet-launcher --registrar /path/to/thread_registration.so --profiler /path/to/libprofiler.so.0
```

Both use the normal controller and all its security/native/correctness gates. The
selected transport's two endpoints are profiled; the other arm is context only.
Cell B is fixed: payload348, batch cap65536, window5120, ACK boundary1104, two-second
warmup and six-second measurement. Sampling is100Hz per thread over an approximately
four-second interior window, starting after the warmup phase witness. Progress and GC
diagnostics are off. Capture is diagnostic, and its rates are not primary throughput.

After targets exit, resolve each endpoint's profile using its same-run JIT map:

```sh
python3 tools/NativeProfile/resolve_profile.py evidence/profile-quic/client/cpu.prof evidence/profile-quic/client/managed-perf.map .local/quic-client-symbols.json
```

Optional exact debug files go under ignored `tools/NativeProfile/native-symbols/` as
`<deployed-module-name>.dbg`. The resolver verifies build IDs, uses sized ELF function
intervals and exact same-run JIT intervals, and retains unresolved/ambiguous samples.
Copy the deployed CoreCLR's matching symbols there if available. No nearest-export
fallback is used. Kernel stacks, off-CPU causes, complete managed stacks, inclusive
costs and allocation counts are not established by these leaf CPU samples. CPU timers
charge user+system time. Compare samples × period with acknowledged CPU, not wall time.

`/proc` thread CPU and schedstat snapshots can identify busy threads. A hot anonymous
thread is not proven to be a particular connection worker without separate mapping
evidence. Runnable scheduler wait is not all off-CPU waiting. Affinity is recorded
per observed thread; threads created/exited between snapshots remain explicit limits.

Raw captures contain process IDs, host paths and JIT/runtime internals. They remain
ignored local evidence and require sanitization before sharing. A hash does not make
an unavailable raw artifact public. Keep profiler source/binary/symbol/log hashes with
the result and preserve unsuccessful captures.

The optional `START_TID <tid> <profile>` command uses gperftools2.15's public
`ProfilerStartWithOptions` thread filter. It verifies that the selected TID belongs
to this process and uses only a lock-free atomic load and gettid syscall in the
signal handler. Build this registrar separately; preserve old captures' binaries.
Filtered sample CPU must match the selected thread's CPU, not whole-process CPU.

A portable calibration host and driver include native, managed, sleeping and mixed
controls plus native-only/managed-only filters with both burners running concurrently:

```sh
dotnet build tools/NativeProfile/Calibration/Calibration.csproj -c Release
python3 tools/NativeProfile/calibrate.py evidence/calibration --dotnet-launcher /path/to/dotnet-launcher --bridge /path/to/thread_registration.so --build tools/NativeProfile/Calibration/bin/Release/net10.0/Calibration.dll
```

After accounting checks, resolve both filtered profiles with the same-run JIT map and
verify the expected native versus managed leaf identities. Calibration uses its project
default GC; the transport benchmark still uses ServerGC. Sleep is an intentional
negative sampling control. No native binary or debug symbols should be committed.

## Native flow and identified-worker captures

Optional LTTng2 userspace tooling and the deployed matching
`libmsquic.lttng.so.<version>` allow connection-worker identity, flow and UDP datapath
observations. Keep that extra tracing library separately pinned; do not silently
replace the original timing pins. Use compatible Babeltrace2 Python bindings/plugins
for decoding. These tools use a private session daemon and retain failed capture state.

```sh
python3 tools/NativeProfile/trace_spike.py evidence/native-flow --runtime-root /path/to/dotnet-root --native-directory /path/to/native-libraries --lttng-root / --trace-library /path/to/libmsquic.lttng.so.2.6.3 --build builds/current/TransportSpike.dll
python3 tools/NativeProfile/analyze_native.py evidence/native-flow .local/native-flow-decoded.json
python3 tools/NativeProfile/profile_worker.py evidence/native-worker --runtime-root /path/to/dotnet-root --native-directory /path/to/native-libraries --lttng-root / --trace-library /path/to/libmsquic.lttng.so.2.6.3 --build builds/current/TransportSpike.dll --registrar /path/to/thread_registration.so --profiler /path/to/libprofiler.so.0
python3 tools/NativeProfile/analyze_worker_profile.py evidence/native-worker .local/native-worker-decoded.json
```

Set `--lttng-root` to an extracted package root if not installed system-wide. Binding
and plugin paths (`PYTHONPATH`, `BABELTRACE_PLUGIN_PATH`, `LD_LIBRARY_PATH`) must match
that installation. The decoders check capture artifact hashes and the normal controller
run before interpreting events; they retain unknown initial states and discarded-event
guards. They require the original matching build/native files for that local audit.
Resolve each filtered `cpu.prof` with `resolve_profile.py` and its same-run map afterward.

The flow tool brackets a quiet two-second worker CPU interval with mapping events,
then captures a short hot flow window. The filtered tool selects a candidate native
thread and verifies it is the actual connection worker before/after sampling; it disables
hot flow/mapping channels during profiling. Selected-thread sample CPU must match that
thread's accounting. Failure of identity/timer/source/native checks invalidates capture.

The published causal study used private, fixed-path recorder versions. These portable
recorders substitute CLI paths and add targeted child cleanup; they were source-reviewed
and CLI-checked, not rerun as new captures. Public decoders replayed the original raw
captures. This distinction is part of the reproduction limit, not a second experiment.
