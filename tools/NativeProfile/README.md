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
