# .NET10 versus11: registered comparison

This follow-up compares the current workload under .NET10.0.14 and final.NET11.0.0,
with application runtime async as a separate factor. It does not pool data with the
original88 measurements. All builds use SDK11.0.100 and C#15.0 to hold compiler
and language versions fixed; target framework/runtime libraries change together.

|Variant|Target/runtime|Application async mode|
|---|---|---|
|net10-classic|net10.0 /10.0.14|Classic compiler state machines|
|net11-classic|net11.0 /11.0.0|Classic compiler state machines|
|net11-runtime-async|net11.0 /11.0.0|Runtime async opt-in|

Classic refers to application lowering. Framework libraries use their shipped
implementation. The build helper checks the emitted metadata in RunAsync, SendData,
ReadAcks, ReadData, WriteAcks, WriteNumber, ExpectNumber and local Guard. Classic
requires compiler state-machine attributes and no runtime-async flag; opt-in requires
the opposite. All builds freeze source/binary hashes and lowering evidence.
ServerGC, TieredCompilation and TieredPGO are explicitly enabled; roll-forward is disabled.

MsQuic2.6.3 and OpenSSL library hashes, certificate, TLS1.3/AES128-GCM, ALPN,
operation cancellation, source framing/validation and logical byte credit stay fixed.
Only CLR/runtime-owned library versions intentionally change. TLS processes need not
load MsQuic; QUIC processes must. Native pins are captured from real listeners with
the same existing identity, then verified at both endpoints. There is no scheduler tuning.

The primary matrix has72 attempts: two workloads, three variants, both transports,
six rounds. All six variant-order permutations occur once, so each variant occupies
each position twice. Q/T transport order reverses every round. Same-round runtime
deltas are reported alongside medians and individual results.

- 348B payload:356B frame,184frames/write65,504B,1280framecredit455,680B,
  ACKthreshold10 and shared boundary1104.
- 4096B payload:4104B frame,15frames/write61,560B,111framecredit455,544B,
  ACKthreshold10 and shared boundary105.

Two separate follow-ups each have12 attempts (three variants,both transports,two rounds):
managed allocation diagnostics at348B, and serial348B/window1 latency sanity.
Thus96 timed attempts are planned:84 uninstrumented including serial,12 diagnostic.
Every attempt has2s warmup+6s measurement on one persistent connection. Diagnostics
are excluded from primary throughput claims; serial RTT is closed-loop, not offered-load
latency. All payload bytes, counts, peer delivery ACKs and phase fences must validate.
Failed attempts are retained and stop execution. No edits/build/tests/profiling overlap
timed workloads. A short packaging smoke matrix and54 native correctness cases
(18per variant) are separate from these96 measurements.

## Reproduce

Install the pinned SDK and both runtimes. The build helper deliberately selects
SDK11.0.100 through an ignored local selector while preserving the repository's
default.NET10 setup. `DOTNET_HOST_PATH` may select an isolated dotnet installation.
Prepare the default local identity first using the main README instructions, then:

```sh
python3 build_comparison.py
python3 prepare.py --reuse-identity --build builds/net10-classic/TransportSpike.dll --native-pins .local/native-pins-net10.json
python3 prepare.py --reuse-identity --build builds/net11-classic/TransportSpike.dll --native-pins .local/native-pins-net11.json
python3 run_spike.py check evidence/check10 --build builds/net10-classic/TransportSpike.dll --expected-runtime '.NET 10.0.14' --native-pins .local/native-pins-net10.json --ack-boundary 1104
python3 run_spike.py check evidence/check11 --build builds/net11-classic/TransportSpike.dll --expected-runtime '.NET 11.0.0' --native-pins .local/native-pins-net11.json --ack-boundary 1104
python3 run_spike.py check evidence/check11async --build builds/net11-runtime-async/TransportSpike.dll --expected-runtime '.NET 11.0.0' --native-pins .local/native-pins-net11.json --ack-boundary 1104
python3 run_comparison.py primary evidence/runtime-primary
python3 run_comparison.py diagnostic evidence/runtime-diagnostic
python3 run_comparison.py serial evidence/runtime-serial
python3 analyze_comparison.py evidence/runtime-primary evidence/runtime-diagnostic evidence/runtime-serial
```

Keep all source committed before building/running. Frozen build names and evidence
directories must be new. Reuse the identity rather than generating a different one
for each runtime. Never replace pins to hide an unexpected dependency change.
Public exports omit keys, identities, private paths and raw logs.

Results will be appended after the registered matrix completes and is independently audited.
