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

## Results

All96 registered attempts completed and passed the raw-witness audit:72primary,
12allocation diagnostic and12serial. No performance attempt was invalid or excluded.
The54native correctness cases and6short packaging smokes are separate from this ledger.
An independent replay reproduced every raw and sanitized summary exactly.

The new comparison uses SDK11-built applications for all variants. It is separate from
the original SDK10-built88-row dataset. Target framework and shipped runtime/framework
libraries change together; application classic mode does not disable runtime async
inside the .NET11 framework. These are observations on one Linux localhost host.

|Application variant|348B QUIC frames/sec|348B TLS frames/sec|4KiB QUIC payload GB/sec|4KiB TLS payload GB/sec|
|---|---:|---:|---:|---:|
|.NET10 classic|5,376,345|6,500,961|1.934|3.096|
|.NET11 classic|5,298,601|5,677,439|1.947|3.045|
|.NET11 runtime async|5,143,591|5,679,440|1.904|3.001|

Each primary cell has six repetitions. GB/sec uses decimal payload bytes and excludes
framing. The complete values, CPU measurements and paired changes are in
[measurements](results/runtime-comparison/measurements.json) and
[recomputed summaries](results/runtime-comparison/summary.json).

The following are medians of same-round percentage changes, which differ from ratios
of the throughput medians in the table above:

|Transition|348B QUIC|348B TLS|4KiB QUIC|4KiB TLS|
|---|---:|---:|---:|---:|
|.NET10 classic → .NET11 classic|-2.03%|-10.86%|+1.06%|-1.64%|
|.NET11 classic → runtime async|-1.39%|+0.18%|-1.73%|-1.83%|

There is no general .NET11 or application-runtime-async throughput improvement here.
The348B TLS rate is lower in all six same-round .NET11 comparisons; larger-payload
QUIC is approximately flat. Several small effects have mixed signs; six rounds do not
establish a universal regression or guarantee. Keep the individual results and ranges.
The slower first .NET10 QUIC348B result (4,158,471frames/sec) remains included. No cold-run
exclusion or selection of only favorable repetitions was performed.

Higher observed process CPU/frame on.NET11 also deserves investigation. In the primary
cells, ratios of CPU/frame medians for.NET11 classic versus.NET10 classic are about
+30%Q/+57%TLS at348B and+22%Q/+35%TLS at4KiB. These process counters include managed and
native work and are not native attribution. They do not identify a cause. Phase CPU
boundaries differ slightly between endpoints as described in RESULTS.md.

The separate348B diagnostic experiment gives combined managed allocations:

|Application variant|QUIC B/frame|TLS B/frame|
|---|---:|---:|
|.NET10 classic|2.978|1.512|
|.NET11 classic|3.566|1.500|
|.NET11 runtime async|2.931|1.555|

Two repetitions per cell. Application runtime async lowers observed QUIC allocation
about18% versus.NET11 classic without a throughput gain. Actual ACK coalescing can
change with execution timing. These are managed bytes, not native allocations, RSS or
retained capacity. Instrumented throughput is excluded from the primary comparison.

Serial348B/window1 sanity gives the following medians of per-attempt sampled p50 ACK RTT:

|Application variant|QUIC microseconds|TLS microseconds|
|---|---:|---:|
|.NET10 classic|22.583|12.614|
|.NET11 classic|25.774|17.238|
|.NET11 runtime async|26.330|16.872|

Two repetitions per cell, every64th frame sampled, no omitted samples. This is closed-loop
application acknowledgment latency and does not measure offered-load tail latency.
.NET11 does not improve this serial sample. Per-attempt p95/p99 remain in the export.

Native MsQuic/OpenSSL hashes and certificate were fixed. We have not isolated the.NET11
CPU differences to JIT, framework async, interop, GC, native callbacks or ACK feedback.
This workload is different from a16KiB TLS-record round-trip microbenchmark and need
not reproduce its published speedup. No scheduler/native setting was tuned and no
runtime-wide or protocol-wide conclusion follows from one host and this small protocol.

## Inspect the published follow-up

```sh
python3 analyze_comparison.py --published results/runtime-comparison/measurements.json
```

The published analyzer needs only this repository and its recorded Git history. The
allowlisted export exactly reproduces the raw audit summaries while excluding local
paths, identity/certificate fingerprints, keys, full dotnet-info output and raw logs.
Original source/native/binary/log hashes retain provenance, but hashes alone cannot
re-audit the unavailable original logs. The earlier88 measurements remain unchanged.
