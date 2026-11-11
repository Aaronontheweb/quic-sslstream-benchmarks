# QUIC versus SslStream benchmarks

A standalone .NET experiment comparing one persistent bidirectional `QuicStream`
with one full-duplex `NetworkStream`/`SslStream` connection. Both use mutual TLS1.3,
AES-128-GCM, the same framing, validated payloads and bounded logical byte credit.
There are no actor framework, HTTP, serialization or stream-processing dependencies.

The initial localhost measurements favor SslStream. A common larger-batch/ACK policy
improved QUIC throughput, but did not close the gap. These are measurements of a
transport **plus a small application protocol**, not a universal protocol ranking.

|348B payload, confirmation medians|QUIC frames/sec|SslStream frames/sec|
|---|---:|---:|
|Original16KiB cap and ACK policy|4,149,851|5,714,277|
|64KiB cap and shared ACK credit boundary|5,617,568|7,214,781|

The combined policy improves QUIC35.37%; matching SslStream improves26.26%.
QUIC remains22.14% below SslStream by ratio of medians. A separate4KiB payload
sanity case gives2.019 versus3.458 decimalGB/s of payload, a41.63% gap.
See [methodology and limitations](RESULTS.md), [sanitized measurements](results/measurements.json)
and [environment](results/environment.json). All88 performance attempts are included;
12 allocation-diagnostic attempts are kept separate from76 uninstrumented attempts.

A subsequent [controlled.NET10/11 comparison](RUNTIME_COMPARISON.md) adds96 separate
measurements, including application runtime async. It shows no general throughput
improvement on this host. The original measurements above remain unchanged.

## Run locally

Requirements: Linux with `/proc`, Git, Python3.11+, OpenSSL, .NET SDK10.0.403,
.NET runtime10.0.14, and a compatible `libmsquic` installation. The measured native
version was2.6.3. This harness is Linux-specific. See Microsoft's
[QUIC platform dependencies](https://learn.microsoft.com/en-us/dotnet/fundamentals/networking/quic/quic-overview#platform-dependencies)
for installation guidance. Setup does not install packages or modify your trust store.

```sh
git clone https://github.com/Aaronontheweb/quic-sslstream-benchmarks.git
cd quic-sslstream-benchmarks
dotnet build -c Release
python3 prepare.py
python3 freeze_build.py current
python3 run_spike.py check evidence/check --build builds/current/TransportSpike.dll --ack-boundary 1104
python3 run_spike.py run evidence/fixed-ack-16k --build builds/current/TransportSpike.dll --rounds 4 --payload 348 --batch 16384 --window 1280 --ack-boundary 1104
python3 run_spike.py run evidence/fixed-ack-64k --build builds/current/TransportSpike.dll --rounds 4 --payload 348 --batch 65536 --window 1280 --ack-boundary 1104
python3 summarize.py evidence/fixed-ack-16k evidence/fixed-ack-64k
```

Run build, preparation, correctness, profiling and timing sequentially. Keep the source
clean before freezing; every output directory must be new. Failed attempts are retained
and stop the controller. Each round reverses QUIC/TLS order from the previous round.
Defaults are2s warmup and6s measurement on the same connection. Fresh runs produce
new local evidence; they do not overwrite the published measurements.

`prepare.py` creates a fresh30-day self-signed localhost identity under ignored
`.local/` and captures hashes from a real QUIC listener. Each arm checks its own loaded
native libraries against these pins. Both endpoints check certificate identity, the
client checks hostname, and the controller checks runtime/security/counters/hashes.
To prepare a different environment, explicitly remove `.local/` and run preparation
again. Never do this during a block. `DOTNET_HOST_PATH` can select a custom dotnet
executable; `--expected-runtime '.NET 10.0.14'` is the default runtime gate. If studying
a different SDK/runtime, deliberately change `global.json` and that runtime gate and
record the new environment instead of presenting it as an exact reproduction.

The historical `baseline-workload-v1` tag contains the exact C# workload used for the
original baseline. `credit-ack-workload-v1` contains the revised C# workload used for
fixed-boundary experiments. Use a separate worktree and freeze each if reproducing
the exact original-versus-candidate comparison. The portable controller/setup scripts
replace the original machine-specific launcher, certificate location and native pins;
no original private Git history or raw local artifacts are published.

## Other experiments

- One frame/write: `--batch 0 --window 1280 --ack-boundary 1104`.
- Serial acknowledgment RTT: `--batch 0 --window 1` (samples every64th frame).
- Separate managed allocation diagnostics: add `--diagnostics`.
- Separate sender progress diagnostics: add `--progress-diagnostics`. The default
  `--progress-sample-every 64` samples data writes 0, 64, 128, etc. It records
  whole-batch insufficient-credit episodes and their elapsed durations, channel-read
  readiness during those episodes, data-write readiness, and sampled write invocation
  and completion durations. Counters/histograms are preallocated before timing;
  marker/control writes are excluded. This mode is independent of GC diagnostics.
  Keep both off for primary throughput and measure the progress mode's perturbation
  separately. A readiness snapshot does not prove no asynchronous work occurred.
  Completion durations are application observations, including continuation scheduling;
  they are not native send durations or transport ACK times. Histogram bin 0 is zero
  ticks; bin i > 0 covers [2^(i-1), 2^i-1] ticks at the reported clock frequency.
  Invocation plus remaining observed duration equals total sampled write duration;
  credit episodes are measured separately, not a decomposition of uninstrumented time.
- Cancellation allocation experiment: add `--cancellation lifetime`. It retains
  bounded phase/global transport abort; native I/O omits individual tokens.
- 4KiB sanity: `--payload 4096 --batch 65536 --window 111 --ack-boundary 105`.

A nonzero ACK boundary must be a multiple of the actual batch and fit in the window.
Default0 preserves original batch-boundary ACK requests. That original policy changes
reverse ACK frequency with batch size; use a common explicit boundary to isolate
batch-size changes. Larger buffers and prebuilt saturated batches do not measure
batching dwell time or offered-load tail latency.

New builds' `check` mode explicitly exercises the 348B A/B/C cells (64KiB/1,280
frames, 64KiB/5,120 frames, 128KiB/5,120 frames; common ACK boundary 1,104) with
8,193 frames, diagnostics on and off. These exceed credit and end with a partial
batch. It also checks bounded credit waits, progress parameter disagreement, and
progress-enabled aborts. The original corruption, identity and abort checks remain.
The old frozen build remains usable as an off-path control; its historical schema
is accepted only when its frozen descriptor lacks the progress implementation.

## Inspect the publication without rerunning benchmarks

```sh
python3 analyze_results.py > /tmp/quic-sslstream-summary.json
```

This verifies all published counts/order, workload source hashes against both tags,
security/runtime fields, derived arithmetic and total coverage, then recomputes medians
and per-pair throughput deltas. The export uses an explicit field allowlist. It omits
local paths, usernames, hostnames, certificate fingerprints/bytes, keys, private links,
full `dotnet --info` output and raw logs. Original log hashes retain provenance, but
readers cannot re-audit unavailable raw logs from those hashes alone.

Local raw logs/manifests include paths and are ignored along with keys, certificates,
build outputs and native pins. Review any new evidence before sharing it. Source and
published results are available under the [MIT license](LICENSE).
