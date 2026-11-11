# QUIC versus SslStream benchmarks

A Linux, single-stream .NET transport experiment with common framing, validated payloads,
logical byte credit and peer delivery acknowledgments. Both arms use mutual TLS 1.3,
AES-128-GCM and the same local test identity. No actor framework dependencies.

This tag preserves the original batch-boundary ACK workload. Later revisions add
an explicit ACK credit boundary to compare data batch sizes with fixed ACK triggers.

Requirements: .NET SDK10.0.403/runtime10.0.14, Linux with libmsquic, Python3.11+,
OpenSSL and Git. Build, generate a local identity/native pins, commit source before
freezing, then run checks sequentially:

```sh
dotnet build -c Release
python3 prepare.py
python3 freeze_build.py baseline
python3 run_spike.py check evidence/check-baseline --build builds/baseline/TransportSpike.dll
```

See Microsoft platform prerequisites:
https://learn.microsoft.com/en-us/dotnet/fundamentals/networking/quic/quic-overview

The setup creates a fresh self-signed localhost identity under ignored `.local/`;
it never changes the trust store. Native library hashes are captured from a real
QUIC listener. Do not run setup/build/check/profile concurrently with timed runs.
Raw local diagnostics contain paths and must not be committed. No keys, certificates,
raw logs or machine paths are included in published results.
