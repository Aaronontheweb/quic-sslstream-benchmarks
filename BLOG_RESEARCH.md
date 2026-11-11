# Petabridge article research packet

Working title: **Why one .NET QUIC stream trails SslStream on loopback**.
Status: research packet, not a published article. Scope is this application protocol,
Linux x64, .NET 10.0.14, MsQuic 2.6.3, one connection and one stream. The historical
.NET 11 comparison is separate context; this causal study did not rerun .NET 11.

## Working outline

1. Ask the narrow question: why does the existing encrypted, delivery-confirmed QUIC
   workload lose to SslStream? Define payload/framed bytes and actual batching/ACK credit.
2. Show original and runtime-comparison observations without mixing environments or
   source versions. Explain why near-equal aggregate CPU/frame does not identify a
   critical worker's capacity.
3. Present competing explanations before their tests: application feedback, write
   completion overhead, copies, receive staging, transport windows, packet processing.
4. Explain A/B/B/A credit and B/C/C/B batching results. Both transports improve; QUIC
   does not catch up. Include the disabled-code regression and diagnostic perturbation.
5. Follow the failed attribution lead: whole-process yield/spin samples are large, but
   worker identity was unknown. Map the actual connection, calibrate thread filtering,
   then show the worker-only profile with zero named yield/spin leaves.
6. Connect versioned source facts to observations: native copies, locked receive
   staging, one-worker execution, async completions, GSO/GRO and growing native windows.
7. State the bounded explanation, unmeasured copy penalties and kernel/off-CPU limits.
   Supply reproduction commands and the smallest consequential custom-runtime test.

## Claim ledger

|Potential claim|Status|Evidence|Limits|
|---|---|---|---|
|Larger application credit improves this QUIC workload|Measured|E04 four matched ordinal changes: median +8.00%; all positive|Also helps TLS +17.07%; credit changes buffering budget|
|Larger writes help at fixed larger credit|Measured|E05 QUIC +4.47%, TLS +11.97%; four changes each|Not a direct A→C combined confirmation; no batching dwell/tail study|
|Adding disabled diagnostics has a cost|Measured|E02 QUIC −2.02% median paired|TLS drifting result is inconclusive; cannot call disabled path free|
|Observed application credit waiting contributes|Supported inference|E03 A versus E04 B progress observations plus E04 primary control|Two B diagnostics; percentages are not uninstrumented capacity decomposition|
|One QUIC connection worker is near one CPU|Measured + source-proven mechanism|E07 identity map, E08 /proc CPU + filtered samples; versioned MsQuic execution source|Not a whole-host saturation claim; one capture/endpoint|
|Global yield/spin explains the worker limit|Weakened|E06 whole profiles versus E08 zero named yield/spin worker leaves|Leaf sampling cannot prove zero inlined/unsampled work|
|Copies are present and visible|Source-proven + sampled|.NET buffers/receive source, E08 38/48 copy-name leaves|Not a measured percentage of the gap, bytes copied or inclusive copy cost|
|A fixed native 64 KiB receive window causes the gap|Weakened|E07 virtual receive growth to 8 MiB|Wrapper staging still 64 KiB; initial flow states partly unknown|
|Missing Linux GSO/GRO explains low throughput|Weakened|E07 native segment metadata and exact v2.6.3 datapath source|Loopback, not NIC hardware evidence|
|Native worker crypto/protocol/I/O limits remaining progress|Supported inference|E08 high worker occupancy and explicit module/leaf samples|Kernel stacks/off-CPU mechanisms and relative causal penalties unresolved|
|A copy-removing rewrite or throughput profile will help|Unresolved|Concrete future custom-runtime/profile or matched wrapper control|No speed claim or public runtime option invented|

The per-experiment planning records preceded attempts; they preserve predictions,
competing explanations and falsification conditions. They are private research notes.
The public [causal report](CAUSAL_INVESTIGATION.md) is the readable synthesis; the
exported ledger preserves every attempt, including diagnostic contexts. Raw private
artifacts are not distributed, and public hashes do not substitute for them.

## Figures and short excerpts

Chart-ready data:

- `results/causal-investigation/attempts.csv`: all 80 points; filter
  `measurementClass=uninstrumented` and E04/E05 for primary charts. Plot each point,
  median and full range, with four points per arm/transport. Never pick fastest runs.
- `summary.json`: paired changes and independent-median ratios, separately named.
  Good panels are throughput versus application credit and versus actual batch bytes;
  keep E04 and E05 controls in separate panels.
- `progress.csv`: credit wait and write observations with sample counts/interval.
  Label diagnostic mode and E03 perturbation; do not present a wait chart as a
  decomposition of uninstrumented runtime.
- `measurements.json` profiles: module shares can form mutually exclusive stacks.
  Copy-name/allocator-name categories overlap modules and belong in a separate table.
  Include unresolved/ambiguous denominator, ~400 samples and kernel visibility limits.

A useful code excerpt is the conceptual application gate below. Use the actual
versioned `Protocol.cs` when quoting implementation; this pseudocode just explains it:

```csharp
while (sent - delivered + nextBatchFrames > windowFrames)
    delivered = await deliveryProgress.ReadAsync(cancellationToken);
await stream.WriteAsync(batch, cancellationToken);
```

Pair it with the [credit/worker diagram](CAUSAL_INVESTIGATION.md#how-application-credit-blocks-the-sender).
Emphasize that transport ACK, public WriteAsync completion and application delivery ACK
are three distinct events. Native window, wrapper staging and application credit are
three different limits.

Primary source links and exact deployed versions are in the
[source ledger](CAUSAL_INVESTIGATION.md#source-facts-versus-attribution). A useful
methodological lead is MsQuic's
[performance troubleshooting guide](https://github.com/microsoft/msquic/blob/main/docs/TroubleshootingGuide.md):
inspect connection-worker CPU rather than aggregate host CPU. Its example numbers are
not measurements of this workload. Historical .NET send-buffer prototype regressions
are useful negative design context, not deployed-version attribution.

## Publication checklist specific to these claims

Keep environment, counts, absolute rates and percentage denominators visible. State
356-byte frames, decimal GB/s, same encryption and delivery confirmation. Retain null,
negative and failed-collector findings. Label all inferred mechanisms. Do not imply
SslStream has no copies/native work, secnetperf isolates wrapper penalties, multiple
streams guarantee more connection-worker cores, or this loopback study ranks protocols
on real networks. Do not publish raw private identity, maps, symbols or host logs.

No blog has been published. Next editorial step is to turn this packet into an article
and review the claim ledger against the linked evidence.
