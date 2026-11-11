#nullable enable
using System.Diagnostics;
using System.Numerics;

// Sender-only application observations. Preallocated before the phase clock starts.
// These durations do not measure native send duration, transport ACKs, or off-CPU time.
internal sealed class ProgressCounters
{
    internal long CreditEpisodes;
    internal long CreditChannelReads;
    internal long CreditChannelReadsReady;
    internal long DataWritesReady;
    internal readonly TickHistogram CreditWait = new();
    private readonly TickHistogram _write = new();
    private readonly TickHistogram _invocation = new();
    private readonly TickHistogram _remaining = new();

    internal void RecordWrite(long before, long invoked, long completed)
    {
        _write.Record(completed - before);
        _invocation.Record(invoked - before);
        _remaining.Record(completed - invoked);
    }

    internal object Snapshot() => new
    {
        clockFrequency = Stopwatch.Frequency,
        creditEpisodes = CreditEpisodes,
        creditChannelReads = CreditChannelReads,
        creditChannelReadsReady = CreditChannelReadsReady,
        creditChannelReadsAwaited = CreditChannelReads - CreditChannelReadsReady,
        dataWritesReady = DataWritesReady,
        creditWait = CreditWait.Snapshot(),
        write = _write.Snapshot(), invocation = _invocation.Snapshot(), remaining = _remaining.Snapshot()
    };

    internal sealed class TickHistogram
    {
        // Bin 0 contains zero; bin i>0 contains [2^(i-1), 2^i-1] ticks.
        private readonly long[] _bins = new long[65];
        private long _count;
        private long _total;
        private long _minimum = long.MaxValue;
        private long _maximum;

        internal void Record(long ticks)
        {
            _bins[ticks == 0 ? 0 : 1 + BitOperations.Log2((ulong)ticks)]++;
            _count++;
            _total += ticks;
            _minimum = Math.Min(_minimum, ticks);
            _maximum = Math.Max(_maximum, ticks);
        }

        internal object Snapshot() => new
        {
            count = _count, totalTicks = _total, minimumTicks = _count == 0 ? (long?)null : _minimum,
            maximumTicks = _count == 0 ? (long?)null : _maximum, bins = _bins
        };
    }
}
