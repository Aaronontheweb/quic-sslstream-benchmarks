using System.Buffers.Binary;
using System.Diagnostics;
using System.Net.Quic;
using System.Threading.Channels;

internal static class Protocol
{
    private const ulong Final = 1UL << 63;
    private const ulong Ready = 0x315944414552;
    private const ulong Confirm = 0x314d5249464e4f43;
    private const ulong Done = 0x31454e4f44;

    private sealed class State
    {
        internal readonly Channel<byte> Wake = Channel.CreateBounded<byte>(new BoundedChannelOptions(1)
        {
            SingleReader = true, SingleWriter = true, FullMode = BoundedChannelFullMode.DropWrite,
            AllowSynchronousContinuations = false
        });
        internal readonly byte[] Payload;
        internal readonly byte[] SendBuffer;
        internal readonly byte[] Marker;
        internal readonly byte[] ReadBuffer;
        internal readonly byte[] AckReadBuffer = new byte[16];
        internal readonly byte[] AckWriteBuffer = new byte[16];
        internal readonly long[] Latencies = new long[65536];
        internal State(Options options)
        {
            Payload = Enumerable.Range(0, options.Payload).Select(i => (byte)(i * 31 + 7)).ToArray();
            SendBuffer = new byte[options.BatchBytes];
            for (var i = 0; i < options.BatchFrames; i++)
                Payload.CopyTo(SendBuffer, i * options.FrameBytes + 8);
            Marker = new byte[options.FrameBytes];
            BinaryPrimitives.WriteUInt64LittleEndian(Marker, ulong.MaxValue);
            ReadBuffer = new byte[Math.Max(65536, options.FrameBytes * 2)];
        }
        internal long Submitted;
        internal long Acknowledged;
        internal long Latest;
        internal int Finished;
        internal long DataWrites;
        internal long DataReads;
        internal long AckWrites;
        internal long AckReads;
        internal long MaximumInFlight;
        internal long SampleStart;
        internal int Samples;
        internal int OmittedSamples;
        internal long DataBytes;
        internal long Received;
        internal int MarkerSubmitted;
        internal void Signal() => Wake.Writer.TryWrite(0);
    }

    private sealed class Measurement(bool diagnostics)
    {
        private readonly Process _process = Process.GetCurrentProcess();
        private readonly TimeSpan _cpu = CurrentCpu();
        private static TimeSpan CurrentCpu()
        {
            using var process = Process.GetCurrentProcess();
            return process.TotalProcessorTime;
        }
        private readonly long _allocated = diagnostics ? GC.GetTotalAllocatedBytes(true) : 0;
        private readonly long _start = Stopwatch.GetTimestamp();

        internal object Finish(State s, Options o, int phase)
        {
            var elapsed = Stopwatch.GetElapsedTime(_start).TotalSeconds;
            _process.Refresh();
            var cpu = (_process.TotalProcessorTime - _cpu).TotalMilliseconds;
            var allocated = diagnostics ? GC.GetTotalAllocatedBytes(true) - _allocated : (long?)null;
            _process.Dispose();
            var sorted = s.Latencies.AsSpan(0, s.Samples).ToArray();
            Array.Sort(sorted);
            double? Percentile(double q) => sorted.Length == 0 ? null : sorted[(int)Math.Ceiling(q * sorted.Length) - 1] * 1e6 / Stopwatch.Frequency;
            return new
            {
                role = o.Role, transport = o.Transport, phase, frames = o.Role == "client" ? s.Submitted : s.Received,
                payloadBytes = o.Payload, frameBytes = o.FrameBytes, dataBytes = s.DataBytes,
                batchFrames = o.BatchFrames, batchBytes = o.BatchBytes, windowFrames = o.Window,
                creditBytes = (long)o.Window * o.FrameBytes, requestedAckEvery = o.RequestedAckEvery,
                effectiveAckEvery = o.AckEvery, ackAtBatchBoundary = true,
                elapsedSeconds = elapsed, cpuMilliseconds = cpu, allocatedBytes = allocated,
                dataWrites = s.DataWrites, dataReads = s.DataReads, ackWrites = s.AckWrites, ackReads = s.AckReads,
                maximumInFlight = s.MaximumInFlight, cancellation = o.Cancellation, diagnostics,
                latencySamples = s.Samples, omittedLatencySamples = s.OmittedSamples,
                p50Us = Percentile(.50), p95Us = Percentile(.95), p99Us = Percentile(.99),
                protocol = "fixed-frames-cumulative-ack-v1", complete = true
            };
        }
    }

    private static byte[] Header(Options o, int phase)
    {
        var header = new byte[64];
        BinaryPrimitives.WriteUInt64LittleEndian(header, 0x31534c5351495551);
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(8), phase);
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(12), o.Payload);
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(16), o.BatchBytes);
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(20), o.Window);
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(24), o.AckEvery);
        BinaryPrimitives.WriteInt64LittleEndian(header.AsSpan(32), o.Frames);
        BinaryPrimitives.WriteInt64LittleEndian(header.AsSpan(40), BitConverter.DoubleToInt64Bits(phase == 0 ? o.Warmup : o.Seconds));
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(48), o.Diagnostics ? 1 : 0);
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(52), o.Cancellation == "operation" ? 0 : 1);
        return header;
    }

    private static async Task WriteNumber(Stream stream, ulong value, CancellationToken token)
    {
        var buffer = new byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(buffer, value);
        await stream.WriteAsync(buffer, token);
    }

    private static async Task ExpectNumber(Stream stream, ulong value, CancellationToken token)
    {
        var buffer = new byte[8];
        await stream.ReadExactlyAsync(buffer, token);
        if (BinaryPrimitives.ReadUInt64LittleEndian(buffer) != value)
            throw new InvalidDataException("Phase fence differs.");
    }

    internal static async Task RunAsync(Stream stream, Options o, int phase, CancellationToken parent)
    {
        var state = new State(o);
        var header = Header(o, phase);
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(parent);
        using var abort = stop.Token.Register(() =>
        {
            if (stream is QuicStream quic)
                quic.Abort(QuicAbortDirection.Both, 1);
            else
                stream.Dispose();
        });
        using var injectedAbort = o.Role == "client" && o.AbortAfterMilliseconds > 0
            ? new Timer(_ =>
            {
                Program.Emit("ABORT_REQUESTED", new { phase, role = o.Role });
                stop.Cancel();
            }, null, Timeout.Infinite, Timeout.Infinite)
            : null;
        var io = o.Cancellation == "operation" ? stop.Token : CancellationToken.None;
        async Task Guard(Func<Task> body)
        {
            try
            {
                await body();
            }
            catch
            {
                stop.Cancel();
                throw;
            }
        }
        if (o.Role == "client")
        {
            await stream.WriteAsync(header, stop.Token);
            await ExpectNumber(stream, Ready + (ulong)phase, stop.Token);
            injectedAbort?.Change(o.AbortAfterMilliseconds, Timeout.Infinite);
            var measurement = new Measurement(o.Diagnostics);
            await Task.WhenAll(Guard(() => SendData(stream, state, o, phase, io, stop.Token)),
                Guard(() => ReadAcks(stream, state, o, io)));
            if (state.Acknowledged != state.Submitted || Volatile.Read(ref state.MarkerSubmitted) == 0)
                throw new InvalidDataException("Final delivery acknowledgment missing.");
            var result = measurement.Finish(state, o, phase);
            await WriteNumber(stream, Confirm + (ulong)phase, stop.Token);
            await ExpectNumber(stream, Done + (ulong)phase, stop.Token);
            Program.Emit("PHASE", result);
        }
        else
        {
            var received = new byte[header.Length];
            await stream.ReadExactlyAsync(received, stop.Token);
            if (!received.AsSpan().SequenceEqual(header))
                throw new InvalidDataException("Client/server workload differs.");
            await WriteNumber(stream, Ready + (ulong)phase, stop.Token);
            var measurement = new Measurement(o.Diagnostics);
            await Task.WhenAll(Guard(() => ReadData(stream, state, o, io)),
                Guard(() => WriteAcks(stream, state, io, stop.Token)));
            var result = measurement.Finish(state, o, phase);
            await ExpectNumber(stream, Confirm + (ulong)phase, stop.Token);
            Program.Emit("PHASE", result);
            await WriteNumber(stream, Done + (ulong)phase, stop.Token);
        }
    }

    private static ulong Digest(long count) => unchecked((ulong)count * 0x9E3779B185EBCA87UL ^ (ulong)count * (ulong)(count - 1) / 2);

    private static async Task SendData(Stream stream, State state, Options o, int phase, CancellationToken io, CancellationToken stop)
    {
        var buffer = state.SendBuffer;
        var marker = state.Marker;
        var started = Stopwatch.GetTimestamp();
        var seconds = phase == 0 ? o.Warmup : o.Seconds;
        var sent = 0L;
        while (o.Frames > 0 ? sent < o.Frames : sent == 0 || Stopwatch.GetElapsedTime(started).TotalSeconds < seconds)
        {
            var batch = o.Frames > 0 ? (int)Math.Min(o.BatchFrames, o.Frames - sent) : o.BatchFrames;
            while (o.Window - (sent - Volatile.Read(ref state.Acknowledged)) < batch)
                await state.Wake.Reader.ReadAsync(stop);
            for (var i = 0; i < batch; i++)
                BinaryPrimitives.WriteUInt64LittleEndian(buffer.AsSpan(i * o.FrameBytes), (ulong)(sent + i));
            if (sent == 0 && o.Corrupt != "none")
                buffer[o.Corrupt == "sequence" ? 0 : 8] ^= 0x40;
            if (o.Window == 1 && (sent & 63) == 0)
                Volatile.Write(ref state.SampleStart, Stopwatch.GetTimestamp());
            sent += batch;
            Volatile.Write(ref state.Submitted, sent);
            state.MaximumInFlight = Math.Max(state.MaximumInFlight, sent - Volatile.Read(ref state.Acknowledged));
            var length = batch * o.FrameBytes;
            if (o.Fragment == 0)
            {
                await stream.WriteAsync(buffer.AsMemory(0, length), io);
                state.DataWrites++;
            }
            else
            {
                for (var offset = 0; offset < length; offset += o.Fragment)
                {
                    await stream.WriteAsync(buffer.AsMemory(offset, Math.Min(o.Fragment, length - offset)), io);
                    state.DataWrites++;
                }
            }
            state.DataBytes += length;
        }
        Volatile.Write(ref state.MarkerSubmitted, 1);
        await stream.WriteAsync(marker, io);
    }

    private static async Task ReadAcks(Stream stream, State state, Options o, CancellationToken io)
    {
        var ack = state.AckReadBuffer;
        var previous = 0L;
        while (true)
        {
            await stream.ReadExactlyAsync(ack, io);
            state.AckReads++;
            var word = BinaryPrimitives.ReadUInt64LittleEndian(ack);
            var final = (word & Final) != 0;
            var count = checked((long)(word & ~Final));
            if (count < previous || (!final && count == previous) || count > Volatile.Read(ref state.Submitted)
                || BinaryPrimitives.ReadUInt64LittleEndian(ack.AsSpan(8)) != Digest(count))
                throw new InvalidDataException("Invalid acknowledgment prefix or digest.");
            if (o.Window == 1 && count > previous && ((count - 1) & 63) == 0)
            {
                var elapsed = Stopwatch.GetTimestamp() - Volatile.Read(ref state.SampleStart);
                if (state.Samples < state.Latencies.Length)
                    state.Latencies[state.Samples++] = elapsed;
                else
                    state.OmittedSamples++;
            }
            previous = count;
            Volatile.Write(ref state.Acknowledged, count);
            state.Signal();
            if (final)
            {
                if (Volatile.Read(ref state.MarkerSubmitted) == 0 || count != Volatile.Read(ref state.Submitted))
                    throw new InvalidDataException("Final acknowledgment does not cover submitted data.");
                return;
            }
        }
    }

    private static async Task ReadData(Stream stream, State state, Options o, CancellationToken io)
    {
        var buffer = state.ReadBuffer;
        var buffered = 0;
        while (true)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(buffered), io);
            state.DataReads++;
            if (read == 0)
                throw new EndOfStreamException("Missing final marker.");
            buffered += read;
            var offset = 0;
            while (buffered - offset >= o.FrameBytes)
            {
                var frame = buffer.AsSpan(offset, o.FrameBytes);
                var sequence = BinaryPrimitives.ReadUInt64LittleEndian(frame);
                if (sequence == ulong.MaxValue)
                {
                    if (buffered - offset != o.FrameBytes || frame[8..].ContainsAnyExcept((byte)0))
                        throw new InvalidDataException("Malformed phase terminator.");
                    Volatile.Write(ref state.Latest, state.Received);
                    Volatile.Write(ref state.Finished, 1);
                    state.Signal();
                    return;
                }
                if (sequence != (ulong)state.Received || !frame[8..].SequenceEqual(state.Payload))
                    throw new InvalidDataException("Frame order or payload corruption.");
                state.Received++;
                state.DataBytes += o.FrameBytes;
                offset += o.FrameBytes;
                if (state.Received % o.AckEvery == 0 || state.Received % o.BatchFrames == 0)
                {
                    Volatile.Write(ref state.Latest, state.Received);
                    state.Signal();
                }
            }
            buffer.AsSpan(offset, buffered - offset).CopyTo(buffer);
            buffered -= offset;
        }
    }

    private static async Task WriteAcks(Stream stream, State state, CancellationToken io, CancellationToken stop)
    {
        var ack = state.AckWriteBuffer;
        var previous = -1L;
        while (true)
        {
            await state.Wake.Reader.ReadAsync(stop);
            var final = Volatile.Read(ref state.Finished) != 0;
            var count = Volatile.Read(ref state.Latest);
            if (count == previous && !final)
                continue;
            BinaryPrimitives.WriteUInt64LittleEndian(ack, (ulong)count | (final ? Final : 0));
            BinaryPrimitives.WriteUInt64LittleEndian(ack.AsSpan(8), Digest(count));
            await stream.WriteAsync(ack, io);
            state.AckWrites++;
            previous = count;
            if (final)
                return;
        }
    }
}
