using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Quic;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

[assembly: SupportedOSPlatform("linux")]

internal static class Program
{
    internal static void Emit(string kind, object value) => Console.WriteLine(kind + " " + JsonSerializer.Serialize(value));

    private static async Task<int> Main(string[] args)
    {
        try
        {
            var options = Options.Parse(args);
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            using var identity = X509CertificateLoader.LoadPkcs12FromFile(options.Certificate, null, X509KeyStorageFlags.EphemeralKeySet);
            await using var session = await Session.OpenAsync(options, identity, timeout.Token);
            for (var phase = 0; phase < 2; phase++)
                await Protocol.RunAsync(session.Stream, options, phase, timeout.Token);
            if (options.Role == "server")
            {
                Emit("DONE", new { endpoint = "server" });
                await Console.In.ReadLineAsync(timeout.Token);
            }
            return 0;
        }
        catch (Exception error)
        {
            Emit("ERROR", new { type = error.GetType().Name, error.Message, detail = error.ToString() });
            return 1;
        }
    }
}

internal sealed record Options(string Role, string Transport, string Certificate, string Pin, int Port,
    int Payload, int BatchCap, int Window, int RequestedAckEvery, double Warmup, double Seconds,
    long Frames, bool Diagnostics, int Fragment, string Corrupt, string Cancellation, int AbortAfterMilliseconds,
    int RequestedAckBoundary)
{
    internal int FrameBytes => checked(Payload + 8);
    internal int BatchFrames => Math.Min(Window, BatchCap == 0 ? 1 : BatchCap / FrameBytes);
    internal int BatchBytes => checked(BatchFrames * FrameBytes);
    internal int AckEvery => Math.Min(Window, RequestedAckEvery);
    internal int AckBoundary => RequestedAckBoundary == 0 ? BatchFrames : RequestedAckBoundary;

    internal static Options Parse(string[] args)
    {
        if (args.Length == 0 || args[0] is not ("server" or "client"))
            throw new ArgumentException("First argument must be server or client.");
        var values = new Dictionary<string, string>();
        var known = new HashSet<string>(["transport", "cert", "pin", "port", "payload", "batch", "window",
            "ack-every", "warmup", "seconds", "frames", "diagnostics", "fragment", "corrupt", "cancellation", "abort-after-ms", "ack-boundary"]);
        for (var i = 1; i < args.Length; i += 2)
        {
            if (i + 1 == args.Length || !args[i].StartsWith("--", StringComparison.Ordinal)
                || !known.Contains(args[i][2..]) || !values.TryAdd(args[i][2..], args[i + 1]))
                throw new ArgumentException("Unknown, duplicate or incomplete argument.");
        }
        string Get(string key, string fallback) => values.GetValueOrDefault(key, fallback);
        int Number(string key, int fallback) => int.Parse(Get(key, fallback.ToString()), System.Globalization.CultureInfo.InvariantCulture);
        double Real(string key, double fallback) => double.Parse(Get(key, fallback.ToString(System.Globalization.CultureInfo.InvariantCulture)), System.Globalization.CultureInfo.InvariantCulture);
        var result = new Options(args[0], Get("transport", "quic"), Get("cert", ""), Get("pin", ""),
            Number("port", 0), Number("payload", 348), Number("batch", 16384), Number("window", 1280),
            Number("ack-every", 10), Real("warmup", 2), Real("seconds", 6),
            long.Parse(Get("frames", "0"), System.Globalization.CultureInfo.InvariantCulture),
            bool.Parse(Get("diagnostics", "false")), Number("fragment", 0), Get("corrupt", "none"), Get("cancellation", "operation"), Number("abort-after-ms", 0), Number("ack-boundary", 0));
        if (result.Transport is not ("quic" or "tls") || !File.Exists(result.Certificate) || result.Pin.Length != 40
            || result.Port is < 0 or > 65535 || (result.Role == "client" && result.Port == 0)
            || result.Payload is < 1 or > 65536 || result.BatchCap is < 0 or > 1048576
            || result.Window is < 1 or > 65536 || result.RequestedAckEvery < 1 || result.BatchFrames < 1
            || result.RequestedAckBoundary < 0 || result.AckBoundary > result.Window || result.AckBoundary % result.BatchFrames != 0
            || result.Warmup < 0.01 || result.Warmup > 20 || result.Seconds < 0.01 || result.Seconds > 30
            || !double.IsFinite(result.Warmup) || !double.IsFinite(result.Seconds) || result.Frames < 0
            || result.Fragment < 0 || result.Corrupt is not ("none" or "sequence" or "payload")
            || result.Cancellation is not ("operation" or "lifetime") || result.AbortAfterMilliseconds < 0)
            throw new ArgumentException("Invalid transport, identity, workload or bounds.");
        return result;
    }
}

internal sealed class Session(Stream stream, QuicConnection? connection, TcpClient? tcp, CancellationTokenRegistration abort) : IAsyncDisposable
{
    internal Stream Stream { get; } = stream;
    internal static readonly SslApplicationProtocol Alpn = new("transport-spike-v1");
    internal const TlsCipherSuite Cipher = TlsCipherSuite.TLS_AES_128_GCM_SHA256;

    internal static async Task<Session> OpenAsync(Options o, X509Certificate2 identity, CancellationToken token)
    {
        bool Validate(object _, X509Certificate? peer, X509Chain? chain, SslPolicyErrors errors)
        {
            var pin = peer is not null && peer.GetCertHashString().Equals(o.Pin, StringComparison.OrdinalIgnoreCase);
            var hostname = o.Role == "server" || (errors & SslPolicyErrors.RemoteCertificateNameMismatch) == 0;
            if (!pin || !hostname)
                Program.Emit("AUTH_REJECT", new { role = o.Role, reason = !pin ? "pin-mismatch" : "hostname-mismatch" });
            return pin && hostname;
        }
        var cipher = new CipherSuitesPolicy([Cipher]);
        SslClientAuthenticationOptions Client() => new()
        {
            TargetHost = "localhost", EnabledSslProtocols = SslProtocols.Tls13,
            ApplicationProtocols = [Alpn], ClientCertificates = new X509CertificateCollection { identity },
            RemoteCertificateValidationCallback = Validate, CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            CipherSuitesPolicy = cipher
        };
        SslServerAuthenticationOptions Server() => new()
        {
            ServerCertificate = identity, ClientCertificateRequired = true, EnabledSslProtocols = SslProtocols.Tls13,
            ApplicationProtocols = [Alpn], RemoteCertificateValidationCallback = Validate,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck, CipherSuitesPolicy = cipher
        };
        QuicConnection? connection = null;
        TcpClient? tcp = null;
        Stream stream;
        SslProtocols protocol;
        TlsCipherSuite negotiated;
        SslApplicationProtocol alpn;
        X509Certificate? remote;
        if (o.Transport == "quic")
        {
            if (!QuicConnection.IsSupported)
                throw new PlatformNotSupportedException("Native QUIC is unavailable.");
            if (o.Role == "server")
            {
                await using var listener = await QuicListener.ListenAsync(new QuicListenerOptions
                {
                    ListenEndPoint = new IPEndPoint(IPAddress.Loopback, o.Port), ApplicationProtocols = [Alpn],
                    ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(new QuicServerConnectionOptions
                    {
                        ServerAuthenticationOptions = Server(), DefaultCloseErrorCode = 0,
                        DefaultStreamErrorCode = 1, MaxInboundBidirectionalStreams = 1, MaxInboundUnidirectionalStreams = 0
                    })
                }, token);
                Program.Emit("READY", new { port = listener.LocalEndPoint.Port, transport = o.Transport });
                connection = await listener.AcceptConnectionAsync(token);
                stream = await connection.AcceptInboundStreamAsync(token);
            }
            else
            {
                connection = await QuicConnection.ConnectAsync(new QuicClientConnectionOptions
                {
                    RemoteEndPoint = new IPEndPoint(IPAddress.Loopback, o.Port), ClientAuthenticationOptions = Client(),
                    DefaultCloseErrorCode = 0, DefaultStreamErrorCode = 1,
                    MaxInboundBidirectionalStreams = 0, MaxInboundUnidirectionalStreams = 0
                }, token);
                stream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional, token);
            }
            protocol = connection.SslProtocol;
            negotiated = connection.NegotiatedCipherSuite;
            alpn = connection.NegotiatedApplicationProtocol;
            remote = connection.RemoteCertificate;
        }
        else
        {
            if (o.Role == "server")
            {
                using var listener = new TcpListener(IPAddress.Loopback, o.Port);
                listener.Start();
                Program.Emit("READY", new { port = ((IPEndPoint)listener.LocalEndpoint).Port, transport = o.Transport });
                tcp = await listener.AcceptTcpClientAsync(token);
            }
            else
            {
                tcp = new TcpClient();
                await tcp.ConnectAsync(IPAddress.Loopback, o.Port, token);
            }
            tcp.NoDelay = true;
            var ssl = new SslStream(tcp.GetStream(), false);
            if (o.Role == "server")
                await ssl.AuthenticateAsServerAsync(Server(), token);
            else
                await ssl.AuthenticateAsClientAsync(Client(), token);
            stream = ssl;
            protocol = ssl.SslProtocol;
            negotiated = ssl.NegotiatedCipherSuite;
            alpn = ssl.NegotiatedApplicationProtocol;
            remote = ssl.RemoteCertificate;
            if (!ssl.IsMutuallyAuthenticated)
                throw new InvalidDataException("Mutual TLS did not negotiate.");
        }
        if (protocol != SslProtocols.Tls13 || negotiated != Cipher || alpn != Alpn || remote is null
            || !remote.GetCertHashString().Equals(o.Pin, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Negotiated security does not match the control.");
        Program.Emit("SECURITY", new { role = o.Role, transport = o.Transport, tls = protocol.ToString(),
            cipher = negotiated.ToString(), alpn = alpn.ToString(), peerPin = remote.GetCertHashString(),
            mutual = true, tcpSendBuffer = tcp?.SendBufferSize, tcpReceiveBuffer = tcp?.ReceiveBufferSize,
            runtime = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription,
            architecture = System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture.ToString(),
            serverGc = System.Runtime.GCSettings.IsServerGC,
            nativeLibraries = File.ReadLines("/proc/self/maps").Select(line => line.Split(' ', StringSplitOptions.RemoveEmptyEntries)[^1])
                .Where(path => path.StartsWith('/') && new[] { "libmsquic", "libcoreclr", "libssl", "libcrypto" }
                    .Any(prefix => Path.GetFileName(path).StartsWith(prefix, StringComparison.Ordinal))).Distinct().Order().ToArray() });
        var abort = token.Register(() =>
        {
            if (stream is QuicStream quic)
                quic.Abort(QuicAbortDirection.Both, 1);
            else
                tcp!.Dispose();
        });
        return new Session(stream, connection, tcp, abort);
    }

    public async ValueTask DisposeAsync()
    {
        abort.Dispose();
        await Stream.DisposeAsync();
        if (connection is not null)
            await connection.DisposeAsync();
        tcp?.Dispose();
    }
}
