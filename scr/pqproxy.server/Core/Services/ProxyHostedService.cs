using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using pqproxy.server.Core.Models;
using pqproxy.server.Core.Networking;
using pqproxy.server.Core.Middleware;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System.Security.Cryptography.X509Certificates;
namespace pqproxy.server.Core.Services
{
    /// <summary>
    /// HostedService, который слушает входящие TCP-подключения и форвардит их через PQ-TLS.
    /// </summary>
    public class ProxyHostedService : IHostedService, IDisposable
    {
        private readonly SettingsDto _settings;
        private readonly CertificateManager _certMgr;
        private readonly IPqTlsClientFactory _pqFactory;
        private readonly ILogger<ProxyHostedService> _logger;
        private TcpListener _listener;
        private CancellationTokenSource _cts = new();

        public ProxyHostedService(
            SettingsDto settings,
            CertificateManager certMgr,
            IPqTlsClientFactory pqFactory,
            ILogger<ProxyHostedService> logger)
        {
            _settings = settings;
            _certMgr = certMgr;
            _pqFactory = pqFactory;
            _logger = logger;
        }

        public Task StartAsync(CancellationToken cancellationToken)
        {
            _listener = new TcpListener(IPAddress.Any, _settings.MainSettings.Server.Port);
            _listener.Start();
            _logger.LogInformation("Proxy listening on 0.0.0.0:{Port}", _settings.MainSettings.Server.Port);
            _ = AcceptLoopAsync(_cts.Token);
            return Task.CompletedTask;
        }

        private async Task AcceptLoopAsync(CancellationToken ct)
        {
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    var client = await _listener.AcceptTcpClientAsync(ct);
                    _ = Task.Run(() => HandleClientAsync(client, ct), ct);
                }
            }
            catch (OperationCanceledException) { }
        }

        private async Task HandleClientAsync(TcpClient client, CancellationToken ct)
        {
            try
            {
                using var net = client.GetStream();

                var req = await ConnectParser.ParseAsync(net);
                if (req is null) return;

                await net.WriteAsync("HTTP/1.1 200 Connection Established\r\n\r\n"u8.ToArray(), ct);
                await net.FlushAsync(ct);

                using var pre = new PrebufferStream(net, req.Leftover);

                var pfxBytes = _certMgr.GetLeafPfx(req.Host);
                var leaf = new X509Certificate2(
                    pfxBytes,
                    (string?)null,
                    X509KeyStorageFlags.Exportable
                  | X509KeyStorageFlags.PersistKeySet
                  | X509KeyStorageFlags.MachineKeySet);

                using var ssl = new SslStream(pre, leaveInnerStreamOpen: false);
                var protos = SslProtocols.Tls12 | SslProtocols.Tls13;

                var options = new SslServerAuthenticationOptions
                {
                    ServerCertificate = leaf,
                    ClientCertificateRequired = false,
                    EnabledSslProtocols = protos,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                    ApplicationProtocols = new List<SslApplicationProtocol>
                    {
                        SslApplicationProtocol.Http2,
                        SslApplicationProtocol.Http11
                    }
                };

                await ssl.AuthenticateAsServerAsync(options);

                _logger.LogInformation("→ {Host}:{Port} (CONNECT)", req.Host, req.Port);

                using var backend = _pqFactory.Connect(req.Host, req.Port);

                await Task.WhenAll(
                    ssl.CopyToAsync(backend.Stream, ct),
                    backend.Stream.CopyToAsync(ssl, ct)
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in HandleClientAsync");
            }
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            _cts.Cancel();
            _listener.Stop();
            return Task.CompletedTask;
        }

        public void Dispose() => _cts.Cancel();
    }
}
