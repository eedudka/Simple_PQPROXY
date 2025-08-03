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
using System.Buffers;
using System.Threading.Channels;
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
        private readonly SemaphoreSlim _connectionSemaphore;
        private readonly Channel<TcpClient> _clientQueue;
        private readonly List<Task> _workers = new();
        private int _activeConnections = 0;
        private long _totalConnections = 0;
        private const int ConnectionTimeoutMs = 30000;
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

            var maxConn = 1000;
            _connectionSemaphore = new SemaphoreSlim(maxConn, maxConn);
            
            // Канал для очереди клиентов
            _clientQueue = Channel.CreateUnbounded<TcpClient>(new UnboundedChannelOptions
            {
                SingleReader = false,
                SingleWriter = false
            });
        }

        public Task StartAsync(CancellationToken cancellationToken)
        {
            _listener = new TcpListener(IPAddress.Any, _settings.MainSettings.Server.Port);
            _listener.Start();
            _logger.LogInformation("Optimized proxy listening on 0.0.0.0:{Port} (max connections: {MaxConn})", 
                _settings.MainSettings.Server.Port, 
                _connectionSemaphore.CurrentCount);
            
            // Запускаем воркеры для обработки подключений
            for (int i = 0; i < 4; i++)
            {
                _workers.Add(Task.Run(() => ProcessClientsAsync(_cts.Token), _cts.Token));
            }
            
            // Запускаем accept loop
            _ = AcceptLoopAsync(_cts.Token);
            
            return Task.CompletedTask;
        }

        private async Task ProcessClientsAsync(CancellationToken ct)
        {
            await foreach (var client in _clientQueue.Reader.ReadAllAsync(ct))
            {
                // Запускаем обработку в отдельной задаче
                _ = Task.Run(async () =>
                {
                    await _connectionSemaphore.WaitAsync(ct);
                    try
                    {
                        Interlocked.Increment(ref _activeConnections);
                        Interlocked.Increment(ref _totalConnections);
                        await HandleClientAsync(client, ct);
                    }
                    finally
                    {
                        Interlocked.Decrement(ref _activeConnections);
                        _connectionSemaphore.Release();
                    }
                }, ct);
            }
        }

        private async Task AcceptLoopAsync(CancellationToken ct)
        {
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    // Используем AcceptTcpClientAsync без cancellation token для избежания исключений
                    var tcpClientTask = _listener.AcceptTcpClientAsync();
                    var tcs = new TaskCompletionSource<bool>();
                    
                    using (ct.Register(() => tcs.TrySetCanceled()))
                    {
                        var completedTask = await Task.WhenAny(tcpClientTask, tcs.Task);
                        if (completedTask == tcs.Task)
                        {
                            break;
                        }
                    }
                    
                    var client = await tcpClientTask;
                    
                    // Проверяем лимит подключений
                    if (_connectionSemaphore.CurrentCount == 0)
                    {
                        _logger.LogWarning("Connection limit reached, rejecting new connection");
                        client.Close();
                        continue;
                    }
                    
                    // Добавляем в очередь на обработку
                    await _clientQueue.Writer.WriteAsync(client, ct);
                }
            }
            catch (ObjectDisposedException)
            {
                // Нормальное завершение при остановке
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in AcceptLoopAsync");
            }
            finally
            {
                _clientQueue.Writer.TryComplete();
            }
        }

        private async Task HandleClientAsync(TcpClient client, CancellationToken ct)
        {
            using (client)
            {
                try
                {
                    // Устанавливаем таймауты
                    client.ReceiveTimeout = ConnectionTimeoutMs;
                    client.SendTimeout = ConnectionTimeoutMs;

                    using var net = client.GetStream();

                    // Парсим CONNECT с таймаутом
                    using var parseTimeout = new CancellationTokenSource(5000);
                    using var combined = CancellationTokenSource.CreateLinkedTokenSource(ct, parseTimeout.Token);

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

                    using var handshakeTimeout = new CancellationTokenSource(10000);
                    using var handshakeCombined = CancellationTokenSource.CreateLinkedTokenSource(ct, handshakeTimeout.Token);

                    await ssl.AuthenticateAsServerAsync(options);

                    _logger.LogInformation("→ {Host}:{Port} (CONNECT) [Active: {Active}, Total: {Total}]",
                        req.Host, req.Port, _activeConnections, _totalConnections);

                    using var backend = _pqFactory.Connect(req.Host, req.Port);

                    await Task.WhenAll(
                            CopyWithTimeoutAsync(ssl, backend.Stream, ct),
                            CopyWithTimeoutAsync(backend.Stream, ssl, ct));
                }
                catch (IOException io) when (io.Message.Contains("EOF"))
                {
                    _logger.LogDebug(io, "TLS aborted by peer — ok");
                    return;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error in HandleClientAsync");
                }
            }
        }

        private async Task CopyWithTimeoutAsync(Stream source, Stream destination, CancellationToken ct)
        {
            var buffer = ArrayPool<byte>.Shared.Rent(81920);
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    using var timeoutCts = new CancellationTokenSource(30000);
                    using var combined = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);
                    
                    var bytesRead = await source.ReadAsync(buffer, 0, buffer.Length, combined.Token);
                    if (bytesRead == 0) break;
                    
                    await destination.WriteAsync(buffer, 0, bytesRead, combined.Token);
                    await destination.FlushAsync(combined.Token);
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        public async Task StopAsync(CancellationToken cancellationToken)
        {
            _logger.LogInformation("Stopping proxy service...");
            
            // Прекращаем прием новых подключений
            _listener?.Stop();
            _clientQueue.Writer.TryComplete();
            
            // Даем время на завершение активных подключений
            using var shutdownCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            using var combined = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, shutdownCts.Token);
            
            try
            {
                // Ждем завершения воркеров
                await Task.WhenAll(_workers);
                
                // Ждем завершения активных подключений
                while (_activeConnections > 0 && !combined.Token.IsCancellationRequested)
                {
                    _logger.LogInformation("Waiting for {Count} active connections to close...", _activeConnections);
                    await Task.Delay(1000, combined.Token);
                }
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Shutdown timeout reached, forcing close");
            }
            
            _cts.Cancel();
            _logger.LogInformation("Proxy service stopped. Total connections served: {Total}", _totalConnections);
        }

        public void Dispose()
        {
            _cts?.Cancel();
            _cts?.Dispose();
            _connectionSemaphore?.Dispose();
        }
    }
}
