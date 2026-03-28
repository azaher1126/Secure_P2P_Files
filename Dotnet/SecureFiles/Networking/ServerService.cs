using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SecureFiles.Services;

namespace SecureFiles.Networking;

public class ServerService : BackgroundService
{
    private static readonly TimeSpan CleanupInterval = TimeSpan.FromSeconds(30);

    private readonly ILogger<ServerService> _logger;
    private readonly PeerService _peerService;
    private readonly ConnectionManager _connectionManager;
    private readonly MessageFramer _messageFramer;

    private readonly ConcurrentDictionary<Task, byte> _activeConnections = new();

    public ServerService(
        PeerService peerService,
        ConnectionManager connectionManager,
        MessageFramer messageFramer,
        ILogger<ServerService> logger)
    {
        _logger = logger;
        _peerService = peerService;
        _connectionManager = connectionManager;
        _messageFramer = messageFramer;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var listener = new TcpListener(IPAddress.Any, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        _logger.LogInformation("TCP listener started on port {Port}", port);

        await _peerService.StartAsync((ushort)port, stoppingToken);

        var cleanupTask = RunCleanupLoopAsync(stoppingToken);
        var acceptTask = RunAcceptLoopAsync(listener, stoppingToken);

        await Task.WhenAll(acceptTask, cleanupTask);

        // Drain in-flight connections before shutting down
        await Task.WhenAll(_activeConnections.Keys);

        listener.Stop();
    }

    private async Task RunAcceptLoopAsync(TcpListener listener, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var client = await listener.AcceptTcpClientAsync(ct);
                var remoteEp = client.Client.RemoteEndPoint as IPEndPoint;
                _logger.LogDebug("Inbound TCP connection from {Remote}", remoteEp);

                var task = HandleInboundConnectionAsync(client, ct);
                _activeConnections.TryAdd(task, 0);
                _ = task.ContinueWith(t => _activeConnections.TryRemove(t, out _), TaskContinuationOptions.ExecuteSynchronously);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error accepting TCP connection");
            }
        }
    }

    private async Task HandleInboundConnectionAsync(TcpClient client, CancellationToken ct)
    {
        try
        {
            var session = await _connectionManager.AcceptInboundAsync(client, ct);
            await HandleSessionMessagesAsync(session, ct);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Inbound handshake or session failed");
            client.Dispose();
        }
    }

    private async Task HandleSessionMessagesAsync(Session session, CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested && !session.IsExpired)
            {
                var (type, payload) = await _messageFramer.ReceiveMessage(session, ct);
                _logger.LogDebug("Received {Type} from {Peer}", type, session.PeerFingerprint);

                // TODO: Dispatch to protocol handlers (GET_FILE_LIST, REQ_TO_RECEIVE, etc.)
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Session error with {Peer}", session.PeerFingerprint);
        }
        finally
        {
            _connectionManager.RemoveSession(session.PeerFingerprint);
        }
    }

    private async Task RunCleanupLoopAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(CleanupInterval);
        while (await timer.WaitForNextTickAsync(ct))
        {
            _connectionManager.CleanupExpiredSessions();
        }
    }
}
