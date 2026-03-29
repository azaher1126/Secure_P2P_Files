using System.Collections.Concurrent;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using SecureFiles.Models;
using SecureFiles.Services;

namespace SecureFiles.Networking;

public class ConnectionManager : IDisposable
{
    private readonly HandshakeService _handshakeService;
    private readonly ContactStore _contactStore;
    private readonly ILogger<ConnectionManager> _logger;

    private readonly ConcurrentDictionary<string, Session> _activeSessions = new();

    public ConnectionManager(
        HandshakeService handshakeService,
        ContactStore contactStore,
        ILogger<ConnectionManager> logger)
    {
        _handshakeService = handshakeService;
        _contactStore = contactStore;
        _logger = logger;
    }

    public IReadOnlyDictionary<string, Session> ActiveSessions => _activeSessions;

    /// <summary>
    /// Accept an inbound TCP connection and perform responder handshake.
    /// Returns the established session.
    /// </summary>
    public async Task<Session> AcceptInboundAsync(TcpClient client, CancellationToken ct)
    {
        var session = await _handshakeService.AcceptHandshake(client, ct);
        StoreSession(session);
        await _contactStore.SaveContactAsync(session.PeerFingerprint, session.PeerPublicKey.ExportSubjectPublicKeyInfo(), ct);
        _logger.LogInformation("Inbound session established with {Peer}", session.PeerFingerprint);
        return session;
    }

    /// <summary>
    /// Connect to a discovered peer and perform initiator handshake.
    /// </summary>
    public async Task<Session> ConnectToPeer(Peer peer, CancellationToken ct)
    {
        if (_activeSessions.TryGetValue(peer.InstanceName, out var existing) && !existing.IsExpired)
        {
            _logger.LogDebug("Reusing existing session with {Peer}", peer.InstanceName);
            return existing;
        }

        var client = new TcpClient();
        await client.ConnectAsync(peer.Address, peer.Port, ct);

        _logger.LogDebug("Connected to peer {Name} at {Address}:{Port}", peer.FriendlyName, peer.Address, peer.Port);

        var session = await _handshakeService.InitiateHandshake(client, ct);
        StoreSession(session);
        await _contactStore.SaveContactAsync(session.PeerFingerprint, session.PeerPublicKey.ExportSubjectPublicKeyInfo(), ct);
        return session;
    }

    /// <summary>
    /// Remove and dispose a specific session.
    /// </summary>
    public void RemoveSession(string peerFingerprint)
    {
        if (_activeSessions.TryRemove(peerFingerprint, out var session))
        {
            session.Dispose();
            _logger.LogDebug("Session with {Peer} removed", peerFingerprint);
        }
    }

    /// <summary>
    /// Remove all expired sessions.
    /// </summary>
    public void CleanupExpiredSessions()
    {
        foreach (var (key, session) in _activeSessions)
        {
            if (session.IsExpired && _activeSessions.TryRemove(key, out var removed))
            {
                _logger.LogInformation("Session with {Peer} expired, cleaning up", key);
                removed.Dispose();
            }
        }
    }

    private void StoreSession(Session session)
    {
        if (_activeSessions.TryRemove(session.PeerFingerprint, out var old))
        {
            _logger.LogDebug("Replacing existing session with {Peer}", session.PeerFingerprint);
            old.Dispose();
        }

        _activeSessions[session.PeerFingerprint] = session;
    }

    public void Dispose()
    {
        foreach (var (_, session) in _activeSessions)
            session.Dispose();

        _activeSessions.Clear();
    }
}
