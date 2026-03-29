using System.Collections.Concurrent;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using SecureFiles.Networking;
using SecureFiles.Networking.Messages;

namespace SecureFiles.Services;

public class KeyMigrationService
{
    private readonly UserConfigProvider _userConfigProvider;
    private readonly LocalFileService _localFileService;
    private readonly ContactStore _contactStore;
    private readonly ConnectionManager _connectionManager;
    private readonly MessageFramer _messageFramer;
    private readonly ConsentQueue _consentQueue;
    private readonly PeerService _peerService;
    private readonly ILogger<KeyMigrationService> _logger;

    private readonly ConcurrentDictionary<string, byte> _seenNonces = new();

    public KeyMigrationService(
        UserConfigProvider userConfigProvider,
        LocalFileService localFileService,
        ContactStore contactStore,
        ConnectionManager connectionManager,
        MessageFramer messageFramer,
        ConsentQueue consentQueue,
        PeerService peerService,
        ILogger<KeyMigrationService> logger)
    {
        _userConfigProvider = userConfigProvider;
        _localFileService = localFileService;
        _contactStore = contactStore;
        _connectionManager = connectionManager;
        _messageFramer = messageFramer;
        _consentQueue = consentQueue;
        _peerService = peerService;
        _logger = logger;
    }

    public async Task MigrateKeyAsync(CancellationToken ct)
    {
        // Generate new RSA-2048 key pair
        using var newRsa = RSA.Create(2048);
        var newPublicKey = newRsa.ExportSubjectPublicKeyInfo();
        var newPrivateKey = newRsa.ExportPkcs8PrivateKey();

        // Generate replay nonce
        var replayNonce = RandomNumberGenerator.GetBytes(16);

        // Sign (NewPublicKeyDer || ReplayNonce) with OLD private key
        var signedData = new byte[newPublicKey.Length + replayNonce.Length];
        newPublicKey.CopyTo(signedData.AsSpan());
        replayNonce.CopyTo(signedData.AsSpan(newPublicKey.Length));

        using var oldRsa = RSA.Create();
        oldRsa.ImportPkcs8PrivateKey(_userConfigProvider.PrivateKey, out _);
        var signature = oldRsa.SignData(signedData, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        var message = new KeyMigrationMessage(newPublicKey, replayNonce, signature);
        var payload = message.Serialize();

        // Send to all active sessions
        foreach (var (_, session) in _connectionManager.ActiveSessions)
        {
            if (session.IsExpired) continue;
            try
            {
                await _messageFramer.SendMessage(session, MessageType.KeyMigration, payload, ct);
                _logger.LogInformation("Sent key migration to {Peer}", session.PeerFingerprint);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to send key migration to {Peer}", session.PeerFingerprint);
            }
        }

        // Persist new keys to disk
        _userConfigProvider.ReplaceKeys(newPublicKey, newPrivateKey);
        await _userConfigProvider.SaveNewKeysAsync(_localFileService, ct);

        // Close all sessions — next handshake will use new key
        foreach (var (fingerprint, _) in _connectionManager.ActiveSessions)
        {
            _connectionManager.RemoveSession(fingerprint);
        }

        // Re-advertise with new fingerprint
        await _peerService.ReAdvertiseAsync();

        _logger.LogInformation("Key migration complete. New fingerprint: {Fingerprint}", _userConfigProvider.GetFingerprint());
    }

    public async Task<bool> HandleKeyMigrationAsync(Session session, byte[] payload, CancellationToken ct)
    {
        var message = KeyMigrationMessage.Deserialize(payload);

        // Get sender's currently trusted public key
        var trustedKey = _contactStore.GetPublicKey(session.PeerFingerprint);
        if (trustedKey == null)
        {
            _logger.LogWarning("Received key migration from unknown contact {Peer}", session.PeerFingerprint);
            return false;
        }

        // Verify signature over (NewPublicKeyDer || ReplayNonce) using trusted key
        var signedData = new byte[message.NewPublicKeyDer.Length + message.ReplayNonce.Length];
        message.NewPublicKeyDer.CopyTo(signedData.AsSpan());
        message.ReplayNonce.CopyTo(signedData.AsSpan(message.NewPublicKeyDer.Length));

        using var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(trustedKey, out _);

        bool valid;
        try
        {
            valid = rsa.VerifyData(signedData, message.OldSignature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        }
        catch (CryptographicException)
        {
            valid = false;
        }

        if (!valid)
        {
            _logger.LogError("Key migration signature verification failed from {Peer}", session.PeerFingerprint);
            return false;
        }

        // Check replay nonce
        var nonceHex = Convert.ToHexStringLower(message.ReplayNonce);
        if (!_seenNonces.TryAdd(nonceHex, 0))
        {
            _logger.LogError("Replayed key migration nonce from {Peer}", session.PeerFingerprint);
            return false;
        }

        // Update contact store with new public key
        await _contactStore.SaveContactAsync(session.PeerFingerprint, message.NewPublicKeyDer, ct);

        _logger.LogInformation("Contact {Peer} migrated to new key", session.PeerFingerprint);

        // Notify the user via consent queue (fire-and-forget, no need to wait for dismissal)
        _ = _consentQueue.RequestConsent(new Models.ConsentRequest
        {
            Type = Models.ConsentRequestType.KeyMigrationNotice,
            PeerName = session.PeerFingerprint,
            FileName = ""
        });

        // Signal that session should be terminated
        return true;
    }
}
