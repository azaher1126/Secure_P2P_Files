using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using SecureFiles.Models;
using SecureFiles.Networking.Messages;
using SecureFiles.Services;

namespace SecureFiles.Networking;

public class ProtocolInitiator
{
    private readonly SharedFileService _sharedFileService;
    private readonly ContactStore _contactStore;
    private readonly MessageFramer _messageFramer;
    private readonly ILogger<ProtocolInitiator> _logger;

    public ProtocolInitiator(
        SharedFileService sharedFileService,
        ContactStore contactStore,
        MessageFramer messageFramer,
        ILogger<ProtocolInitiator> logger)
    {
        _sharedFileService = sharedFileService;
        _contactStore = contactStore;
        _messageFramer = messageFramer;
        _logger = logger;
    }

    /// <summary>
    /// Request the peer's shared file list.
    /// </summary>
    public async Task<IReadOnlyList<SharedFile>> RequestFileListAsync(Session session, CancellationToken ct)
    {
        await _messageFramer.SendMessage(session, MessageType.GetFileList, [], ct);

        var (type, payload) = await _messageFramer.ReceiveMessage(session, ct);
        if (type != MessageType.FileListResponse)
            throw new InvalidOperationException($"Expected FileListResponse, got {type}");

        var response = FileListResponseMessage.Deserialize(payload);
        _logger.LogDebug("Received file list ({Count} files) from {Peer}", response.Files.Count, session.PeerFingerprint);

        await _contactStore.CacheFileListAsync(session.PeerFingerprint, response.Files, ct);

        return response.Files;
    }

    /// <summary>
    /// Request to download a file from the peer.
    /// Requires file metadata from a prior RequestFileListAsync call for signature storage.
    /// Returns true if the transfer completed, false if the peer denied the request.
    /// </summary>
    public async Task<bool> RequestFileAsync(Session session, SharedFile fileMetadata, CancellationToken ct)
    {
        var request = new FileRequestMessage(fileMetadata.Name);
        await _messageFramer.SendMessage(session, MessageType.ReqToReceive, request.Serialize(), ct);

        var (consentType, consentPayload) = await _messageFramer.ReceiveMessage(session, ct);
        if (consentType != MessageType.ConsentResponse)
            throw new InvalidOperationException($"Expected ConsentResponse, got {consentType}");

        var consent = ConsentResponseMessage.Deserialize(consentPayload);
        if (!consent.Accepted)
        {
            _logger.LogInformation("Peer {Peer} denied download of '{File}'", session.PeerFingerprint, fileMetadata.Name);
            return false;
        }

        var (dataType, dataPayload) = await _messageFramer.ReceiveMessage(session, ct);
        if (dataType != MessageType.DataTransfer)
            throw new InvalidOperationException($"Expected DataTransfer, got {dataType}");

        var transfer = DataTransferMessage.Deserialize(dataPayload);

        var ownerKey = _contactStore.GetPublicKey(fileMetadata.OwnerFingerprint);
        if (ownerKey != null)
        {
            if (!SignatureVerifier.VerifyFileSignature(ownerKey, fileMetadata, transfer.FileData))
                throw new CryptographicException("File signature verification failed");
        }
        else
        {
            _logger.LogWarning("Cannot verify signature for '{File}' — owner {Owner} not in contact store",
                fileMetadata.Name, fileMetadata.OwnerFingerprint);
        }

        await _sharedFileService.ReceiveFile(
            transfer.Filename,
            transfer.FileData,
            fileMetadata.OwnerFingerprint,
            fileMetadata.OwnerSignature,
            ct);

        _logger.LogInformation("Downloaded file '{File}' from {Peer}", transfer.Filename, session.PeerFingerprint);
        return true;
    }

    /// <summary>
    /// Offer to send a file to the peer.
    /// Returns true if the transfer completed, false if the peer denied the request.
    /// </summary>
    public async Task<bool> SendFileAsync(Session session, string filename, CancellationToken ct)
    {
        var fileData = await _sharedFileService.GetFileForTransfer(filename, ct);

        var request = new FileRequestMessage(filename);
        await _messageFramer.SendMessage(session, MessageType.ReqToSend, request.Serialize(), ct);

        var (consentType, consentPayload) = await _messageFramer.ReceiveMessage(session, ct);
        if (consentType != MessageType.ConsentResponse)
            throw new InvalidOperationException($"Expected ConsentResponse, got {consentType}");

        var consent = ConsentResponseMessage.Deserialize(consentPayload);
        if (!consent.Accepted)
        {
            _logger.LogInformation("Peer {Peer} denied upload of '{File}'", session.PeerFingerprint, filename);
            return false;
        }

        var transfer = new DataTransferMessage(filename, fileData);
        await _messageFramer.SendMessage(session, MessageType.DataTransfer, transfer.Serialize(), ct);

        _logger.LogInformation("Sent file '{File}' to {Peer}", filename, session.PeerFingerprint);
        return true;
    }
}
