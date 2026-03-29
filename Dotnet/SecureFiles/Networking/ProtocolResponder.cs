using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using SecureFiles.Models;
using SecureFiles.Networking.Messages;
using SecureFiles.Services;

namespace SecureFiles.Networking;

public class ProtocolResponder
{
    private readonly SharedFileService _sharedFileService;
    private readonly ContactStore _contactStore;
    private readonly ConsentQueue _consentQueue;
    private readonly MessageFramer _messageFramer;
    private readonly ILogger<ProtocolResponder> _logger;

    public ProtocolResponder(
        SharedFileService sharedFileService,
        ContactStore contactStore,
        ConsentQueue consentQueue,
        MessageFramer messageFramer,
        ILogger<ProtocolResponder> logger)
    {
        _sharedFileService = sharedFileService;
        _contactStore = contactStore;
        _consentQueue = consentQueue;
        _messageFramer = messageFramer;
        _logger = logger;
    }

    public async Task HandleMessageAsync(Session session, MessageType type, byte[] payload, CancellationToken ct)
    {
        switch (type)
        {
            case MessageType.GetFileList:
                await HandleGetFileListAsync(session, ct);
                break;
            case MessageType.ReqToReceive:
                await HandleReqToReceiveAsync(session, payload, ct);
                break;
            case MessageType.ReqToSend:
                await HandleReqToSendAsync(session, payload, ct);
                break;
            default:
                _logger.LogWarning("Unexpected inbound message type {Type} from {Peer}", type, session.PeerFingerprint);
                break;
        }
    }

    private async Task HandleGetFileListAsync(Session session, CancellationToken ct)
    {
        var files = _sharedFileService.ListFiles();
        var response = new FileListResponseMessage(files);
        await _messageFramer.SendMessage(session, MessageType.FileListResponse, response.Serialize(), ct);

        _logger.LogDebug("Sent file list ({Count} files) to {Peer}", files.Count, session.PeerFingerprint);
    }

    private async Task HandleReqToReceiveAsync(Session session, byte[] payload, CancellationToken ct)
    {
        var request = FileRequestMessage.Deserialize(payload);
        _logger.LogInformation("Peer {Peer} requests to download '{File}'", session.PeerFingerprint, request.Filename);

        var consent = await _consentQueue.RequestConsent(new ConsentRequest
        {
            Type = ConsentRequestType.SendFile,
            PeerName = session.PeerFingerprint,
            FileName = request.Filename
        }, ct);

        var consentResponse = new ConsentResponseMessage(consent, request.Filename);
        await _messageFramer.SendMessage(session, MessageType.ConsentResponse, consentResponse.Serialize(), ct);

        if (!consent)
        {
            _logger.LogInformation("User denied download of '{File}' to {Peer}", request.Filename, session.PeerFingerprint);
            return;
        }

        var fileData = await _sharedFileService.GetFileForTransfer(request.Filename, ct);
        var transfer = new DataTransferMessage(request.Filename, fileData);
        await _messageFramer.SendMessage(session, MessageType.DataTransfer, transfer.Serialize(), ct);

        _logger.LogInformation("Sent file '{File}' to {Peer}", request.Filename, session.PeerFingerprint);
    }

    private async Task HandleReqToSendAsync(Session session, byte[] payload, CancellationToken ct)
    {
        var request = FileRequestMessage.Deserialize(payload);
        _logger.LogInformation("Peer {Peer} requests to upload '{File}'", session.PeerFingerprint, request.Filename);

        var consent = await _consentQueue.RequestConsent(new ConsentRequest
        {
            Type = ConsentRequestType.ReceiveFile,
            PeerName = session.PeerFingerprint,
            FileName = request.Filename
        }, ct);

        var consentResponse = new ConsentResponseMessage(consent, request.Filename);
        await _messageFramer.SendMessage(session, MessageType.ConsentResponse, consentResponse.Serialize(), ct);

        if (!consent)
        {
            _logger.LogInformation("User denied upload of '{File}' from {Peer}", request.Filename, session.PeerFingerprint);
            return;
        }

        // Read the follow-up DataTransfer message
        var (type, transferPayload) = await _messageFramer.ReceiveMessage(session, ct);
        if (type != MessageType.DataTransfer)
        {
            _logger.LogError("Expected DataTransfer after consent accept, got {Type} from {Peer}", type, session.PeerFingerprint);
            return;
        }

        var transfer = DataTransferMessage.Deserialize(transferPayload);

        // Look up the sender's cached file list to find the file's original metadata
        var cachedFiles = _contactStore.GetCachedFileList(session.PeerFingerprint);
        var fileMeta = cachedFiles?.FirstOrDefault(f => f.Name == transfer.Filename);

        var ownerFingerprint = fileMeta?.OwnerFingerprint ?? session.PeerFingerprint;
        var ownerSignature = fileMeta?.OwnerSignature ?? [];

        // Verify signature if we have the owner's public key
        var ownerKey = _contactStore.GetPublicKey(ownerFingerprint);
        if (ownerKey != null && ownerSignature.Length > 0)
        {
            var metaForVerification = new SharedFile(transfer.Filename, SHA256.HashData(transfer.FileData), ownerFingerprint, ownerSignature);
            if (!SignatureVerifier.VerifyFileSignature(ownerKey, metaForVerification, transfer.FileData))
            {
                _logger.LogError("Signature verification failed for '{File}' from {Peer}", transfer.Filename, session.PeerFingerprint);
                return;
            }
        }
        else
        {
            _logger.LogWarning("Cannot verify signature for '{File}' — owner {Owner} not in contact store or no signature available",
                transfer.Filename, ownerFingerprint);
        }

        await _sharedFileService.ReceiveFile(
            transfer.Filename,
            transfer.FileData,
            ownerFingerprint,
            ownerSignature,
            ct);

        _logger.LogInformation("Received file '{File}' from {Peer}", transfer.Filename, session.PeerFingerprint);
    }
}
