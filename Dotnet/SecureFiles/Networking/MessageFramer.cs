using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using SecureFiles.Helpers;

namespace SecureFiles.Networking;

public class MessageFramer
{
    private const int NonceSize = 12;
    private const int TagSize = 16;

    private readonly ILogger<MessageFramer> _logger;

    public MessageFramer(ILogger<MessageFramer> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Encrypt a payload and send it over the session stream using the §5 wire format.
    /// Wire: [MsgType 1B][PayloadLen 4B BE][Nonce 12B][Ciphertext][AuthTag 16B]
    /// </summary>
    public async Task SendMessage(Session session, MessageType type, byte[] payload, CancellationToken ct = default)
    {
        if (session.IsExpired)
            throw new InvalidOperationException("Session has expired");

        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var ciphertext = new byte[payload.Length];
        var tag = new byte[TagSize];

        using var aes = new AesGcm(session.SessionKey, TagSize);
        aes.Encrypt(nonce, payload, ciphertext, tag);

        using var stream = new MemoryStream();

        // Write MsgType (1 byte)
        stream.WriteByte((byte)type);

        // Write PayloadLen (4 bytes BE) — length of ciphertext only
        await BigEndianHelper.WriteUInt32BigEndian(stream, (uint)ciphertext.Length, ct);

        // Write Nonce (12 bytes)
        await stream.WriteAsync(nonce, ct);

        // Write Ciphertext
        await stream.WriteAsync(ciphertext, ct);

        // Write AuthTag (16 bytes)
        await stream.WriteAsync(tag, ct);
        
        await session.Stream.WriteAsync(stream.ToArray(), ct);
        await session.Stream.FlushAsync(ct);

        _logger.LogDebug("Sent message type {Type} ({Len} bytes payload)", type, payload.Length);
    }

    /// <summary>
    /// Read and decrypt one message from the session stream using the §5 wire format.
    /// </summary>
    public async Task<(MessageType type, byte[] payload)> ReceiveMessage(Session session, CancellationToken ct = default)
    {
        if (session.IsExpired)
            throw new InvalidOperationException("Session has expired");

        var stream = session.Stream;

        // Read MsgType (1 byte)
        var typeBuf = new byte[1];
        await stream.ReadExactlyAsync(typeBuf, ct);
        var type = (MessageType)typeBuf[0];

        // Read PayloadLen (4 bytes BE)
        var payloadLen = await BigEndianHelper.ReadUInt32BigEndian(stream, ct);

        // Read Nonce (12 bytes)
        var nonce = new byte[NonceSize];
        await stream.ReadExactlyAsync(nonce, ct);

        // Read Ciphertext
        var ciphertext = new byte[payloadLen];
        await stream.ReadExactlyAsync(ciphertext, ct);

        // Read AuthTag (16 bytes)
        var tag = new byte[TagSize];
        await stream.ReadExactlyAsync(tag, ct);

        // Decrypt and verify
        var plaintext = new byte[payloadLen];
        using var aes = new AesGcm(session.SessionKey, TagSize);
        try
        {
            aes.Decrypt(nonce, ciphertext, tag, plaintext);
        }
        catch (CryptographicException)
        {
            _logger.LogError("GCM authentication tag verification failed for message type {Type}", type);
            throw new CryptographicException(
                $"Message integrity check failed for message type {type}. Session terminated.");
        }

        _logger.LogDebug("Received message type {Type} ({Len} bytes payload)", type, payloadLen);

        return (type, plaintext);
    }
}
