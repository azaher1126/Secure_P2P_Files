using System.Net.Sockets;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using SecureFiles.Helpers;
using SecureFiles.Services;

namespace SecureFiles.Networking;

public class HandshakeService
{
    private readonly UserConfigProvider _userConfig;
    private readonly ILogger<HandshakeService> _logger;

    public HandshakeService(UserConfigProvider userConfig, ILogger<HandshakeService> logger)
    {
        _userConfig = userConfig;
        _logger = logger;
    }

    /// <summary>
    /// Perform handshake as initiator (Peer A sends first, then receives).
    /// </summary>
    public async Task<Session> InitiateHandshake(TcpClient client, CancellationToken ct)
    {
        var stream = client.GetStream();
        var (myEphemeralPrivate, myEphemeralPublic) = GenerateX25519KeyPair();

        await SendKeyExchangeAsync(stream, myEphemeralPublic, ct);
        _logger.LogDebug("Handshake Phase 1 sent (initiator)");

        var (peerRsaKey, peerX25519Pub) = await ReceiveAndVerifyKeyExchangeAsync(stream, ct);

        var sessionKey = DeriveSessionKey(myEphemeralPrivate, peerX25519Pub);
        var peerFingerprint = ComputeFingerprint(peerRsaKey);

        _logger.LogInformation("Handshake completed with peer {Fingerprint} (initiator)", peerFingerprint);

        return new Session(sessionKey, peerRsaKey, peerFingerprint, client);
    }

    /// <summary>
    /// Perform handshake as responder (Peer B receives first, then sends).
    /// </summary>
    public async Task<Session> AcceptHandshake(TcpClient client, CancellationToken ct)
    {
        var stream = client.GetStream();
        var (myEphemeralPrivate, myEphemeralPublic) = GenerateX25519KeyPair();

        var (peerRsaKey, peerX25519Pub) = await ReceiveAndVerifyKeyExchangeAsync(stream, ct);
        _logger.LogDebug("Handshake Phase 1 received (responder)");

        await SendKeyExchangeAsync(stream, myEphemeralPublic, ct);
        _logger.LogDebug("Handshake Phase 1 sent (responder)");

        var sessionKey = DeriveSessionKey(myEphemeralPrivate, peerX25519Pub);
        var peerFingerprint = ComputeFingerprint(peerRsaKey);

        _logger.LogInformation("Handshake completed with peer {Fingerprint} (responder)", peerFingerprint);

        return new Session(sessionKey, peerRsaKey, peerFingerprint, client);
    }

    private static (X25519PrivateKeyParameters privateKey, byte[] publicKeyBytes) GenerateX25519KeyPair()
    {
        var generator = new X25519KeyPairGenerator();
        generator.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 256));
        var keyPair = generator.GenerateKeyPair();

        var privateKey = (X25519PrivateKeyParameters)keyPair.Private;
        var publicKey = (X25519PublicKeyParameters)keyPair.Public;

        var publicKeyBytes = new byte[X25519PublicKeyParameters.KeySize];
        publicKey.Encode(publicKeyBytes, 0);

        return (privateKey, publicKeyBytes);
    }

    private async Task SendKeyExchangeAsync(Stream stream, byte[] x25519PublicKey, CancellationToken ct)
    {
        using var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(_userConfig.PublicKey, out _);
        rsa.ImportPkcs8PrivateKey(_userConfig.PrivateKey, out _);

        // Sign the 32-byte X25519 public value with RSA-PSS
        var signature = rsa.SignData(
            x25519PublicKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss);

        // Write wire format directly to the network stream:
        // [RSA_Pub_Key_Len (4B BE)] [RSA_Pub_Key_DER]
        // [X25519_Pub_Value_Len (4B BE)] [X25519_Pub_Value (32B)]
        // [Signature_Len (4B BE)] [RSA_PSS_Signature]
        await BigEndianHelper.WriteLengthPrefixed(stream, _userConfig.PublicKey, ct);
        await BigEndianHelper.WriteLengthPrefixed(stream, x25519PublicKey, ct);
        await BigEndianHelper.WriteLengthPrefixed(stream, signature, ct);
        await stream.FlushAsync(ct);
    }

    private static async Task<(RSA peerRsaKey, byte[] peerX25519Pub)> ReceiveAndVerifyKeyExchangeAsync(
        Stream stream, CancellationToken ct)
    {
        // Read RSA public key
        var rsaPubDer = await BigEndianHelper.ReadLengthPrefixed(stream, ct);

        // Read X25519 public value
        var x25519Pub = await BigEndianHelper.ReadLengthPrefixed(stream, ct);
        if (x25519Pub.Length != 32)
            throw new CryptographicException($"Expected 32-byte X25519 public key, got {x25519Pub.Length} bytes");

        // Read RSA-PSS signature
        var signature = await BigEndianHelper.ReadLengthPrefixed(stream, ct);

        // Import peer's RSA public key
        var peerRsa = RSA.Create();
        peerRsa.ImportSubjectPublicKeyInfo(rsaPubDer, out _);

        // Verify signature over the X25519 public value
        var valid = peerRsa.VerifyData(
            x25519Pub,
            signature,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss);

        if (!valid)
        {
            peerRsa.Dispose();
            throw new CryptographicException("Handshake failed: RSA-PSS signature verification failed on peer's X25519 public key");
        }

        return (peerRsa, x25519Pub);
    }

    private static byte[] DeriveSessionKey(X25519PrivateKeyParameters myPrivateKey, byte[] peerPublicKeyBytes)
    {
        // Compute X25519 shared secret
        var peerPublicKey = new X25519PublicKeyParameters(peerPublicKeyBytes, 0);
        var agreement = new X25519Agreement();
        agreement.Init(myPrivateKey);

        var sharedSecret = new byte[agreement.AgreementSize];
        agreement.CalculateAgreement(peerPublicKey, sharedSecret, 0);

        // Derive session key via HKDF-SHA256
        var salt = "CISC468-SALT"u8.ToArray();
        var info = "SessionKey"u8.ToArray();

        var sessionKey = HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            ikm: sharedSecret,
            outputLength: 32,
            salt: salt,
            info: info);

        // Zero the raw shared secret
        CryptographicOperations.ZeroMemory(sharedSecret);

        return sessionKey;
    }

    private static string ComputeFingerprint(RSA rsaKey)
    {
        var spkiDer = rsaKey.ExportSubjectPublicKeyInfo();
        var hash = SHA256.HashData(spkiDer);
        return Convert.ToHexStringLower(hash[..8]);
    }
}
