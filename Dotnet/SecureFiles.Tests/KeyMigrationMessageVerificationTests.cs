using System.Security.Cryptography;
using SecureFiles.Networking.Messages;

namespace SecureFiles.Tests;

public class KeyMigrationMessageVerificationTests
{
    private static (RSA oldKey, RSA newKey, KeyMigrationMessage message) CreateValidMigration()
    {
        var oldRsa = RSA.Create(2048);
        var newRsa = RSA.Create(2048);
        var newPubDer = newRsa.ExportSubjectPublicKeyInfo();
        var nonce = RandomNumberGenerator.GetBytes(16);

        var signedData = newPubDer.Concat(nonce).ToArray();
        var signature = oldRsa.SignData(signedData, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        return (oldRsa, newRsa, new KeyMigrationMessage(newPubDer, nonce, signature));
    }

    [Fact]
    public void ValidSignature_VerifiesSuccessfully()
    {
        var (oldKey, _, msg) = CreateValidMigration();
        var trustedKey = oldKey.ExportSubjectPublicKeyInfo();

        using var verifier = RSA.Create();
        verifier.ImportSubjectPublicKeyInfo(trustedKey, out _);

        var signedData = msg.NewPublicKeyDer.Concat(msg.ReplayNonce).ToArray();
        var valid = verifier.VerifyData(signedData, msg.OldSignature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        Assert.True(valid);
        oldKey.Dispose();
    }

    [Fact]
    public void TamperedNewKey_FailsVerification()
    {
        var (oldKey, _, msg) = CreateValidMigration();
        var trustedKey = oldKey.ExportSubjectPublicKeyInfo();

        // Tamper with the new public key
        var tampered = (byte[])msg.NewPublicKeyDer.Clone();
        tampered[10] ^= 0xFF;

        using var verifier = RSA.Create();
        verifier.ImportSubjectPublicKeyInfo(trustedKey, out _);

        var signedData = tampered.Concat(msg.ReplayNonce).ToArray();
        var valid = verifier.VerifyData(signedData, msg.OldSignature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        Assert.False(valid);
        oldKey.Dispose();
    }

    [Fact]
    public void TamperedNonce_FailsVerification()
    {
        var (oldKey, _, msg) = CreateValidMigration();
        var trustedKey = oldKey.ExportSubjectPublicKeyInfo();

        var tamperedNonce = (byte[])msg.ReplayNonce.Clone();
        tamperedNonce[0] ^= 0xFF;

        using var verifier = RSA.Create();
        verifier.ImportSubjectPublicKeyInfo(trustedKey, out _);

        var signedData = msg.NewPublicKeyDer.Concat(tamperedNonce).ToArray();
        var valid = verifier.VerifyData(signedData, msg.OldSignature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        Assert.False(valid);
        oldKey.Dispose();
    }

    [Fact]
    public void WrongTrustedKey_FailsVerification()
    {
        var (oldKey, _, msg) = CreateValidMigration();
        using var wrongKey = RSA.Create(2048);

        using var verifier = RSA.Create();
        verifier.ImportSubjectPublicKeyInfo(wrongKey.ExportSubjectPublicKeyInfo(), out _);

        var signedData = msg.NewPublicKeyDer.Concat(msg.ReplayNonce).ToArray();
        var valid = verifier.VerifyData(signedData, msg.OldSignature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        Assert.False(valid);
        oldKey.Dispose();
    }

    [Fact]
    public void RoundTrip_SerializeDeserialize_PreservesVerifiability()
    {
        var (oldKey, _, msg) = CreateValidMigration();
        var trustedKey = oldKey.ExportSubjectPublicKeyInfo();

        // Serialize and deserialize
        var deserialized = KeyMigrationMessage.Deserialize(msg.Serialize());

        using var verifier = RSA.Create();
        verifier.ImportSubjectPublicKeyInfo(trustedKey, out _);

        var signedData = deserialized.NewPublicKeyDer.Concat(deserialized.ReplayNonce).ToArray();
        var valid = verifier.VerifyData(signedData, deserialized.OldSignature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        Assert.True(valid);
        oldKey.Dispose();
    }
}
