using System.Security.Cryptography;
using SecureFiles.Networking.Messages;

namespace SecureFiles.Tests.Messages;

public class KeyMigrationMessageTests
{
    [Fact]
    public void RoundTrip_RealisticPayload()
    {
        using var rsa = RSA.Create(2048);
        var pubKey = rsa.ExportSubjectPublicKeyInfo();
        var nonce = RandomNumberGenerator.GetBytes(16);
        var sig = new byte[256];
        Random.Shared.NextBytes(sig);

        var original = new KeyMigrationMessage(pubKey, nonce, sig);
        var deserialized = KeyMigrationMessage.Deserialize(original.Serialize());

        Assert.Equal(pubKey, deserialized.NewPublicKeyDer);
        Assert.Equal(nonce, deserialized.ReplayNonce);
        Assert.Equal(sig, deserialized.OldSignature);
    }

    [Fact]
    public void Serialize_ThreeLengthPrefixedFields()
    {
        var key = new byte[] { 1, 2, 3 };
        var nonce = new byte[] { 4, 5 };
        var sig = new byte[] { 6 };

        var msg = new KeyMigrationMessage(key, nonce, sig);
        var bytes = msg.Serialize();

        // 4 + 3 + 4 + 2 + 4 + 1 = 18
        Assert.Equal(18, bytes.Length);
    }
}
