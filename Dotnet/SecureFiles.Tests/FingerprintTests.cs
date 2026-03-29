using System.Security.Cryptography;
using SecureFiles.Models;
using SecureFiles.Services;

namespace SecureFiles.Tests;

public class FingerprintTests
{
    [Fact]
    public void TwoDifferentKeys_ProduceDifferentFingerprints()
    {
        using var rsa1 = RSA.Create(2048);
        using var rsa2 = RSA.Create(2048);

        var fp1 = ComputeFingerprint(rsa1.ExportSubjectPublicKeyInfo());
        var fp2 = ComputeFingerprint(rsa2.ExportSubjectPublicKeyInfo());

        Assert.NotEqual(fp1, fp2);
    }

    [Fact]
    public void SameKey_ProducesSameFingerprint()
    {
        using var rsa = RSA.Create(2048);
        var pubKey = rsa.ExportSubjectPublicKeyInfo();

        Assert.Equal(ComputeFingerprint(pubKey), ComputeFingerprint(pubKey));
    }

    [Fact]
    public void Fingerprint_MatchesBetweenProviderAndManualComputation()
    {
        using var rsa = RSA.Create(2048);
        var pubKey = rsa.ExportSubjectPublicKeyInfo();
        var config = new UserConfig("User", pubKey, rsa.ExportPkcs8PrivateKey());
        var provider = new UserConfigProvider(config, "pw");

        var manual = ComputeFingerprint(pubKey);
        Assert.Equal(manual, provider.GetFingerprint());
    }

    private static string ComputeFingerprint(byte[] publicKeyDer)
    {
        var hash = SHA256.HashData(publicKeyDer);
        return Convert.ToHexStringLower(hash[..8]);
    }
}
