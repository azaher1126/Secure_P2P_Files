using System.Security.Cryptography;
using SecureFiles.Models;
using SecureFiles.Services;

namespace SecureFiles.Tests;

public class UserConfigProviderTests
{
    private static UserConfigProvider CreateProvider()
    {
        using var rsa = RSA.Create(2048);
        var config = new UserConfig(
            "TestUser",
            rsa.ExportSubjectPublicKeyInfo(),
            rsa.ExportPkcs8PrivateKey());
        return new UserConfigProvider(config, "password");
    }

    [Fact]
    public void GetFingerprint_Returns16HexChars()
    {
        var provider = CreateProvider();
        var fingerprint = provider.GetFingerprint();

        Assert.Equal(16, fingerprint.Length);
        Assert.True(fingerprint.All(c => "0123456789abcdef".Contains(c)));
    }

    [Fact]
    public void GetFingerprint_IsSha256First8Bytes()
    {
        using var rsa = RSA.Create(2048);
        var pubKey = rsa.ExportSubjectPublicKeyInfo();
        var config = new UserConfig("User", pubKey, rsa.ExportPkcs8PrivateKey());
        var provider = new UserConfigProvider(config, "pw");

        var expected = Convert.ToHexStringLower(SHA256.HashData(pubKey)[..8]);
        Assert.Equal(expected, provider.GetFingerprint());
    }

    [Fact]
    public void GetFingerprint_DeterministicForSameKey()
    {
        var provider = CreateProvider();
        Assert.Equal(provider.GetFingerprint(), provider.GetFingerprint());
    }

    [Fact]
    public void ReplaceKeys_ChangesFingerprint()
    {
        var provider = CreateProvider();
        var oldFingerprint = provider.GetFingerprint();

        using var newRsa = RSA.Create(2048);
        provider.ReplaceKeys(
            newRsa.ExportSubjectPublicKeyInfo(),
            newRsa.ExportPkcs8PrivateKey());

        Assert.NotEqual(oldFingerprint, provider.GetFingerprint());
    }

    [Fact]
    public void ReplaceKeys_UpdatesPublicAndPrivateKey()
    {
        var provider = CreateProvider();
        using var newRsa = RSA.Create(2048);
        var newPub = newRsa.ExportSubjectPublicKeyInfo();
        var newPriv = newRsa.ExportPkcs8PrivateKey();

        provider.ReplaceKeys(newPub, newPriv);

        Assert.Equal(newPub, provider.PublicKey);
        Assert.Equal(newPriv, provider.PrivateKey);
    }

    [Fact]
    public void Username_IsPreservedAfterReplaceKeys()
    {
        var provider = CreateProvider();
        using var newRsa = RSA.Create(2048);

        provider.ReplaceKeys(
            newRsa.ExportSubjectPublicKeyInfo(),
            newRsa.ExportPkcs8PrivateKey());

        Assert.Equal("TestUser", provider.Username);
    }
}
