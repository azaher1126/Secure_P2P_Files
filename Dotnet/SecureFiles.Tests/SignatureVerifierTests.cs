using System.Security.Cryptography;
using System.Text;
using SecureFiles.Models;
using SecureFiles.Services;

namespace SecureFiles.Tests;

public class SignatureVerifierTests
{
    private static (byte[] publicKeyDer, SharedFile file, byte[] fileData) CreateSignedFile(
        string filename = "test.txt", string content = "hello world")
    {
        using var rsa = RSA.Create(2048);
        var publicKeyDer = rsa.ExportSubjectPublicKeyInfo();
        var fileData = Encoding.UTF8.GetBytes(content);
        var hash = SHA256.HashData(fileData);
        var fingerprint = Convert.ToHexStringLower(SHA256.HashData(publicKeyDer)[..8]);

        var signedData = Encoding.UTF8.GetBytes(filename).Concat(hash).ToArray();
        var signature = rsa.SignData(signedData, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        var file = new SharedFile(filename, hash, fingerprint, signature);
        return (publicKeyDer, file, fileData);
    }

    [Fact]
    public void ValidSignature_ReturnsTrue()
    {
        var (pubKey, file, data) = CreateSignedFile();
        Assert.True(SignatureVerifier.VerifyFileSignature(pubKey, file, data));
    }

    [Fact]
    public void TamperedFileData_ReturnsFalse()
    {
        var (pubKey, file, data) = CreateSignedFile();
        data[0] ^= 0xFF;
        Assert.False(SignatureVerifier.VerifyFileSignature(pubKey, file, data));
    }

    [Fact]
    public void WrongKey_ReturnsFalse()
    {
        var (_, file, data) = CreateSignedFile();
        using var otherRsa = RSA.Create(2048);
        var otherKey = otherRsa.ExportSubjectPublicKeyInfo();

        Assert.False(SignatureVerifier.VerifyFileSignature(otherKey, file, data));
    }

    [Fact]
    public void TamperedSignature_ReturnsFalse()
    {
        var (pubKey, file, data) = CreateSignedFile();
        var badSig = (byte[])file.OwnerSignature.Clone();
        badSig[0] ^= 0xFF;
        var tamperedFile = file with { OwnerSignature = badSig };

        Assert.False(SignatureVerifier.VerifyFileSignature(pubKey, tamperedFile, data));
    }

    [Fact]
    public void HashMismatch_ReturnsFalse()
    {
        var (pubKey, file, _) = CreateSignedFile();
        var differentData = Encoding.UTF8.GetBytes("different content");

        Assert.False(SignatureVerifier.VerifyFileSignature(pubKey, file, differentData));
    }

    [Fact]
    public void WrongFilename_ReturnsFalse()
    {
        var (pubKey, file, data) = CreateSignedFile("original.txt");
        var renamedFile = file with { Name = "renamed.txt" };

        Assert.False(SignatureVerifier.VerifyFileSignature(pubKey, renamedFile, data));
    }
}
