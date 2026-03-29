using System.Security.Cryptography;
using System.Text;
using SecureFiles.Models;

namespace SecureFiles.Services;

public static class SignatureVerifier
{
    public static bool VerifyFileSignature(byte[] ownerPublicKeyDer, SharedFile fileMetadata, byte[] fileData)
    {
        var hash = SHA256.HashData(fileData);

        if (!hash.AsSpan().SequenceEqual(fileMetadata.Hash))
            return false;

        using var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(ownerPublicKeyDer, out _);

        // Signature is over: UTF8(filename) || SHA256(fileData)  (per spec Section 6.3.1)
        var signedData = Encoding.UTF8.GetBytes(fileMetadata.Name).Concat(hash).ToArray();
        return rsa.VerifyData(signedData, fileMetadata.OwnerSignature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
    }
}
