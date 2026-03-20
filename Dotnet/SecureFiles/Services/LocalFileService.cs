using System.Security.Cryptography;

namespace SecureFiles.Services;

public class LocalFileService : IDisposable
{
    private readonly Aes _aes = Aes.Create();

    public LocalFileService()
    {
        _aes.KeySize = 256;
        _aes.Mode = CipherMode.CBC;
        _aes.Padding = PaddingMode.PKCS7;
    }

    /// <summary>
    /// Reads and decrypts a file written by WriteEncryptedBytes.
    /// Expected format on disk: [IV (16 bytes)][AES-256-CBC Ciphertext]
    /// </summary>
    public async Task<byte[]> ReadEncryptedBytes(string filePath, byte[] key)
    {
        var fileBytes = await File.ReadAllBytesAsync(filePath);

        if (fileBytes.Length < 16)
            throw new InvalidOperationException($"File '{filePath}' is too small to contain a valid IV.");

        _aes.Key = key;
        _aes.IV = fileBytes[..16];

        using var decryptor = _aes.CreateDecryptor();
        return decryptor.TransformFinalBlock(fileBytes, 16, fileBytes.Length - 16);
    }

    /// <summary>
    /// Encrypts bytes and writes them to disk.
    /// Format on disk: [IV (16 bytes)][AES-256-CBC Ciphertext]
    /// A fresh random IV is generated for every write.
    /// </summary>
    public async Task WriteEncryptedBytes(string filePath, byte[] bytes, byte[] key)
    {
        _aes.Key = key;
        _aes.GenerateIV();

        using var encryptor = _aes.CreateEncryptor();
        var ciphertext = encryptor.TransformFinalBlock(bytes, 0, bytes.Length);

        await using var fs = new FileStream(filePath, FileMode.Create, FileAccess.Write);
        await fs.WriteAsync(_aes.IV);
        await fs.WriteAsync(ciphertext);
    }

    public void Dispose()
    {
        _aes.Dispose();
        GC.SuppressFinalize(this);
    }
}