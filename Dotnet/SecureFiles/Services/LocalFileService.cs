using System.Security.Cryptography;

namespace SecureFiles.Services;

public class LocalFileService : IDisposable
{
    private readonly Aes _aes = Aes.Create();

    public string DataDirectory { get; }

    public LocalFileService(string? dataDirectory = null)
    {
        _aes.KeySize = 256;
        _aes.Mode = CipherMode.CBC;
        _aes.Padding = PaddingMode.PKCS7;

        DataDirectory = dataDirectory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "SecureFiles");
    }
    
    public string GetLogFilePath() => Path.Combine(DataDirectory, "app.log");

    public bool FileExists(string relativePath) =>
        File.Exists(ResolvePath(relativePath));

    public async Task<byte[]> ReadRawBytes(string relativePath, CancellationToken cancellationToken = default) =>
        await File.ReadAllBytesAsync(ResolvePath(relativePath), cancellationToken);

    public async Task WriteRawBytes(string relativePath, byte[] bytes, CancellationToken cancellationToken = default)
    {
        EnsureDirectoryExists(relativePath);
        await File.WriteAllBytesAsync(ResolvePath(relativePath), bytes, cancellationToken);
    }

    /// <summary>
    /// Reads and decrypts a file written by WriteEncryptedBytes.
    /// Expected format on disk: [IV (16 bytes)][AES-256-CBC Ciphertext]
    /// </summary>
    public async Task<byte[]> ReadEncryptedBytes(string relativePath, byte[] key)
    {
        var fullPath = ResolvePath(relativePath);
        var fileBytes = await File.ReadAllBytesAsync(fullPath);

        if (fileBytes.Length < 16)
            throw new InvalidOperationException($"File '{relativePath}' is too small to contain a valid IV.");

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
    public async Task WriteEncryptedBytes(string relativePath, byte[] bytes, byte[] key)
    {
        EnsureDirectoryExists(relativePath);
        var fullPath = ResolvePath(relativePath);

        _aes.Key = key;
        _aes.GenerateIV();

        using var encryptor = _aes.CreateEncryptor();
        var ciphertext = encryptor.TransformFinalBlock(bytes, 0, bytes.Length);

        await using var fs = new FileStream(fullPath, FileMode.Create, FileAccess.Write);
        await fs.WriteAsync(_aes.IV);
        await fs.WriteAsync(ciphertext);
    }

    public void DeleteFile(string relativePath)
    {
        var fullPath = ResolvePath(relativePath);
        if (File.Exists(fullPath))
            File.Delete(fullPath);
    }

    public void EnsureDataDirectoryExists() => Directory.CreateDirectory(DataDirectory);

    public void DeleteDataDirectory()
    {
        if (Directory.Exists(DataDirectory))
            Directory.Delete(DataDirectory, true);
    }

    private string ResolvePath(string relativePath) =>
        Path.Combine(DataDirectory, relativePath);

    private void EnsureDirectoryExists(string relativePath)
    {
        var fullPath = ResolvePath(relativePath);
        var directory = Path.GetDirectoryName(fullPath);
        if (directory != null)
            Directory.CreateDirectory(directory);
    }

    public void Dispose()
    {
        _aes.Dispose();
        GC.SuppressFinalize(this);
    }
}
