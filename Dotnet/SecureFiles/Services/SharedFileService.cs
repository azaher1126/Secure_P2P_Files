using System.Security.Cryptography;
using System.Text;
using SecureFiles.Models;

namespace SecureFiles.Services;

public class SharedFileService
{
    private const string FilesDirName = "files";
    private const string IndexFileName = "fileindex";

    private readonly LocalFileService _localFileService;
    private readonly UserConfigService _userConfigService;

    private readonly List<SharedFile> _sharedFiles = [];

    private string FilesDirectory => Path.Combine(_userConfigService.DataDirectory, FilesDirName);
    private string IndexPath => Path.Combine(_userConfigService.DataDirectory, IndexFileName);

    public SharedFileService(LocalFileService localFileService, UserConfigService userConfigService)
    {
        _localFileService = localFileService;
        _userConfigService = userConfigService;
    }

    /// <summary>
    /// Loads the file index from disk. Must be called after UserConfigService is initialized.
    /// </summary>
    public async Task LoadIndex(CancellationToken cancellationToken = default)
    {
        Directory.CreateDirectory(FilesDirectory);

        if (!File.Exists(IndexPath))
            return;

        var key = await _userConfigService.DeriveAesKey(cancellationToken);
        var indexBytes = await _localFileService.ReadEncryptedBytes(IndexPath, key);

        using var reader = new BinaryReader(new MemoryStream(indexBytes), Encoding.UTF8);
        var count = reader.ReadInt32();
        for (var i = 0; i < count; i++)
        {
            _sharedFiles.Add(SharedFile.UnpackBinary(reader));
        }
    }

    /// <summary>
    /// Adds a file to the shared files store. Reads the plaintext file from the given path,
    /// computes its SHA-256 hash, signs (filename || hash) with the local RSA key,
    /// encrypts and stores it in the data directory.
    /// </summary>
    public async Task AddFile(string sourcePath, CancellationToken cancellationToken = default)
    {
        var fileName = Path.GetFileName(sourcePath);

        if (_sharedFiles.Any(f => f.Name == fileName))
            throw new InvalidOperationException($"A file named '{fileName}' is already shared.");

        var plaintext = await File.ReadAllBytesAsync(sourcePath, cancellationToken);
        var hash = SHA256.HashData(plaintext);

        // Sign: filename UTF-8 bytes || SHA-256 hash bytes (per spec Section 6.3.1)
        var signedData = Encoding.UTF8.GetBytes(fileName).Concat(hash).ToArray();
        using var rsa = RSA.Create();
        rsa.ImportPkcs8PrivateKey(_userConfigService.PrivateKey, out _);
        var signature = rsa.SignData(signedData, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        var ownerFingerprint = _userConfigService.GetFingerprint();
        var sharedFile = new SharedFile(fileName, hash, ownerFingerprint, signature);

        // Encrypt and store the file
        var key = await _userConfigService.DeriveAesKey(cancellationToken);
        var encryptedPath = Path.Combine(FilesDirectory, fileName);
        await _localFileService.WriteEncryptedBytes(encryptedPath, plaintext, key);

        _sharedFiles.Add(sharedFile);
        await SaveIndex(key, cancellationToken);
    }

    /// <summary>
    /// Returns the list of all shared files and their metadata.
    /// </summary>
    public IReadOnlyList<SharedFile> ListFiles() => _sharedFiles.AsReadOnly();

    /// <summary>
    /// Decrypts and returns the plaintext bytes of a shared file for transfer to a peer.
    /// </summary>
    public async Task<byte[]> GetFileForTransfer(string fileName, CancellationToken cancellationToken = default)
    {
        var entry = _sharedFiles.FirstOrDefault(f => f.Name == fileName)
            ?? throw new FileNotFoundException($"No shared file named '{fileName}'.");

        var key = await _userConfigService.DeriveAesKey(cancellationToken);
        var encryptedPath = Path.Combine(FilesDirectory, entry.Name);
        return await _localFileService.ReadEncryptedBytes(encryptedPath, key);
    }

    /// <summary>
    /// Stores a file received from a peer. Encrypts the plaintext and saves the metadata.
    /// </summary>
    public async Task ReceiveFile(string fileName, byte[] plaintext, string ownerFingerprint,
        byte[] ownerSignature, CancellationToken cancellationToken = default)
    {
        var hash = SHA256.HashData(plaintext);

        var sharedFile = new SharedFile(fileName, hash, ownerFingerprint, ownerSignature);

        var key = await _userConfigService.DeriveAesKey(cancellationToken);
        var encryptedPath = Path.Combine(FilesDirectory, fileName);
        await _localFileService.WriteEncryptedBytes(encryptedPath, plaintext, key);

        // Replace if a file with the same name already exists
        _sharedFiles.RemoveAll(f => f.Name == fileName);
        _sharedFiles.Add(sharedFile);
        await SaveIndex(key, cancellationToken);
    }

    /// <summary>
    /// Removes a file from the shared files store and deletes it from disk.
    /// </summary>
    public async Task RemoveFile(string fileName, CancellationToken cancellationToken = default)
    {
        var removed = _sharedFiles.RemoveAll(f => f.Name == fileName);
        if (removed == 0)
            throw new FileNotFoundException($"No shared file named '{fileName}'.");

        var encryptedPath = Path.Combine(FilesDirectory, fileName);
        if (File.Exists(encryptedPath))
            File.Delete(encryptedPath);

        var key = await _userConfigService.DeriveAesKey(cancellationToken);
        await SaveIndex(key, cancellationToken);
    }

    private async Task SaveIndex(byte[] key, CancellationToken cancellationToken = default)
    {
        using var ms = new MemoryStream();
        using (var writer = new BinaryWriter(ms, Encoding.UTF8, true))
        {
            writer.Write(_sharedFiles.Count);
            foreach (var file in _sharedFiles)
            {
                var packed = file.PackBinary();
                packed.Position = 0;
                await packed.CopyToAsync(ms, cancellationToken);
            }
        }

        await _localFileService.WriteEncryptedBytes(IndexPath, ms.ToArray(), key);
    }
}