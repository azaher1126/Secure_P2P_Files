using System.Security.Cryptography;
using System.Text;
using SecureFiles.Models;

namespace SecureFiles.Services;

public class SharedFileService
{
    private const string FilesDirName = "files";
    private const string IndexFileName = "fileindex";

    private readonly LocalFileService _localFileService;
    private readonly UserConfigProvider _userConfigProvider;

    private readonly List<SharedFile> _sharedFiles = [];
    private readonly SemaphoreSlim _indexLock = new(1, 1);

    public SharedFileService(LocalFileService localFileService, UserConfigProvider userConfigProvider)
    {
        _localFileService = localFileService;
        _userConfigProvider = userConfigProvider;
    }

    /// <summary>
    /// Loads the file index from disk. Must be called after UserConfigProvider is available.
    /// </summary>
    public async Task LoadIndex(CancellationToken cancellationToken = default)
    {
        if (!_localFileService.FileExists(IndexFileName))
            return;

        var key = await _userConfigProvider.DeriveAesKey(_localFileService, cancellationToken);
        var indexBytes = await _localFileService.ReadEncryptedBytes(IndexFileName, key);

        using var reader = new BinaryReader(new MemoryStream(indexBytes), Encoding.UTF8);
        var count = reader.ReadInt32();
        await _indexLock.WaitAsync(cancellationToken);
        _sharedFiles.Clear();
        for (var i = 0; i < count; i++)
        {
            _sharedFiles.Add(SharedFile.UnpackBinary(reader));
        }

        _indexLock.Release();
    }

    /// <summary>
    /// Adds a file to the shared files store. Reads the plaintext file from the given path,
    /// computes its SHA-256 hash, signs (filename || hash) with the local RSA key,
    /// encrypts and stores it in the data directory.
    /// </summary>
    public async Task AddFile(string sourcePath, CancellationToken cancellationToken = default)
    {
        var fileName = Path.GetFileName(sourcePath);

        await _indexLock.WaitAsync(cancellationToken);
        try
        {
            if (_sharedFiles.Any(f => f.Name == fileName))
                throw new InvalidOperationException($"A file named '{fileName}' is already shared.");

            var plaintext = await File.ReadAllBytesAsync(sourcePath, cancellationToken);
            var hash = SHA256.HashData(plaintext);

            // Sign: filename UTF-8 bytes || SHA-256 hash bytes (per spec Section 6.3.1)
            var signedData = Encoding.UTF8.GetBytes(fileName).Concat(hash).ToArray();
            using var rsa = RSA.Create();
            rsa.ImportPkcs8PrivateKey(_userConfigProvider.PrivateKey, out _);
            var signature = rsa.SignData(signedData, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

            var ownerFingerprint = _userConfigProvider.GetFingerprint();
            var sharedFile = new SharedFile(fileName, hash, ownerFingerprint, signature);

            // Encrypt and store the file
            var key = await _userConfigProvider.DeriveAesKey(_localFileService, cancellationToken);
            var filePath = Path.Combine(FilesDirName, fileName);
            await _localFileService.WriteEncryptedBytes(filePath, plaintext, key);

            _sharedFiles.Add(sharedFile);
            await SaveIndex(key, cancellationToken);
        }
        finally
        {
            _indexLock.Release();
        }
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

        var key = await _userConfigProvider.DeriveAesKey(_localFileService, cancellationToken);
        var filePath = Path.Combine(FilesDirName, entry.Name);
        return await _localFileService.ReadEncryptedBytes(filePath, key);
    }

    /// <summary>
    /// Stores a file received from a peer. Encrypts the plaintext and saves the metadata.
    /// </summary>
    public async Task ReceiveFile(string fileName, byte[] plaintext, string ownerFingerprint,
        byte[] ownerSignature, CancellationToken cancellationToken = default)
    {
        var hash = SHA256.HashData(plaintext);

        var sharedFile = new SharedFile(fileName, hash, ownerFingerprint, ownerSignature);

        var key = await _userConfigProvider.DeriveAesKey(_localFileService, cancellationToken);
        var filePath = Path.Combine(FilesDirName, fileName);
        await _localFileService.WriteEncryptedBytes(filePath, plaintext, key);

        // Replace if a file with the same name already exists
        await _indexLock.WaitAsync(cancellationToken);
        _sharedFiles.RemoveAll(f => f.Name == fileName);
        _sharedFiles.Add(sharedFile);
        await SaveIndex(key, cancellationToken);
        _indexLock.Release();
    }

    /// <summary>
    /// Removes a file from the shared files store and deletes it from disk.
    /// </summary>
    public async Task RemoveFile(string fileName, CancellationToken cancellationToken = default)
    {
        await _indexLock.WaitAsync(cancellationToken);
        try
        {
            var removed = _sharedFiles.RemoveAll(f => f.Name == fileName);
            if (removed == 0)
                throw new FileNotFoundException($"No shared file named '{fileName}'.");

            var filePath = Path.Combine(FilesDirName, fileName);
            _localFileService.DeleteFile(filePath);

            var key = await _userConfigProvider.DeriveAesKey(_localFileService, cancellationToken);
            await SaveIndex(key, cancellationToken);
        }
        finally
        {
            _indexLock.Release();
        }
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

        await _localFileService.WriteEncryptedBytes(IndexFileName, ms.ToArray(), key);
    }
}