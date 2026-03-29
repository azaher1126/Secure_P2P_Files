using System.Text;
using SecureFiles.Helpers;
using SecureFiles.Models;

namespace SecureFiles.Services;

public class ContactStore
{
    private const string ContactsFileName = "contacts";

    private readonly LocalFileService _localFileService;
    private readonly UserConfigProvider _userConfigProvider;

    private readonly List<Contact> _contacts = [];
    private readonly SemaphoreSlim _contactsLock = new(1, 1);

    public ContactStore(LocalFileService localFileService, UserConfigProvider userConfigProvider)
    {
        _localFileService = localFileService;
        _userConfigProvider = userConfigProvider;
    }

    public async Task LoadAsync(CancellationToken cancellationToken = default)
    {
        if (!_localFileService.FileExists(ContactsFileName))
            return;

        var key = await _userConfigProvider.DeriveAesKey(_localFileService, cancellationToken);
        var data = await _localFileService.ReadEncryptedBytes(ContactsFileName, key);

        using var reader = new BinaryReader(new MemoryStream(data), Encoding.UTF8);
        var count = reader.ReadInt32();
        await _contactsLock.WaitAsync(cancellationToken);
        try
        {
            _contacts.Clear();
            for (var i = 0; i < count; i++)
            {
                var fingerprint = reader.ReadString();
                var publicKeyDer = reader.ReadLengthPrefixedBytes();
                var fileCount = reader.ReadInt32();
                var files = new List<SharedFile>(fileCount);
                for (var j = 0; j < fileCount; j++)
                {
                    files.Add(SharedFile.UnpackBinary(reader));
                }

                _contacts.Add(new Contact(fingerprint, publicKeyDer, files));
            }
        }
        finally
        {
            _contactsLock.Release();
        }
    }

    public async Task SaveContactAsync(string fingerprint, byte[] publicKeyDer, CancellationToken cancellationToken = default)
    {
        await _contactsLock.WaitAsync(cancellationToken);
        try
        {
            var existing = _contacts.FindIndex(c => c.Fingerprint == fingerprint);
            if (existing >= 0)
            {
                // Update public key, preserve cached files
                _contacts[existing] = _contacts[existing] with { PublicKeyDer = publicKeyDer };
            }
            else
            {
                _contacts.Add(new Contact(fingerprint, publicKeyDer, []));
            }

            await SaveAsync(cancellationToken);
        }
        finally
        {
            _contactsLock.Release();
        }
    }

    public Contact? GetContact(string fingerprint) =>
        _contacts.FirstOrDefault(c => c.Fingerprint == fingerprint);

    public byte[]? GetPublicKey(string fingerprint) =>
        GetContact(fingerprint)?.PublicKeyDer;

    public async Task CacheFileListAsync(string fingerprint, IReadOnlyList<SharedFile> files, CancellationToken cancellationToken = default)
    {
        await _contactsLock.WaitAsync(cancellationToken);
        try
        {
            var existing = _contacts.FindIndex(c => c.Fingerprint == fingerprint);
            if (existing >= 0)
            {
                _contacts[existing] = _contacts[existing] with { CachedFiles = files.ToList() };
            }
            else
            {
                _contacts.Add(new Contact(fingerprint, [], files.ToList()));
            }

            await SaveAsync(cancellationToken);
        }
        finally
        {
            _contactsLock.Release();
        }
    }

    public IReadOnlyList<SharedFile>? GetCachedFileList(string fingerprint) =>
        GetContact(fingerprint)?.CachedFiles;

    public IReadOnlyList<Contact> ListContacts() => _contacts.ToList();

    private async Task SaveAsync(CancellationToken cancellationToken = default)
    {
        using var ms = new MemoryStream();
        using (var writer = new BinaryWriter(ms, Encoding.UTF8, true))
        {
            writer.Write(_contacts.Count);
            foreach (var contact in _contacts)
            {
                writer.Write(contact.Fingerprint);
                writer.WriteLengthPrefixedBytes(contact.PublicKeyDer);
                writer.Write(contact.CachedFiles.Count);
                foreach (var file in contact.CachedFiles)
                {
                    var packed = file.PackBinary();
                    packed.Position = 0;
                    await packed.CopyToAsync(ms, cancellationToken);
                }
            }
        }

        var key = await _userConfigProvider.DeriveAesKey(_localFileService, cancellationToken);
        await _localFileService.WriteEncryptedBytes(ContactsFileName, ms.ToArray(), key);
    }
}
