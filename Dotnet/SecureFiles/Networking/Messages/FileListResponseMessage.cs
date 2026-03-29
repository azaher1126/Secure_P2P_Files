using System.Buffers.Binary;
using System.Text;
using SecureFiles.Models;

namespace SecureFiles.Networking.Messages;

public record FileListResponseMessage(IReadOnlyList<SharedFile> Files)
{
    public byte[] Serialize()
    {
        using var ms = new MemoryStream();

        // File_Count (4B BE)
        WriteUInt32(ms, (uint)Files.Count);

        foreach (var file in Files)
        {
            var nameBytes = Encoding.UTF8.GetBytes(file.Name);
            var fingerprintBytes = Encoding.UTF8.GetBytes(file.OwnerFingerprint);

            // Name_Len (4B BE) + Name_Str
            WriteUInt32(ms, (uint)nameBytes.Length);
            ms.Write(nameBytes);

            // Hash_Len (4B BE) + SHA256_Hash (32B)
            WriteUInt32(ms, (uint)file.Hash.Length);
            ms.Write(file.Hash);

            // Fingerprint_Len (4B BE) + Owner_Fingerprint_Hex
            WriteUInt32(ms, (uint)fingerprintBytes.Length);
            ms.Write(fingerprintBytes);

            // Sig_Len (4B BE) + Owner_RSA_Signature
            WriteUInt32(ms, (uint)file.OwnerSignature.Length);
            ms.Write(file.OwnerSignature);
        }

        return ms.ToArray();
    }

    public static FileListResponseMessage Deserialize(byte[] payload)
    {
        var offset = 0;

        var fileCount = ReadUInt32(payload, ref offset);
        var files = new List<SharedFile>((int)fileCount);

        for (var i = 0; i < fileCount; i++)
        {
            var nameBytes = ReadLengthPrefixed(payload, ref offset);
            var name = Encoding.UTF8.GetString(nameBytes);

            var hash = ReadLengthPrefixed(payload, ref offset);

            var fingerprintBytes = ReadLengthPrefixed(payload, ref offset);
            var fingerprint = Encoding.UTF8.GetString(fingerprintBytes);

            var signature = ReadLengthPrefixed(payload, ref offset);

            files.Add(new SharedFile(name, hash, fingerprint, signature));
        }

        return new FileListResponseMessage(files);
    }

    private static void WriteUInt32(Stream stream, uint value)
    {
        Span<byte> buffer = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(buffer, value);
        stream.Write(buffer);
    }

    private static uint ReadUInt32(byte[] data, ref int offset)
    {
        var value = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(offset, 4));
        offset += 4;
        return value;
    }

    private static byte[] ReadLengthPrefixed(byte[] data, ref int offset)
    {
        var length = (int)ReadUInt32(data, ref offset);
        var result = data.AsSpan(offset, length).ToArray();
        offset += length;
        return result;
    }
}
