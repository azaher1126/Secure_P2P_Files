using System.Text;
using SecureFiles.Helpers;

namespace SecureFiles.Models;

public record SharedFile(string Name, byte[] Hash, string OwnerFingerprint, byte[] OwnerSignature)
{
    public MemoryStream PackBinary()
    {
        var result = new MemoryStream();
        using var writer = new BinaryWriter(result, Encoding.UTF8, true);
        writer.Write(Name);
        writer.WriteLengthPrefixedBytes(Hash);
        writer.Write(OwnerFingerprint);
        writer.WriteLengthPrefixedBytes(OwnerSignature);
        return result;
    }

    public static SharedFile UnpackBinary(BinaryReader reader)
    {
        var name = reader.ReadString();
        var hash = reader.ReadLengthPrefixedBytes();
        var ownerFingerprint = reader.ReadString();
        var ownerSignature = reader.ReadLengthPrefixedBytes();
        return new SharedFile(name, hash, ownerFingerprint, ownerSignature);
    }
}