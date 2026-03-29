using System.Buffers.Binary;

namespace SecureFiles.Networking.Messages;

public record KeyMigrationMessage(byte[] NewPublicKeyDer, byte[] ReplayNonce, byte[] OldSignature)
{
    public byte[] Serialize()
    {
        var result = new byte[4 + NewPublicKeyDer.Length + 4 + ReplayNonce.Length + 4 + OldSignature.Length];
        var offset = 0;

        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(offset, 4), (uint)NewPublicKeyDer.Length);
        offset += 4;
        NewPublicKeyDer.CopyTo(result.AsSpan(offset));
        offset += NewPublicKeyDer.Length;

        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(offset, 4), (uint)ReplayNonce.Length);
        offset += 4;
        ReplayNonce.CopyTo(result.AsSpan(offset));
        offset += ReplayNonce.Length;

        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(offset, 4), (uint)OldSignature.Length);
        offset += 4;
        OldSignature.CopyTo(result.AsSpan(offset));

        return result;
    }

    public static KeyMigrationMessage Deserialize(byte[] payload)
    {
        var offset = 0;

        var pubKeyLen = (int)BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(offset, 4));
        offset += 4;
        var newPublicKeyDer = payload.AsSpan(offset, pubKeyLen).ToArray();
        offset += pubKeyLen;

        var nonceLen = (int)BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(offset, 4));
        offset += 4;
        var replayNonce = payload.AsSpan(offset, nonceLen).ToArray();
        offset += nonceLen;

        var sigLen = (int)BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(offset, 4));
        offset += 4;
        var oldSignature = payload.AsSpan(offset, sigLen).ToArray();

        return new KeyMigrationMessage(newPublicKeyDer, replayNonce, oldSignature);
    }
}
