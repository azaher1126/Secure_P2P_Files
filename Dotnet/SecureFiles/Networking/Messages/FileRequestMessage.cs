using System.Buffers.Binary;
using System.Text;

namespace SecureFiles.Networking.Messages;

public record FileRequestMessage(string Filename)
{
    public byte[] Serialize()
    {
        var filenameBytes = Encoding.UTF8.GetBytes(Filename);
        var result = new byte[4 + filenameBytes.Length];

        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(0, 4), (uint)filenameBytes.Length);
        filenameBytes.CopyTo(result.AsSpan(4));

        return result;
    }

    public static FileRequestMessage Deserialize(byte[] payload)
    {
        var filenameLen = (int)BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(0, 4));
        var filename = Encoding.UTF8.GetString(payload, 4, filenameLen);

        return new FileRequestMessage(filename);
    }
}
