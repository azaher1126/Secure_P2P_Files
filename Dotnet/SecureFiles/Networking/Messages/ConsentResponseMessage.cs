using System.Buffers.Binary;
using System.Text;

namespace SecureFiles.Networking.Messages;

public record ConsentResponseMessage(bool Accepted, string Filename)
{
    private const byte StatusAccept = 0x01;
    private const byte StatusDeny = 0x02;

    public byte[] Serialize()
    {
        var filenameBytes = Encoding.UTF8.GetBytes(Filename);
        var result = new byte[1 + 4 + filenameBytes.Length];

        result[0] = Accepted ? StatusAccept : StatusDeny;
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(1, 4), (uint)filenameBytes.Length);
        filenameBytes.CopyTo(result.AsSpan(5));

        return result;
    }

    public static ConsentResponseMessage Deserialize(byte[] payload)
    {
        var accepted = payload[0] == StatusAccept;
        var filenameLen = (int)BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(1, 4));
        var filename = Encoding.UTF8.GetString(payload, 5, filenameLen);

        return new ConsentResponseMessage(accepted, filename);
    }
}
