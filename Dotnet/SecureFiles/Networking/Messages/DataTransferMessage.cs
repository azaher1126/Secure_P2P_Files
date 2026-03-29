using System.Buffers.Binary;
using System.Text;

namespace SecureFiles.Networking.Messages;

public record DataTransferMessage(string Filename, byte[] FileData)
{
    public byte[] Serialize()
    {
        var filenameBytes = Encoding.UTF8.GetBytes(Filename);
        var result = new byte[4 + filenameBytes.Length + 8 + FileData.Length];
        var offset = 0;

        // Filename_Len (4B BE) + Filename_Str
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(offset, 4), (uint)filenameBytes.Length);
        offset += 4;
        filenameBytes.CopyTo(result.AsSpan(offset));
        offset += filenameBytes.Length;

        // Data_Len (8B BE uint64) + Binary_Data
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(offset, 8), (ulong)FileData.Length);
        offset += 8;
        FileData.CopyTo(result.AsSpan(offset));

        return result;
    }

    public static DataTransferMessage Deserialize(byte[] payload)
    {
        var offset = 0;

        // Filename
        var filenameLen = (int)BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(offset, 4));
        offset += 4;
        var filename = Encoding.UTF8.GetString(payload, offset, filenameLen);
        offset += filenameLen;

        // File data
        var dataLen = (long)BinaryPrimitives.ReadUInt64BigEndian(payload.AsSpan(offset, 8));
        offset += 8;
        var fileData = payload.AsSpan(offset, (int)dataLen).ToArray();

        return new DataTransferMessage(filename, fileData);
    }
}
