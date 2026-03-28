using System.Buffers.Binary;

namespace SecureFiles.Helpers;

public static class BigEndianHelper
{
    public static async Task WriteUInt32BigEndian(Stream stream, uint value, CancellationToken ct = default)
    {
        var buffer = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(buffer, value);
        await stream.WriteAsync(buffer, ct);
    }

    public static async Task<uint> ReadUInt32BigEndian(Stream stream, CancellationToken ct = default)
    {
        var buffer = new byte[4];
        await stream.ReadExactlyAsync(buffer, ct);
        return BinaryPrimitives.ReadUInt32BigEndian(buffer);
    }

    public static async Task WriteUInt64BigEndian(Stream stream, ulong value, CancellationToken ct = default)
    {
        var buffer = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(buffer, value);
        await stream.WriteAsync(buffer, ct);
    }

    public static async Task<ulong> ReadUInt64BigEndian(Stream stream, CancellationToken ct = default)
    {
        var buffer = new byte[8];
        await stream.ReadExactlyAsync(buffer, ct);
        return BinaryPrimitives.ReadUInt64BigEndian(buffer);
    }

    public static async Task WriteLengthPrefixed(Stream stream, byte[] data, CancellationToken ct = default)
    {
        await WriteUInt32BigEndian(stream, (uint)data.Length, ct);
        await stream.WriteAsync(data, ct);
    }

    public static async Task<byte[]> ReadLengthPrefixed(Stream stream, CancellationToken ct = default)
    {
        var length = await ReadUInt32BigEndian(stream, ct);
        var buffer = new byte[length];
        await stream.ReadExactlyAsync(buffer, ct);
        return buffer;
    }
}
