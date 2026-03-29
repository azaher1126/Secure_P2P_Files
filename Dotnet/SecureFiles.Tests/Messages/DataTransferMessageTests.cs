using SecureFiles.Networking.Messages;

namespace SecureFiles.Tests.Messages;

public class DataTransferMessageTests
{
    [Fact]
    public void RoundTrip_SmallFile()
    {
        var data = new byte[] { 0xCA, 0xFE, 0xBA, 0xBE };
        var original = new DataTransferMessage("test.bin", data);
        var deserialized = DataTransferMessage.Deserialize(original.Serialize());

        Assert.Equal("test.bin", deserialized.Filename);
        Assert.Equal(data, deserialized.FileData);
    }

    [Fact]
    public void RoundTrip_EmptyFile()
    {
        var original = new DataTransferMessage("empty.txt", []);
        var deserialized = DataTransferMessage.Deserialize(original.Serialize());

        Assert.Equal("empty.txt", deserialized.Filename);
        Assert.Empty(deserialized.FileData);
    }

    [Fact]
    public void RoundTrip_LargeFile()
    {
        var data = new byte[100_000];
        Random.Shared.NextBytes(data);
        var original = new DataTransferMessage("big.dat", data);
        var deserialized = DataTransferMessage.Deserialize(original.Serialize());

        Assert.Equal(data, deserialized.FileData);
    }

    [Fact]
    public void Serialize_DataLengthIs8BytesBigEndian()
    {
        var data = new byte[3];
        var msg = new DataTransferMessage("a", data);
        var bytes = msg.Serialize();

        // After filename: 4B name_len + 1B name = 5 bytes, then 8B data_len
        var dataLenOffset = 4 + 1;
        var dataLen = BitConverter.ToUInt64(bytes.AsSpan(dataLenOffset, 8).ToArray().Reverse().ToArray());
        Assert.Equal(3UL, dataLen);
    }
}
