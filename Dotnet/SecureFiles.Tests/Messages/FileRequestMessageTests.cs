using SecureFiles.Networking.Messages;

namespace SecureFiles.Tests.Messages;

public class FileRequestMessageTests
{
    [Fact]
    public void RoundTrip_SimpleFilename()
    {
        var original = new FileRequestMessage("test.txt");
        var deserialized = FileRequestMessage.Deserialize(original.Serialize());
        Assert.Equal(original.Filename, deserialized.Filename);
    }

    [Fact]
    public void RoundTrip_UnicodeFilename()
    {
        var original = new FileRequestMessage("文件.txt");
        var deserialized = FileRequestMessage.Deserialize(original.Serialize());
        Assert.Equal(original.Filename, deserialized.Filename);
    }

    [Fact]
    public void RoundTrip_EmptyFilename()
    {
        var original = new FileRequestMessage("");
        var deserialized = FileRequestMessage.Deserialize(original.Serialize());
        Assert.Equal("", deserialized.Filename);
    }

    [Fact]
    public void Serialize_BigEndianLengthPrefix()
    {
        var msg = new FileRequestMessage("AB");
        var bytes = msg.Serialize();

        // 4-byte BE length prefix = 2, then "AB"
        Assert.Equal(6, bytes.Length);
        Assert.Equal(0, bytes[0]);
        Assert.Equal(0, bytes[1]);
        Assert.Equal(0, bytes[2]);
        Assert.Equal(2, bytes[3]);
        Assert.Equal((byte)'A', bytes[4]);
        Assert.Equal((byte)'B', bytes[5]);
    }
}
