using SecureFiles.Networking.Messages;

namespace SecureFiles.Tests.Messages;

public class ConsentResponseMessageTests
{
    [Fact]
    public void RoundTrip_Accepted()
    {
        var original = new ConsentResponseMessage(true, "file.txt");
        var deserialized = ConsentResponseMessage.Deserialize(original.Serialize());

        Assert.True(deserialized.Accepted);
        Assert.Equal("file.txt", deserialized.Filename);
    }

    [Fact]
    public void RoundTrip_Denied()
    {
        var original = new ConsentResponseMessage(false, "file.txt");
        var deserialized = ConsentResponseMessage.Deserialize(original.Serialize());

        Assert.False(deserialized.Accepted);
        Assert.Equal("file.txt", deserialized.Filename);
    }

    [Fact]
    public void Serialize_AcceptByte_Is0x01()
    {
        var msg = new ConsentResponseMessage(true, "x");
        var bytes = msg.Serialize();
        Assert.Equal(0x01, bytes[0]);
    }

    [Fact]
    public void Serialize_DenyByte_Is0x02()
    {
        var msg = new ConsentResponseMessage(false, "x");
        var bytes = msg.Serialize();
        Assert.Equal(0x02, bytes[0]);
    }
}
