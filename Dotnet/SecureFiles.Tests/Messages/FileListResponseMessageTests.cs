using SecureFiles.Models;
using SecureFiles.Networking.Messages;

namespace SecureFiles.Tests.Messages;

public class FileListResponseMessageTests
{
    [Fact]
    public void RoundTrip_EmptyList()
    {
        var original = new FileListResponseMessage([]);
        var deserialized = FileListResponseMessage.Deserialize(original.Serialize());

        Assert.Empty(deserialized.Files);
    }

    [Fact]
    public void RoundTrip_SingleFile()
    {
        var hash = new byte[32];
        Random.Shared.NextBytes(hash);
        var sig = new byte[256];
        Random.Shared.NextBytes(sig);

        var file = new SharedFile("doc.pdf", hash, "abcdef0123456789", sig);
        var original = new FileListResponseMessage([file]);
        var deserialized = FileListResponseMessage.Deserialize(original.Serialize());

        Assert.Single(deserialized.Files);
        Assert.Equal("doc.pdf", deserialized.Files[0].Name);
        Assert.Equal(hash, deserialized.Files[0].Hash);
        Assert.Equal("abcdef0123456789", deserialized.Files[0].OwnerFingerprint);
        Assert.Equal(sig, deserialized.Files[0].OwnerSignature);
    }

    [Fact]
    public void RoundTrip_MultipleFiles()
    {
        var files = Enumerable.Range(0, 5).Select(i =>
        {
            var h = new byte[32];
            Random.Shared.NextBytes(h);
            var s = new byte[256];
            Random.Shared.NextBytes(s);
            return new SharedFile($"file{i}.txt", h, $"fingerprint{i:d16}", s);
        }).ToList();

        var original = new FileListResponseMessage(files);
        var deserialized = FileListResponseMessage.Deserialize(original.Serialize());

        Assert.Equal(5, deserialized.Files.Count);
        for (var i = 0; i < 5; i++)
        {
            Assert.Equal(files[i].Name, deserialized.Files[i].Name);
            Assert.Equal(files[i].Hash, deserialized.Files[i].Hash);
            Assert.Equal(files[i].OwnerFingerprint, deserialized.Files[i].OwnerFingerprint);
            Assert.Equal(files[i].OwnerSignature, deserialized.Files[i].OwnerSignature);
        }
    }
}
