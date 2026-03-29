using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging.Abstractions;
using SecureFiles.Networking;

namespace SecureFiles.Tests;

public class MessageFramerTests : IDisposable
{
    private readonly MessageFramer _framer = new(NullLogger<MessageFramer>.Instance);
    private readonly List<IDisposable> _disposables = [];

    public void Dispose()
    {
        foreach (var d in _disposables)
            d.Dispose();
    }

    private (Session sender, Session receiver) CreateLoopbackSessionPair()
    {
        var sessionKey = RandomNumberGenerator.GetBytes(32);

        using var rsa = RSA.Create(2048);
        var pubKeyDer = rsa.ExportSubjectPublicKeyInfo();

        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var clientA = new TcpClient();
        clientA.Connect(IPAddress.Loopback, port);
        var clientB = listener.AcceptTcpClient();
        listener.Stop();

        var rsaA = RSA.Create();
        rsaA.ImportSubjectPublicKeyInfo(pubKeyDer, out _);
        var rsaB = RSA.Create();
        rsaB.ImportSubjectPublicKeyInfo(pubKeyDer, out _);

        var sender = new Session(sessionKey, rsaA, "sender-fp", clientA);
        var receiver = new Session((byte[])sessionKey.Clone(), rsaB, "receiver-fp", clientB);

        _disposables.Add(sender);
        _disposables.Add(receiver);

        return (sender, receiver);
    }

    [Fact]
    public async Task RoundTrip_SmallPayload()
    {
        var payload = new byte[] { 1, 2, 3, 4, 5 };
        var (sender, receiver) = CreateLoopbackSessionPair();

        await _framer.SendMessage(sender, MessageType.GetFileList, payload);
        var (type, received) = await _framer.ReceiveMessage(receiver);

        Assert.Equal(MessageType.GetFileList, type);
        Assert.Equal(payload, received);
    }

    [Fact]
    public async Task RoundTrip_EmptyPayload()
    {
        var (sender, receiver) = CreateLoopbackSessionPair();

        await _framer.SendMessage(sender, MessageType.FileListResponse, []);
        var (type, received) = await _framer.ReceiveMessage(receiver);

        Assert.Equal(MessageType.FileListResponse, type);
        Assert.Empty(received);
    }

    [Fact]
    public async Task RoundTrip_LargePayload()
    {
        var payload = new byte[50_000];
        Random.Shared.NextBytes(payload);
        var (sender, receiver) = CreateLoopbackSessionPair();

        await _framer.SendMessage(sender, MessageType.DataTransfer, payload);
        var (_, received) = await _framer.ReceiveMessage(receiver);

        Assert.Equal(payload, received);
    }

    [Fact]
    public async Task TamperedCiphertext_ThrowsCryptographicException()
    {
        var payload = new byte[] { 1, 2, 3 };
        var (sender, receiver) = CreateLoopbackSessionPair();

        await _framer.SendMessage(sender, MessageType.GetFileList, payload);

        // Read the raw bytes from receiver stream and tamper
        var stream = receiver.Stream;
        var rawData = new byte[1 + 4 + 12 + payload.Length + 16];
        await stream.ReadExactlyAsync(rawData);

        // Tamper with ciphertext (after 1B type + 4B len + 12B nonce = offset 17)
        rawData[17] ^= 0xFF;

        // Create a new loopback pair to send tampered data
        var (tamperSender, tamperReceiver) = CreateLoopbackSessionPair();
        // Overwrite tamperReceiver's session key with the original
        var receiverWithSameKey = new Session(
            (byte[])sender.SessionKey.Clone(),
            RSA.Create(2048),
            "fp",
            tamperReceiver.TcpClient);
        _disposables.Add(receiverWithSameKey);

        await tamperSender.Stream.WriteAsync(rawData);
        await tamperSender.Stream.FlushAsync();

        await Assert.ThrowsAsync<CryptographicException>(
            () => _framer.ReceiveMessage(receiverWithSameKey));
    }

    [Fact]
    public async Task WrongSessionKey_ThrowsCryptographicException()
    {
        var payload = new byte[] { 10, 20, 30 };
        var (sender, receiver) = CreateLoopbackSessionPair();

        await _framer.SendMessage(sender, MessageType.GetFileList, payload);

        // Create receiver with wrong key
        var wrongKey = RandomNumberGenerator.GetBytes(32);
        var wrongSession = new Session(
            wrongKey,
            RSA.Create(2048),
            "wrong-fp",
            receiver.TcpClient);
        _disposables.Add(wrongSession);

        await Assert.ThrowsAsync<CryptographicException>(
            () => _framer.ReceiveMessage(wrongSession));
    }

    [Fact]
    public async Task AllMessageTypes_PreservedInWireFormat()
    {
        foreach (var msgType in Enum.GetValues<MessageType>())
        {
            var (sender, receiver) = CreateLoopbackSessionPair();

            await _framer.SendMessage(sender, msgType, [0x42]);
            var (receivedType, _) = await _framer.ReceiveMessage(receiver);

            Assert.Equal(msgType, receivedType);
        }
    }
}
