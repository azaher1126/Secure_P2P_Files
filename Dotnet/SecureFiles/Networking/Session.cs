using System.Net.Sockets;
using System.Security.Cryptography;

namespace SecureFiles.Networking;

public class Session : IDisposable
{
    private static readonly TimeSpan SessionTimeout = TimeSpan.FromMinutes(5);

    public byte[] SessionKey { get; }
    public RSA PeerPublicKey { get; }
    public string PeerFingerprint { get; }
    public DateTime ExpiresAt { get; }
    public TcpClient TcpClient { get; }
    public NetworkStream Stream { get; }

    public bool IsExpired => DateTime.UtcNow >= ExpiresAt;

    public Session(byte[] sessionKey, RSA peerPublicKey, string peerFingerprint, TcpClient tcpClient)
    {
        SessionKey = sessionKey;
        PeerPublicKey = peerPublicKey;
        PeerFingerprint = peerFingerprint;
        ExpiresAt = DateTime.UtcNow.Add(SessionTimeout);
        TcpClient = tcpClient;
        Stream = tcpClient.GetStream();
    }

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(SessionKey);
        Stream.Dispose();
        TcpClient.Dispose();
        PeerPublicKey.Dispose();
    }
}
