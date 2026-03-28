namespace SecureFiles.Console;

public enum ConsentRequestType
{
    ReceiveFile,
    SendFile
}

public class ConsentRequest
{
    public required ConsentRequestType Type { get; init; }
    public required string PeerName { get; init; }
    public required string FileName { get; init; }
    public TaskCompletionSource<bool> Response { get; } = new();
}
