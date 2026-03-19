namespace SecureFiles.Models;

public record Peer(string? FriendlyName, string InstanceName, string Address, int Port);

public record AdvertisePeer(string FriendlyName, string InstanceName, ushort Port);