using System.Collections.Concurrent;
using Makaretu.Dns;
using Microsoft.Extensions.Logging;
using SecureFiles.Models;

namespace SecureFiles.Services;

public class PeerService : IAsyncDisposable
{
    private const string ServiceName = "_secure_p2p_files._tcp";

    private readonly AdvertisePeer _advertisePeer;
    private ServiceProfile _serviceProfile;

    private ServiceDiscovery? _serviceDiscovery;

    private readonly ILogger<PeerService> _logger;

    private readonly ConcurrentDictionary<string, Peer> _peers = new();

    public PeerService(AdvertisePeer advertisePeer, ILogger<PeerService> logger)
    {
        _logger = logger;

        _advertisePeer = advertisePeer;
        _serviceProfile = GetServiceProfile(advertisePeer);
    }

    public async Task StartAsync()
    {
        if (_serviceDiscovery != null)
        {
            return;
        }

        _serviceDiscovery = await ServiceDiscovery.CreateInstance();

        await StartAdvertising();

        _serviceDiscovery.ServiceInstanceDiscovered = OnServiceDiscovered;
        _serviceDiscovery.ServiceInstanceShutdown = OnServiceShutdown;

        await _serviceDiscovery.QueryServiceInstances(ServiceName);
    }
    
    public ICollection<Peer> GetPeers()
    {
        return _peers.Values;
    }

    private ServiceProfile GetServiceProfile(AdvertisePeer advertisePeer, uint instanceNumber = 0)
    {
        var instanceName = advertisePeer.InstanceName;
        if (instanceNumber > 0)
        {
            instanceName += "-" + instanceNumber;
        }

        var serviceProfile = new ServiceProfile(instanceName, ServiceName, advertisePeer.Port);
        serviceProfile.AddProperty("Friendly_User_Name", advertisePeer.FriendlyName);
        return serviceProfile;
    }

    private async Task StartAdvertising()
    {
        if (_serviceDiscovery == null)
        {
            throw new InvalidOperationException("Service discovery is not initialized");
        }

        uint currentCounter = 0;
        while (await _serviceDiscovery.Probe(_serviceProfile))
        {
            currentCounter++;
            _serviceProfile = GetServiceProfile(_advertisePeer, currentCounter);
        }

        _serviceDiscovery.Advertise(_serviceProfile);
        _logger.LogDebug("Started advertising service {instanceName} for {port}", _serviceProfile.InstanceName,
            _advertisePeer.Port);
    }

    private Task OnServiceDiscovered(ServiceInstanceDiscoveryEventArgs e)
    {
        if (e.ServiceInstanceName == null
            || e.ServiceInstanceName == _serviceProfile.FullyQualifiedName
            || !e.ServiceInstanceName.BelongsTo($"{ServiceName}.local"))
        {
            return Task.CompletedTask;
        }

        string? friendlyName =
            e.Message.AdditionalRecords.OfType<TXTRecord>().FirstOrDefault()?.Strings[1].Split('=', 2)[1];
        string serviceInstance = e.ServiceInstanceName.Labels[0];
        _peers[serviceInstance] = new Peer(friendlyName, serviceInstance, e.RemoteEndPoint.Address.ToString(),
            e.RemoteEndPoint.Port);

        _logger.LogDebug("Discovered service instance: {FriendlyName}/{InstanceName} at {Host}:{Port}",
            friendlyName,
            serviceInstance,
            e.RemoteEndPoint.Address,
            e.RemoteEndPoint.Port);

        return Task.CompletedTask;
    }

    private Task OnServiceShutdown(ServiceInstanceShutdownEventArgs e)
    {
        if (e.ServiceInstanceName == null
            || e.ServiceInstanceName == _serviceProfile.FullyQualifiedName
            || !e.ServiceInstanceName.BelongsTo($"{ServiceName}.local"))
        {
            return Task.CompletedTask;
        }
        
        string serviceInstance = e.ServiceInstanceName.Labels[0];
        _peers.TryRemove(serviceInstance, out _);
        _logger.LogDebug("Service instance shutdown: {InstanceName} at {Host}:{Port}", serviceInstance,
            e.RemoteEndPoint.Address,
            e.RemoteEndPoint.Port);

        return Task.CompletedTask;
    }

    public async ValueTask DisposeAsync()
    {
        if (_serviceDiscovery != null)
        {
            _serviceDiscovery.ServiceInstanceDiscovered = null;
            _serviceDiscovery.ServiceInstanceShutdown = null;

            await _serviceDiscovery.Unadvertise(_serviceProfile);
            if (_logger.IsEnabled(LogLevel.Debug))
            {
                _logger.LogDebug("Stopped advertising service {instanceName} for {port}", _serviceProfile.InstanceName,
                    _advertisePeer.Port);
            }
            _serviceDiscovery.Dispose();
            _serviceDiscovery = null;
        }

        GC.SuppressFinalize(this);
    }
}