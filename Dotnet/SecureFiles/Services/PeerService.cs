using System.Collections.Concurrent;
using System.Net.NetworkInformation;
using Makaretu.Dns;
using Microsoft.Extensions.Logging;
using SecureFiles.Models;

namespace SecureFiles.Services;

public class PeerService : IAsyncDisposable
{
    private const string ServiceName = "_securep2pfiles._tcp";

    private static readonly IEnumerable<NetworkInterfaceType> ExcludedInterfaces =
        [NetworkInterfaceType.Loopback, NetworkInterfaceType.Tunnel];

    private ServiceProfile? _serviceProfile;

    private ServiceDiscovery? _serviceDiscovery;
    private MulticastService? _multicastService;

    private readonly ILogger<PeerService> _logger;
    private readonly ILoggerFactory _loggerFactory;
    private readonly UserConfigProvider _userConfigProvider;

    private readonly ConcurrentDictionary<string, Peer> _peers = new();

    public PeerService(UserConfigProvider userConfigProvider, ILoggerFactory loggerFactory)
    {
        _loggerFactory = loggerFactory;
        _logger = _loggerFactory.CreateLogger<PeerService>();
        _userConfigProvider = userConfigProvider;
    }

    public async Task StartAsync(ushort port, CancellationToken cancellationToken = default)
    {
        if (_serviceDiscovery != null)
        {
            return;
        }

        _multicastService =
            new MulticastService(
                interfaces => interfaces.Where(i => !ExcludedInterfaces.Contains(i.NetworkInterfaceType)),
                _loggerFactory);
        await _multicastService.Start(cancellationToken);
        _serviceDiscovery = await ServiceDiscovery.CreateInstance(_multicastService, _loggerFactory, cancellationToken);

        await StartAdvertising(port);

        _serviceDiscovery.ServiceInstanceDiscovered = OnServiceDiscovered;
        _serviceDiscovery.ServiceInstanceShutdown = OnServiceShutdown;

        await _serviceDiscovery.QueryServiceInstances(ServiceName);
    }

    public ICollection<Peer> GetPeers()
    {
        return _peers.Values;
    }

    private ServiceProfile GetServiceProfile(ushort port, uint instanceNumber = 0)
    {
        var instanceName = _userConfigProvider.GetFingerprint();
        if (instanceNumber > 0)
        {
            instanceName += "-" + instanceNumber;
        }

        var serviceProfile = new ServiceProfile(instanceName, ServiceName, port);
        serviceProfile.AddProperty("name", _userConfigProvider.Username);
        return serviceProfile;
    }

    private async Task StartAdvertising(ushort port)
    {
        if (_serviceDiscovery == null)
        {
            throw new InvalidOperationException("Service discovery is not initialized");
        }

        uint currentCounter = 0;
        do
        {
            _serviceProfile = GetServiceProfile(port, currentCounter);
            currentCounter++;
        } while (await _serviceDiscovery.Probe(_serviceProfile));

        _serviceDiscovery.Advertise(_serviceProfile);
        _logger.LogDebug("Started advertising service {instanceName} for {port}", _serviceProfile.InstanceName, port);
    }

    private Task OnServiceDiscovered(ServiceInstanceDiscoveryEventArgs e)
    {
        if (_serviceProfile == null
            || e.ServiceInstanceName == null
            || e.ServiceInstanceName == _serviceProfile.FullyQualifiedName
            || !e.ServiceInstanceName.BelongsTo($"{ServiceName}.local")
            || _peers.ContainsKey(e.ServiceInstanceName.Labels[0]))
        {
            return Task.CompletedTask;
        }

        string serviceInstance = e.ServiceInstanceName.Labels[0];
        string? friendlyName = e.Message.AdditionalRecords.OfType<TXTRecord>().FirstOrDefault()
            ?.Strings.FirstOrDefault(s => s.StartsWith("name="))?.Split('=', 2)[1];
        
        var serviceRecord = e.Message.AdditionalRecords.OfType<SRVRecord>().First();
        var dnsRecord = e.Message.AdditionalRecords.OfType<ARecord>().FirstOrDefault(r => r.Name == serviceRecord.Target);
        
        var address = dnsRecord?.Address ?? e.RemoteEndPoint.Address;
        _peers[serviceInstance] = new Peer(friendlyName, serviceInstance, address.ToString(),
            serviceRecord.Port);

        _logger.LogDebug("Discovered service instance: {FriendlyName}/{InstanceName}",
            friendlyName,
            serviceInstance);

        return Task.CompletedTask;
    }

    private Task OnServiceShutdown(ServiceInstanceShutdownEventArgs e)
    {
        if (_serviceProfile == null
            || e.ServiceInstanceName == null
            || e.ServiceInstanceName == _serviceProfile.FullyQualifiedName
            || !e.ServiceInstanceName.BelongsTo($"{ServiceName}.local")
            || !_peers.ContainsKey(e.ServiceInstanceName.Labels[0]))
        {
            return Task.CompletedTask;
        }

        string serviceInstance = e.ServiceInstanceName.Labels[0];
        _peers.TryRemove(serviceInstance, out _);
        _logger.LogDebug("Service instance shutdown: {InstanceName}", serviceInstance);

        return Task.CompletedTask;
    }

    public async Task ReAdvertiseAsync()
    {
        if (_serviceDiscovery == null || _serviceProfile == null)
        {
            _logger.LogWarning("Cannot re-advertise: service discovery not initialized");
            return;
        }

        var port = _serviceProfile.Resources.OfType<SRVRecord>().First().Port;
        await _serviceDiscovery.Unadvertise(_serviceProfile);
        _logger.LogDebug("Unadvertised old profile {InstanceName}", _serviceProfile.InstanceName);

        await StartAdvertising(port);
        _logger.LogInformation("Re-advertised with new fingerprint {Fingerprint}", _userConfigProvider.GetFingerprint());
    }

    public async ValueTask DisposeAsync()
    {
        if (_serviceDiscovery != null)
        {
            _serviceDiscovery.ServiceInstanceDiscovered = null;
            _serviceDiscovery.ServiceInstanceShutdown = null;

            if (_serviceProfile != null)
            {
                await _serviceDiscovery.Unadvertise(_serviceProfile);
                if (_logger.IsEnabled(LogLevel.Debug))
                {
                    _logger.LogDebug("Stopped advertising service {instanceName}", _serviceProfile.InstanceName);
                }

                _serviceProfile = null;
            }

            _serviceDiscovery.Dispose();
            _serviceDiscovery = null;
        }

        if (_multicastService != null)
        {
            _multicastService.Dispose();
            _multicastService = null;
        }

        GC.SuppressFinalize(this);
    }
}