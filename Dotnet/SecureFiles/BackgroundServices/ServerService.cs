using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SecureFiles.Models;
using SecureFiles.Services;

namespace SecureFiles.BackgroundServices;

public class ServerService: BackgroundService
{
    private readonly ILogger<ServerService> _logger;
    private readonly PeerService _peerService;
    
    public ServerService(PeerService peerService,ILogger<ServerService> logger)
    {
        _logger = logger;
        _peerService = peerService;
    }
    
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogDebug("Server is running");
        await _peerService.StartAsync();
        while (!stoppingToken.IsCancellationRequested)
        {
            await Task.Delay(10000, stoppingToken);
        }
    }
}