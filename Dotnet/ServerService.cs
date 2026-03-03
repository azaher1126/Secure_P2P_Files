using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace SecureFiles;

public class ServerService: BackgroundService
{
    private readonly ILogger<ServerService> _logger;
    
    public ServerService(ILogger<ServerService> logger)
    {
        _logger = logger;
    }
    
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogDebug("Server is running");
        await Task.Delay(10000, stoppingToken);
    }
}