using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace SecureFiles;

public class ConsoleService: BackgroundService
{
    private readonly ILogger<ConsoleService> _logger;
    private readonly IHostApplicationLifetime _appLifetime;
    
    public ConsoleService(ILogger<ConsoleService> logger, IHostApplicationLifetime appLifetime)
    {
        _logger = logger;
        _appLifetime = appLifetime;
    }
    
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Delay(3000, stoppingToken);
        _appLifetime.StopApplication();
    }
}