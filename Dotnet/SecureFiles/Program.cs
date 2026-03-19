using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SecureFiles.Models;
using SecureFiles.Services;
using SecureFiles.BackgroundServices;

namespace SecureFiles;

internal static class Program
{
    static async Task Main(string[] args)
    {
        HostApplicationBuilder builder = new();
        
        var advertisePeer = new AdvertisePeer(
            FriendlyName: "Alice's=Laptop",
            InstanceName: "alice-laptop",
            Port: 12345
        );
        
        builder.Services.AddSingleton<PeerService>(x => new PeerService(advertisePeer, x.GetRequiredService<ILogger<PeerService>>()));

        builder.Services.AddHostedService<ConsoleService>();
        builder.Services.AddHostedService<ServerService>();
        
        var app = builder.Build();
        
        await app.RunAsync();
    }
}