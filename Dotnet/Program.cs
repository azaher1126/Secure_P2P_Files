using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace SecureFiles;

internal static class Program
{
    static void Main(string[] args)
    {
        HostApplicationBuilder builder = new();

        builder.Services.AddHostedService<ConsoleService>();
        builder.Services.AddHostedService<ServerService>();
        
        var app = builder.Build();
        
        app.Run();
    }
}