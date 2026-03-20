using System.CommandLine;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SecureFiles.Services;
using SecureFiles.BackgroundServices;

namespace SecureFiles;

internal static class Program
{
    static async Task<int> Main(string[] args)
    {
        var parsedArgs = CreateCliParser().Parse(args);
        if (parsedArgs.Action != null)
        {
            return await parsedArgs.InvokeAsync();
        }

        HostApplicationBuilder builder = new(new HostApplicationBuilderSettings
        {
            ContentRootPath = AppContext.BaseDirectory
        });

        builder.Services.AddSingleton<UserConfigService>(
            x => new UserConfigService(x.GetRequiredService<LocalFileService>(),
                parsedArgs.GetValue<string?>("--data-directory"),
                parsedArgs.GetValue<string?>("--password")));
        builder.Services.AddSingleton<LocalFileService>();
        builder.Services.AddSingleton<SharedFileService>();
        builder.Services.AddSingleton<PeerService>();

        builder.Services.AddHostedService<ConsoleService>();
        builder.Services.AddHostedService<ServerService>();

        using var app = builder.Build();
        
        var userConfigService = app.Services.GetRequiredService<UserConfigService>();
        if (!await userConfigService.LoadOrInitialize())
        {
            return 1;
        }

        var sharedFileService = app.Services.GetRequiredService<SharedFileService>();
        await sharedFileService.LoadIndex();

        await app.RunAsync();

        return 0;
    }

    private static RootCommand CreateCliParser()
    {
        Option<string> passwordOption = new("--password")
        {
            Description = "Password used to encrypt all local data. This include files and metadata."
        };
        Option<string> dataDirectoryOption = new("--data-directory")
        {
            Description = "Directory where all local data is stored. This include files and metadata."
        };
        RootCommand rootCommand = new("Secure local Peer-to-Peer file sharing application")
        {
            passwordOption,
            dataDirectoryOption
        };

        return rootCommand;
    }
}
