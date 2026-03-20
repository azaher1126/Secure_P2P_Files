using System.CommandLine;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NReco.Logging.File;
using SecureFiles.Services;
using SecureFiles.BackgroundServices;
using SecureFiles.Console;

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
        
        var localFileService = new LocalFileService(
            parsedArgs.GetValue<string?>("--data-directory"));
        
        var loader = new UserConfigLoader(
            localFileService,
            parsedArgs.GetValue<string?>("--password"));

        var userConfigProvider = await loader.LoadOrInitialize();
        if (userConfigProvider is null)
            return 1;

        HostApplicationBuilder builder = new(new HostApplicationBuilderSettings
        {
            ContentRootPath = AppContext.BaseDirectory
        });

        builder.Logging.ClearProviders();
        builder.Logging.AddFile(localFileService.GetLogFilePath());

        builder.Services.AddSingleton(localFileService);
        builder.Services.AddSingleton(userConfigProvider);
        builder.Services.AddSingleton<SharedFileService>();
        builder.Services.AddSingleton<PeerService>();

        builder.Services.AddHostedService<ConsoleService>();
        builder.Services.AddHostedService<ServerService>();

        using var app = builder.Build();

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
