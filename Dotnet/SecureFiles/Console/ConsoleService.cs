using Microsoft.Extensions.Hosting;
using Terminal.Gui.App;
using Terminal.Gui.Configuration;
using Terminal.Gui.Input;

namespace SecureFiles.Console;

public class ConsoleService: BackgroundService
{
    private readonly MainWindow _mainWindow;

    private readonly IApplication _application;
    private readonly IHostApplicationLifetime _appLifetime;

    public ConsoleService(MainWindow mainWindow, IHostApplicationLifetime appLifetime)
    {
        _mainWindow = mainWindow;
        _appLifetime = appLifetime;

        ConfigurationManager.RuntimeConfig = """{ "Theme": "8-Bit" }""";
        ConfigurationManager.Enable(ConfigLocations.All);
        _application = Application.Create().Init();
        _application.Keyboard.KeyBindings.Replace(Key.Esc, Key.C.WithCtrl);
    }

    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _mainWindow.ShowInitialScreen();
        _application.Run(_mainWindow);
        _appLifetime.StopApplication();

        return Task.CompletedTask;
    }

    public override void Dispose()
    {
        _application.Dispose();
        base.Dispose();
    }
}