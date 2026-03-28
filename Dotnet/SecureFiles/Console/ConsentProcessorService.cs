using Microsoft.Extensions.Hosting;
using SecureFiles.Console.Screens;
using SecureFiles.Models;
using SecureFiles.Services;

namespace SecureFiles.Console;

public class ConsentProcessorService : BackgroundService
{
    private readonly ConsentQueue _consentQueue;
    private readonly MainWindow _mainWindow;

    public ConsentProcessorService(ConsentQueue consentQueue, MainWindow mainWindow)
    {
        _consentQueue = consentQueue;
        _mainWindow = mainWindow;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await foreach (var request in _consentQueue.ReadAllAsync(stoppingToken))
        {
            var tcs = new TaskCompletionSource<bool>();

            _mainWindow.App!.Invoke(() =>
            {
                var dialog = new ConsentPromptDialog(request);
                _mainWindow.App!.Run(dialog);
                tcs.SetResult(dialog.WasAccepted);
                dialog.Dispose();
            });

            request.Response.TrySetResult(await tcs.Task);
        }
    }
}
