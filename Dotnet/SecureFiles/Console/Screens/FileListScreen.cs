using SecureFiles.Console.Helpers;
using SecureFiles.Models;
using SecureFiles.Services;
using Terminal.Gui.Drawing;
using Terminal.Gui.ViewBase;
using Terminal.Gui.Views;

namespace SecureFiles.Console.Screens;

public class FileListScreen : View
{
    public FileListScreen(SharedFileService sharedFileService, INavigator navigator)
    {
        Title = "Shared Files";
        BorderStyle = LineStyle.Single;
        CanFocus = true;

        var files = sharedFileService.ListFiles().ToList();

        if (files.Count == 0)
        {
            var emptyLabel = new Label
            {
                Text = "No files are currently shared.",
                X = 1,
                Y = 1
            };
            Add(emptyLabel);
            return;
        }

        var statusLabel = new Label
        {
            Text = "Select a file to delete.",
            X = 1,
            Y = 1
        };

        var table = new TableView
        {
            X = 1,
            Y = 3,
            Width = Dim.Fill(),
            Height = Dim.Fill()
        };

        table.Table = new EnumerableTableSource<SharedFile>(files, new Dictionary<string, Func<SharedFile, object>>
        {
            { "Name", f => f.Name },
            { "Owner", f => f.OwnerFingerprint },
            { "SHA-256", f => Convert.ToHexStringLower(f.Hash)[..16] + "..." }
        });

        table.CellActivated += (_, e) =>
        {
            var app = App;
            if (app is null) return;
            if (e.Row < 0 || e.Row >= files.Count) return;

            var file = files[e.Row];

            var confirm = MessageBox.Query(
                app,
                "Delete File",
                $"Delete '{file.Name}' from shared files?",
                "Yes", "No");

            if (confirm != 0) return;

            try
            {
                sharedFileService.RemoveFile(file.Name).GetAwaiter().GetResult();
                navigator.NavigateBack();
            }
            catch (Exception ex)
            {
                MessageBox.ErrorQuery(app, "Error", ex.Message, "OK");
            }
        };

        Add(statusLabel, table);
        table.SetFocus();
    }
}
