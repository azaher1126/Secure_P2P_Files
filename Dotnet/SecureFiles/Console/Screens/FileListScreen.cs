using SecureFiles.Models;
using SecureFiles.Services;
using Terminal.Gui.Drawing;
using Terminal.Gui.ViewBase;
using Terminal.Gui.Views;

namespace SecureFiles.Console.Screens;

public class FileListScreen : View
{
    public FileListScreen(SharedFileService sharedFileService)
    {
        Title = "Shared Files";
        BorderStyle = LineStyle.Single;
        CanFocus = true;

        var files = sharedFileService.ListFiles();

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

        var table = new TableView
        {
            X = 1,
            Y = 1,
            Width = Dim.Fill(),
            Height = Dim.Fill()
        };

        table.Table = new EnumerableTableSource<SharedFile>(files, new Dictionary<string, Func<SharedFile, object>>
        {
            { "Name", f => f.Name },
            { "Owner", f => f.OwnerFingerprint },
            { "SHA-256", f => Convert.ToHexStringLower(f.Hash)[..16] + "..." }
        });

        Add(table);
    }
}
