using SecureFiles.Models;
using SecureFiles.Networking;
using Terminal.Gui.Drawing;
using Terminal.Gui.ViewBase;
using Terminal.Gui.Views;

namespace SecureFiles.Console.Screens;

public class PeerFileListScreen : View
{
    public PeerFileListScreen(
        Session session,
        IReadOnlyList<SharedFile> files,
        ProtocolInitiator protocolInitiator)
    {
        Title = $"Files from {session.PeerFingerprint}";
        BorderStyle = LineStyle.Single;
        CanFocus = true;

        if (files.Count == 0)
        {
            var emptyLabel = new Label
            {
                Text = "This peer has no shared files.",
                X = 1,
                Y = 1
            };
            Add(emptyLabel);
            return;
        }

        var statusLabel = new Label
        {
            Text = "Select a file to download.",
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

        var fileList = files.ToList();

        table.Table = new EnumerableTableSource<SharedFile>(fileList, new Dictionary<string, Func<SharedFile, object>>
        {
            { "Name", f => f.Name },
            { "Owner", f => f.OwnerFingerprint },
            { "SHA-256", f => Convert.ToHexStringLower(f.Hash)[..16] + "..." }
        });

        table.CellActivated += (_, e) =>
        {
            var app = App;
            if (app is null) return;
            if (e.Row < 0 || e.Row >= fileList.Count) return;

            var file = fileList[e.Row];

            var confirm = MessageBox.Query(
                app,
                "Download File",
                $"Download '{file.Name}' from this peer?",
                "Yes", "No");

            if (confirm != 0) return;

            statusLabel.Text = $"Downloading '{file.Name}'...";
            app.LayoutAndDraw();

            try
            {
                var result = protocolInitiator.RequestFileAsync(session, file, CancellationToken.None)
                    .GetAwaiter().GetResult();

                statusLabel.Text = result
                    ? $"'{file.Name}' downloaded successfully."
                    : $"Peer declined the download of '{file.Name}'.";
            }
            catch (System.Security.Cryptography.CryptographicException)
            {
                MessageBox.ErrorQuery(app, "Security Error",
                    $"Signature verification failed for '{file.Name}'. The file may have been tampered with.", "OK");
                statusLabel.Text = "Download failed — signature verification error.";
            }
            catch (Exception ex)
            {
                MessageBox.ErrorQuery(app, "Transfer Error", ex.Message, "OK");
                statusLabel.Text = "Download failed.";
            }
        };

        Add(statusLabel, table);
        table.SetFocus();
    }
}
