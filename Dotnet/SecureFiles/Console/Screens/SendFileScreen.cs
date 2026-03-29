using SecureFiles.Models;
using SecureFiles.Networking;
using SecureFiles.Services;
using Terminal.Gui.Drawing;
using Terminal.Gui.ViewBase;
using Terminal.Gui.Views;

namespace SecureFiles.Console.Screens;

public class SendFileScreen : View
{
    public SendFileScreen(
        Session session,
        SharedFileService sharedFileService,
        ProtocolInitiator protocolInitiator)
    {
        Title = $"Send File to {session.PeerFingerprint}";
        BorderStyle = LineStyle.Single;
        CanFocus = true;

        var files = sharedFileService.ListFiles();

        if (files.Count == 0)
        {
            var emptyLabel = new Label
            {
                Text = "No files available to send. Add files first.",
                X = 1,
                Y = 1
            };
            Add(emptyLabel);
            return;
        }

        var statusLabel = new Label
        {
            Text = "Select a file to send.",
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
                "Send File",
                $"Send '{file.Name}' to this peer?",
                "Yes", "No");

            if (confirm != 0) return;

            statusLabel.Text = $"Sending '{file.Name}'...";
            app.LayoutAndDraw();

            try
            {
                var result = protocolInitiator.SendFileAsync(session, file.Name, CancellationToken.None)
                    .GetAwaiter().GetResult();

                statusLabel.Text = result
                    ? $"'{file.Name}' sent successfully."
                    : $"Peer declined the upload of '{file.Name}'.";
            }
            catch (Exception ex)
            {
                MessageBox.ErrorQuery(app, "Transfer Error", ex.Message, "OK");
                statusLabel.Text = "Send failed.";
            }
        };

        Add(statusLabel, table);
        table.SetFocus();
    }
}
