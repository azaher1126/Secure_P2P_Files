using SecureFiles.Services;
using Terminal.Gui.Drawing;
using Terminal.Gui.ViewBase;
using Terminal.Gui.Views;

namespace SecureFiles.Console.Screens;

public class AddFileScreen : View
{
    public AddFileScreen(SharedFileService sharedFileService)
    {
        Title = "Add File";
        BorderStyle = LineStyle.Single;
        CanFocus = true;
        
        var statusLabel = new Label
        {
            Text = "Select a file to share.",
            X = 1,
            Y = 1
        };

        var selectButton = new Button
        {
            Text = "Browse...",
            X = 1,
            Y = 3
        };

        selectButton.Accepting += (_, e) =>
        {
            var app = App;
            if (app is null) return;

            var openDialog = new OpenDialog
            {
                Title = "Select a file to share",
                OpenMode = OpenMode.File,
                AllowsMultipleSelection = false
            };

            app.Run(openDialog);

            var filePaths = openDialog.FilePaths;
            openDialog.Dispose();

            if (filePaths.Count == 0)
                return;

            var filePath = filePaths[0];
            var fileName = Path.GetFileName(filePath);

            var confirm = MessageBox.Query(
                app,
                "Confirm",
                $"Share '{fileName}'?",
                "Yes", "No");

            if (confirm != 0)
                return;

            statusLabel.Text = "Encrypting and storing file...";
            app.LayoutAndDraw();

            try
            {
                sharedFileService.AddFile(filePath).GetAwaiter().GetResult();
                statusLabel.Text = $"'{fileName}' added successfully.";

                var deleteOriginal = MessageBox.Query(
                    app,
                    "Delete Original",
                    $"Delete the original file '{fileName}'?",
                    "Yes", "No");

                if (deleteOriginal == 0)
                {
                    File.Delete(filePath);
                    statusLabel.Text = $"'{fileName}' added and original deleted.";
                }
            }
            catch (InvalidOperationException ex)
            {
                MessageBox.ErrorQuery(
                    app,
                    "Error",
                    ex.Message,
                    "OK");
                statusLabel.Text = "Failed to add file.";
            }

            e.Handled = true;
        };

        Add(statusLabel, selectButton);
        selectButton.SetFocus();
    }
}
