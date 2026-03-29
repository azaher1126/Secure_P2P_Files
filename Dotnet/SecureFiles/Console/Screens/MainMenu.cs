using SecureFiles.Console.Helpers;
using SecureFiles.Services;
using Terminal.Gui.App;
using Terminal.Gui.Drawing;
using Terminal.Gui.ViewBase;
using Terminal.Gui.Views;

namespace SecureFiles.Console.Screens;

public enum MainMenuChoice
{
    ListFiles,
    AddFile,
    ViewPeers,
    ViewContacts,
    MigrateKey,
    Quit
}

public class MainMenu : View
{
    public MainMenu(INavigator navigator, KeyMigrationService keyMigrationService)
    {
        Title = "Main Menu";
        BorderStyle = LineStyle.Single;
        CanFocus = true;

        var prompt = new Label
        {
            Text = "What would you like to do?",
            X = 1,
            Y = 1
        };

        var source = new EnumListSource<MainMenuChoice>(FormatChoice);

        var listView = new ListView
        {
            X = 1,
            Y = 3,
            Width = Dim.Auto(),
            Height = Dim.Auto(),
            Source = source
        };

        listView.Accepting += (_, e) =>
        {
            if (listView.SelectedItem is not { } index) return;

            var choice = source.GetValue(index);
            switch (choice)
            {
                case MainMenuChoice.ListFiles:
                    navigator.Navigate<FileListScreen>();
                    break;
                case MainMenuChoice.AddFile:
                    navigator.Navigate<AddFileScreen>();
                    break;
                case MainMenuChoice.ViewPeers:
                    navigator.Navigate<PeerListScreen>();
                    break;
                case MainMenuChoice.ViewContacts:
                    navigator.Navigate<ContactListScreen>();
                    break;
                case MainMenuChoice.MigrateKey:
                {
                    var app = App;
                    if (app is null) break;

                    var confirm = MessageBox.Query(app, "Key Migration",
                        "This will generate a new RSA key pair and notify all connected contacts. Continue?",
                        "Yes", "No");

                    if (confirm != 0) break;

                    try
                    {
                        keyMigrationService.MigrateKeyAsync(CancellationToken.None).GetAwaiter().GetResult();
                        navigator.RefreshTitle();
                        MessageBox.Query(app, "Success", "Key migration complete. All sessions have been closed.", "OK");
                    }
                    catch (Exception ex)
                    {
                        MessageBox.ErrorQuery(app, "Error", ex.Message, "OK");
                    }

                    break;
                }
                case MainMenuChoice.Quit:
                    App?.RequestStop();
                    break;
            }

            e.Handled = true;
        };

        Add(prompt, listView);
        listView.SetFocus();
        listView.SelectedItem = 0;
    }

    private static string FormatChoice(MainMenuChoice choice) => choice switch
    {
        MainMenuChoice.ListFiles => "List shared files",
        MainMenuChoice.AddFile => "Add a file to share",
        MainMenuChoice.ViewPeers => "View discovered peers",
        MainMenuChoice.ViewContacts => "View contacts",
        MainMenuChoice.MigrateKey => "Migrate key (compromised key)",
        MainMenuChoice.Quit => "Quit",
        _ => choice.ToString()
    };
}