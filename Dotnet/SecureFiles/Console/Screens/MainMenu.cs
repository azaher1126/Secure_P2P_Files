using SecureFiles.Console.Helpers;
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
    Quit
}

public class MainMenu : View
{
    public MainMenu(INavigator navigator)
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
        MainMenuChoice.Quit => "Quit",
        _ => choice.ToString()
    };
}