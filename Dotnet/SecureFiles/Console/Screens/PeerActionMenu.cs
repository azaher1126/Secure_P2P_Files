using SecureFiles.Console.Helpers;
using SecureFiles.Models;
using SecureFiles.Networking;
using SecureFiles.Services;
using Terminal.Gui.Drawing;
using Terminal.Gui.ViewBase;
using Terminal.Gui.Views;

namespace SecureFiles.Console.Screens;

public enum PeerAction
{
    ViewFileList,
    SendFile,
    Back
}

public class PeerActionMenu : View
{
    private readonly Peer _peer;
    private readonly ConnectionManager _connectionManager;
    private readonly ProtocolInitiator _protocolInitiator;
    private readonly SharedFileService _sharedFileService;
    private readonly INavigator _navigator;

    public PeerActionMenu(
        Peer peer,
        ConnectionManager connectionManager,
        ProtocolInitiator protocolInitiator,
        SharedFileService sharedFileService,
        INavigator navigator)
    {
        _peer = peer;
        _connectionManager = connectionManager;
        _protocolInitiator = protocolInitiator;
        _sharedFileService = sharedFileService;
        _navigator = navigator;

        Title = $"Peer: {peer.FriendlyName ?? "Unknown"} ({peer.InstanceName})";
        BorderStyle = LineStyle.Single;
        CanFocus = true;

        var prompt = new Label
        {
            Text = "What would you like to do?",
            X = 1,
            Y = 1
        };

        var source = new EnumListSource<PeerAction>(FormatAction);

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
                case PeerAction.ViewFileList:
                    HandleViewFileList();
                    break;
                case PeerAction.SendFile:
                    HandleSendFile();
                    break;
                case PeerAction.Back:
                    _navigator.NavigateBack();
                    break;
            }

            e.Handled = true;
        };

        Add(prompt, listView);
        listView.SetFocus();
        listView.SelectedItem = 0;
    }

    private void HandleViewFileList()
    {
        var app = App;
        if (app is null) return;

        try
        {
            var session = _connectionManager.ConnectToPeer(_peer, CancellationToken.None)
                .GetAwaiter().GetResult();

            var files = _protocolInitiator.RequestFileListAsync(session, CancellationToken.None)
                .GetAwaiter().GetResult();

            var screen = new PeerFileListScreen(session, files, _protocolInitiator);
            _navigator.Navigate(screen);
        }
        catch (Exception ex)
        {
            MessageBox.ErrorQuery(app, "Connection Error", ex.Message, "OK");
        }
    }

    private void HandleSendFile()
    {
        var app = App;
        if (app is null) return;

        try
        {
            var session = _connectionManager.ConnectToPeer(_peer, CancellationToken.None)
                .GetAwaiter().GetResult();

            var screen = new SendFileScreen(session, _sharedFileService, _protocolInitiator);
            _navigator.Navigate(screen);
        }
        catch (Exception ex)
        {
            MessageBox.ErrorQuery(app, "Connection Error", ex.Message, "OK");
        }
    }

    private static string FormatAction(PeerAction action) => action switch
    {
        PeerAction.ViewFileList => "View file list",
        PeerAction.SendFile => "Send a file",
        PeerAction.Back => "Back",
        _ => action.ToString()
    };
}
