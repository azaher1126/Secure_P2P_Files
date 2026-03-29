using SecureFiles.Console.Helpers;
using SecureFiles.Models;
using SecureFiles.Networking;
using SecureFiles.Services;
using Terminal.Gui.Drawing;
using Terminal.Gui.ViewBase;
using Terminal.Gui.Views;

namespace SecureFiles.Console.Screens;

public class PeerListScreen : View
{
    public PeerListScreen(
        PeerService peerService,
        ConnectionManager connectionManager,
        ProtocolInitiator protocolInitiator,
        SharedFileService sharedFileService,
        INavigator navigator)
    {
        Title = "Discovered Peers";
        BorderStyle = LineStyle.Single;
        CanFocus = true;

        var peers = peerService.GetPeers().ToList();

        if (peers.Count == 0)
        {
            var emptyLabel = new Label
            {
                Text = "No peers discovered yet.",
                X = 1,
                Y = 1
            };
            Add(emptyLabel);
            return;
        }

        var statusLabel = new Label
        {
            Text = "Select a peer to connect.",
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

        table.Table = new EnumerableTableSource<Peer>(peers, new Dictionary<string, Func<Peer, object>>
        {
            { "Name", p => p.FriendlyName ?? "Unknown" },
            { "Peer ID", p => p.InstanceName },
            { "Address", p => $"{p.Address}:{p.Port}" }
        });

        table.CellActivated += (_, e) =>
        {
            var app = App;
            if (app is null) return;
            if (e.Row < 0 || e.Row >= peers.Count) return;

            var peer = peers[e.Row];
            var menu = new PeerActionMenu(peer, connectionManager, protocolInitiator, sharedFileService, navigator);
            navigator.Navigate(menu);
        };

        Add(statusLabel, table);
        table.SetFocus();
    }
}
