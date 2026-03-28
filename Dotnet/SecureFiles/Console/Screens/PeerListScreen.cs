using SecureFiles.Models;
using SecureFiles.Services;
using Terminal.Gui.Drawing;
using Terminal.Gui.ViewBase;
using Terminal.Gui.Views;

namespace SecureFiles.Console.Screens;

public class PeerListScreen: View
{
    public PeerListScreen(PeerService peerService)
    {
        Title = "Discovered Peers";
        BorderStyle = LineStyle.Single;

        var table = new TableView
        {
            X = 1,
            Y= 1,
            Width = Dim.Fill(),
            Height = Dim.Fill()
        };

        table.Table = new EnumerableTableSource<Peer>(peerService.GetPeers(), new Dictionary<string, Func<Peer, object>>
        {
            { "Name", p => p.FriendlyName ?? "Unknown" },
            { "Peer ID", p => p.InstanceName }
        });
        
        Add(table);
    }
}
