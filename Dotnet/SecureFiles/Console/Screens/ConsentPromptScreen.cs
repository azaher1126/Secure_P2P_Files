using SecureFiles.Models;
using Terminal.Gui.ViewBase;
using Terminal.Gui.Views;

namespace SecureFiles.Console.Screens;

public class ConsentPromptDialog : Dialog
{
    public ConsentPromptDialog(ConsentRequest request)
    {
        Title = "Incoming Request";

        var action = request.Type == ConsentRequestType.ReceiveFile
            ? "send you"
            : "download";

        var message = new Label
        {
            Text = $"Peer '{request.PeerName}' wants to {action} file '{request.FileName}'.",
            X = 1,
            Y = 1,
            Width = Dim.Fill(1)
        };

        Add(message);

        AddButton(new Button { Text = "Decline" });
        AddButton(new Button { Text = "Accept" });

        Width = Dim.Fill(8);
    }

    public bool WasAccepted => Result == 1;
}