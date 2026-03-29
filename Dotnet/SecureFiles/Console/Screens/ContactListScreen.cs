using SecureFiles.Models;
using SecureFiles.Services;
using Terminal.Gui.Drawing;
using Terminal.Gui.ViewBase;
using Terminal.Gui.Views;

namespace SecureFiles.Console.Screens;

public class ContactListScreen : View
{
    public ContactListScreen(ContactStore contactStore)
    {
        Title = "Contacts";
        BorderStyle = LineStyle.Single;
        CanFocus = true;

        var contacts = contactStore.ListContacts();

        if (contacts.Count == 0)
        {
            var emptyLabel = new Label
            {
                Text = "No contacts yet. Connect to a peer to add them.",
                X = 1,
                Y = 1
            };
            Add(emptyLabel);
            return;
        }

        var statusLabel = new Label
        {
            Text = "Select a contact to view cached files.",
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

        var contactList = contacts.ToList();

        table.Table = new EnumerableTableSource<Contact>(contactList, new Dictionary<string, Func<Contact, object>>
        {
            { "Fingerprint", c => c.Fingerprint },
            { "Cached Files", c => c.CachedFiles.Count }
        });

        table.CellActivated += (_, e) =>
        {
            var app = App;
            if (app is null) return;
            if (e.Row < 0 || e.Row >= contactList.Count) return;

            var contact = contactList[e.Row];

            if (contact.CachedFiles.Count == 0)
            {
                MessageBox.Query(app, "No Cached Files",
                    $"Contact '{contact.Fingerprint}' has no cached file list.", "OK");
                return;
            }

            var fileNames = string.Join("\n", contact.CachedFiles.Select(f => $"  {f.Name} (owner: {f.OwnerFingerprint})"));
            MessageBox.Query(app, $"Files from {contact.Fingerprint}",
                $"Cached file list:\n{fileNames}", "OK");
        };

        Add(statusLabel, table);
        table.SetFocus();
    }
}
