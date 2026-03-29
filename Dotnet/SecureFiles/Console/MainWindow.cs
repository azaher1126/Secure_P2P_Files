using Microsoft.Extensions.DependencyInjection;
using SecureFiles.Console.Helpers;
using SecureFiles.Console.Screens;
using SecureFiles.Services;
using Terminal.Gui.Drawing;
using Terminal.Gui.Input;
using Terminal.Gui.ViewBase;
using Terminal.Gui.Views;

namespace SecureFiles.Console;

public class MainWindow : Runnable, INavigator
{
    private readonly IServiceProvider _serviceProvider;
    private View? _currentScreen;
    private readonly Label _footerLabel = new()
    {
        Text = "Press ESC to return.",
        X = 1,
        Y = Pos.AnchorEnd(1)
    };

    private readonly Stack<View> _navigationStack = new();

    public MainWindow(IServiceProvider serviceProvider, UserConfigProvider userConfigProvider)
    {
        _serviceProvider = serviceProvider;
        Title = $"Secure P2P Files — {userConfigProvider.Username} ({userConfigProvider.GetFingerprint()})";
        BorderStyle = LineStyle.Single;

        KeyDown += (_, e) =>
        {
            if (e == Key.Esc)
            {
                NavigateBack();
                e.Handled = true;
            }
        };
    }

    public void ShowInitialScreen()
    {
        Navigate<MainMenu>();
    }

    public void Navigate<TScreen>() where TScreen : View
    {
        var screen = ActivatorUtilities.CreateInstance<TScreen>(_serviceProvider);
        Navigate(screen);
    }

    public void Navigate(View screen)
    {
        if (_currentScreen is not null)
        {
            Remove(_currentScreen);
            _navigationStack.Push(_currentScreen);

            if (!SubViews.Contains(_footerLabel))
            {
                Add(_footerLabel);
            }
        }

        _currentScreen = screen;
        _currentScreen.Width = Dim.Fill();
        _currentScreen.Height = _navigationStack.Count > 0 ? Dim.Fill(1) : Dim.Fill();
        Add(screen);
        screen.SetFocus();
    }

    public void NavigateBack()
    {
        if (_navigationStack.Count == 0) return;

        if (_currentScreen is not null)
        {
            Remove(_currentScreen);
            _currentScreen.Dispose();
        }

        _currentScreen = _navigationStack.Pop();
        Add(_currentScreen);
        _currentScreen.SetFocus();

        if (_navigationStack.Count == 0 && SubViews.Contains(_footerLabel))
        {
            Remove(_footerLabel);
        }
    }

}
