using Terminal.Gui.ViewBase;

namespace SecureFiles.Console.Helpers;

public interface INavigator
{
    void Navigate<TScreen>() where TScreen : View;

    void Navigate(View screen);

    void NavigateBack();

    void RefreshTitle();
}
