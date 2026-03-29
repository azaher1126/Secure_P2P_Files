using System.Collections;
using System.Collections.Specialized;
using Terminal.Gui.Text;
using Terminal.Gui.Views;

namespace SecureFiles.Console.Helpers;

public class EnumListSource<T> : IListDataSource where T : struct, Enum
{
    private readonly T[] _values;
    private readonly Func<T, string> _formatter;
    
    public EnumListSource(Func<T, string> formatter)
    {
        _values = Enum.GetValues<T>();
        _formatter = formatter;
    }
    
    public T GetValue(int index) => _values[index];
    
    public void Dispose()
    {
        if (CollectionChanged != null)
            CollectionChanged(this, new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Reset));
        GC.SuppressFinalize(this);
    }

    public bool IsMarked(int item)
    {
        return false;
    }

    public void Render(ListView listView, bool selected, int item, int col, int row, int width, int viewportX = 0)
    {
        var text = _formatter(_values[item]).PadRight(width);
        listView.Move(col, row);
        listView.AddStr(text);
    }

    public void SetMark(int item, bool value)
    {
        
    }

    public IList ToList()
    {
        return _values;
    }

    public int Count => _values.Length;
    public int MaxItemLength => _values.Max(v => _formatter(v).Length);
    public bool SuspendCollectionChangedEvent { get; set; }
    public event NotifyCollectionChangedEventHandler? CollectionChanged;
}