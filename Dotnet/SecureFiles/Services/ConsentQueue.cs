using System.Threading.Channels;
using SecureFiles.Models;

namespace SecureFiles.Services;

public class ConsentQueue
{
    private readonly Channel<ConsentRequest> _channel = Channel.CreateUnbounded<ConsentRequest>();

    /// <summary>
    /// Enqueues a consent request and returns a task that completes when the user responds.
    /// Called by ServerService when a peer sends a REQ_TO_RECEIVE or REQ_TO_SEND.
    /// </summary>
    public async Task<bool> RequestConsent(ConsentRequest request, CancellationToken cancellationToken = default)
    {
        await _channel.Writer.WriteAsync(request, cancellationToken);
        return await request.Response.Task.WaitAsync(cancellationToken);
    }

    /// <summary>
    /// Returns an async enumerable that yields consent requests as they arrive.
    /// Used by MainWindow to process requests sequentially.
    /// </summary>
    public IAsyncEnumerable<ConsentRequest> ReadAllAsync(CancellationToken cancellationToken = default) =>
        _channel.Reader.ReadAllAsync(cancellationToken);
}
