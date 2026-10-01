using System.Net.Sockets;
using MacDiag.Mcp.Mac.Parsers;

namespace MacDiag.Mcp.Diagnostics.Containers;

/// <summary>Docker Engine's container list, over a unix socket.</summary>
/// <remarks>
/// <para>The socket is root-equivalent inside the engine's VM: anything that can POST to it can start a
/// privileged container. So this client can send exactly one request -- a GET of <see cref="ListRequest"/> --
/// and has no method that takes an API path, whatever grants the server holds.</para>
/// <para>Bounded by its own timeout, because a daemon can accept and never answer, and update_self waits for
/// every in-flight call; and by a response size, because the socket belongs to an ordinary user while the
/// server reading it runs as root.</para>
/// </remarks>
public sealed class MacDockerClient : IDockerQuery
{
    internal const string ListRequest = "/containers/json?all=1";
    internal const int MaxResponseBytes = 8 * 1024 * 1024;

    internal TimeSpan Budget { get; init; } = TimeSpan.FromSeconds(5);

    public async Task<(IReadOnlyList<DockerContainer> Containers, string? Limitation)> QueryAsync(
        string socketPath, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(socketPath);

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(Budget);
        try
        {
            // No redirects and no proxy: a 3xx would be a second request to a root-equivalent socket, and
            // HTTP_PROXY in the service's environment must not change what is sent.
            using var handler = new SocketsHttpHandler
            {
                ConnectCallback = (_, token) => ConnectAsync(socketPath, token),
                AllowAutoRedirect = false,
                UseProxy = false,
            };
            using var client = new HttpClient(handler)
            {
                BaseAddress = new Uri("http://docker"),
                Timeout = Timeout.InfiniteTimeSpan,
                MaxResponseContentBufferSize = MaxResponseBytes,
            };
            using var response = await client.GetAsync(ListRequest, deadline.Token).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                return ([], $"Docker answered {(int)response.StatusCode} {response.ReasonPhrase} on {socketPath}, so its containers are not listed.");
            }

            var json = await response.Content.ReadAsStringAsync(deadline.Token).ConfigureAwait(false);
            return (DockerContainers.Parse(json), null);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return ([], $"Docker did not answer on {socketPath} within {Budget.TotalSeconds:0.#} s, so its containers are not listed. " +
                        "The engine or its virtual machine may be hung.");
        }
        catch (HttpRequestException ex)
        {
            return ([], $"Could not ask Docker on {socketPath}: {ex.Message} The engine may be stopped.");
        }
        catch (FormatException ex)
        {
            return ([], $"Docker's container list on {socketPath} could not be read: {ex.Message}");
        }
    }

    private static async ValueTask<Stream> ConnectAsync(string socketPath, CancellationToken cancellationToken)
    {
        var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        try
        {
            await socket.ConnectAsync(new UnixDomainSocketEndPoint(socketPath), cancellationToken).ConfigureAwait(false);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }
}
