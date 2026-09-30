using System.Net.Sockets;
using LinuxDiag.Mcp.Linux.Parsers;

namespace LinuxDiag.Mcp.Diagnostics.Containers;

/// <summary>Docker Engine's container list, over its unix socket.</summary>
/// <remarks>
/// <para>The socket is root-equivalent: anything that can POST to it can start a privileged container.
/// So this client can send exactly one request -- a GET of <see cref="ListRequest"/> -- and has no
/// method that takes a path, whatever grants the server holds.</para>
/// <para>Bounded by its own timeout, because <c>dockerd</c> can accept and then never answer, and
/// update_self waits for every in-flight call.</para>
/// </remarks>
public sealed class DockerEngineClient
{
    public const string DefaultSocket = "/var/run/docker.sock";
    internal const string ListRequest = "/containers/json?all=1";

    private readonly string _socketPath;
    private readonly TimeSpan _timeout;

    public DockerEngineClient()
        : this(DefaultSocket, TimeSpan.FromSeconds(5))
    {
    }

    internal DockerEngineClient(string socketPath, TimeSpan timeout)
    {
        _socketPath = socketPath;
        _timeout = timeout;
    }

    /// <returns>The containers, or none and why; no socket at all is neither a container nor a limitation.</returns>
    public async Task<(IReadOnlyList<DockerContainer> Containers, string? Limitation)> ListAsync(
        CancellationToken cancellationToken)
    {
        if (!File.Exists(_socketPath))
        {
            return ([], null);
        }

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(_timeout);
        try
        {
            // No redirects and no proxy: a 3xx would be a second request to a root-equivalent socket, and
            // HTTP_PROXY in the service's environment must not change what is sent.
            using var handler = new SocketsHttpHandler
            {
                ConnectCallback = ConnectAsync,
                AllowAutoRedirect = false,
                UseProxy = false,
            };
            using var client = new HttpClient(handler)
            {
                BaseAddress = new Uri("http://docker"),
                Timeout = Timeout.InfiniteTimeSpan,
            };
            using var response = await client.GetAsync(ListRequest, deadline.Token).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                return ([], $"Docker answered {(int)response.StatusCode} {response.ReasonPhrase} on {_socketPath}, " +
                            "so Docker containers are not listed.");
            }

            var json = await response.Content.ReadAsStringAsync(deadline.Token).ConfigureAwait(false);
            return (DockerContainers.Parse(json), null);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return ([], $"Docker did not answer on {_socketPath} within {_timeout.TotalSeconds:0.#} s, so Docker " +
                        "containers are not listed. The daemon may be hung.");
        }
        catch (HttpRequestException ex)
        {
            return ([], $"Could not reach Docker on {_socketPath}: {ex.Message} Run the server as root, or in the " +
                        "docker group, to list Docker containers.");
        }
        catch (FormatException ex)
        {
            return ([], $"Docker's container list could not be read: {ex.Message}");
        }
    }

    private async ValueTask<Stream> ConnectAsync(SocketsHttpConnectionContext context, CancellationToken cancellationToken)
    {
        var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        try
        {
            await socket.ConnectAsync(new UnixDomainSocketEndPoint(_socketPath), cancellationToken).ConfigureAwait(false);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }
}
