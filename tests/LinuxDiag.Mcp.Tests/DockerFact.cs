using System.Net.Sockets;

namespace LinuxDiag.Mcp.Tests;

/// <summary>A Linux fact that needs a Docker daemon this account can reach, and says why when it cannot.</summary>
/// <remarks>Probed by connecting, not inferred from the socket's existence: a socket in the docker group's
/// hands and an account outside that group look the same on disk.</remarks>
public sealed class DockerFactAttribute : FactAttribute
{
    private static readonly Lazy<string?> Unavailable = new(Probe);

    public DockerFactAttribute()
    {
        if (!OperatingSystem.IsLinux())
        {
            Skip = "Linux only. Run tools/test-linux.sh.";
        }
        else if (Unavailable.Value is { } reason)
        {
            Skip = reason;
        }
    }

    private static string? Probe()
    {
        if (!File.Exists("/var/run/docker.sock"))
        {
            return "No Docker daemon here: /var/run/docker.sock does not exist.";
        }

        try
        {
            using var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            socket.Connect(new UnixDomainSocketEndPoint("/var/run/docker.sock"));
            return null;
        }
        catch (SocketException ex)
        {
            return $"Docker is installed but this account cannot reach it ({ex.SocketErrorCode}); add it to the docker group.";
        }
    }
}
