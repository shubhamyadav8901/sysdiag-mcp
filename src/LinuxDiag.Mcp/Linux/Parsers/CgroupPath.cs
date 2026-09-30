using System.Text.RegularExpressions;

namespace LinuxDiag.Mcp.Linux.Parsers;

/// <summary>A container named by a process's cgroup: which runtime made it, and its id.</summary>
public sealed record ContainerReference(string Runtime, string Id);

public static partial class CgroupPath
{
    /// <summary>The cgroup v2 path when there is one, else the first non-root v1 path, else "/".</summary>
    public static string Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        string? firstV1 = null;
        foreach (var line in text.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = line.Split(':', 3);
            if (parts.Length != 3)
            {
                continue;
            }

            if (parts[0] == "0" && parts[1].Length == 0)
            {
                return parts[2];
            }

            if (firstV1 is null && parts[2] != "/")
            {
                firstV1 = parts[2];
            }
        }

        return firstV1 ?? "/";
    }

    /// <summary>The container a process's cgroup file names: the v2 path first, then each v1 line.</summary>
    /// <remarks>
    /// On a hybrid host the unified line can name the shim's service while the v1 controllers still carry
    /// Docker's cgroupfs path, so stopping at the v2 line would miss the container.
    /// </remarks>
    public static ContainerReference? ContainerOf(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        var paths = text.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(line => line.Split(':', 3))
            .Where(parts => parts.Length == 3)
            .OrderBy(parts => parts[0] == "0" && parts[1].Length == 0 ? 0 : 1)
            .Select(parts => parts[2]);
        foreach (var path in paths)
        {
            if (Container(path) is { } found)
            {
                return found;
            }
        }

        return null;
    }

    /// <summary>The container a cgroup path belongs to, or null when no runtime claims it.</summary>
    /// <remarks>
    /// The systemd driver names a scope per runtime (<c>docker-&lt;id&gt;.scope</c>,
    /// <c>cri-containerd-&lt;id&gt;.scope</c>); the cgroupfs driver uses a bare id under
    /// <c>/docker</c> or <c>/kubepods</c>. A bare 64-hex segment anywhere else is not claimed: it could
    /// be anything, and a wrong container is worse than the raw path. Every segment is tried from the end,
    /// because a runtime may put the processes below the scope (podman's <c>…/libpod-&lt;id&gt;.scope/container</c>).
    /// </remarks>
    public static ContainerReference? Container(string path)
    {
        ArgumentNullException.ThrowIfNull(path);

        var segments = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        for (var i = segments.Length - 1; i >= 0; i--)
        {
            var scoped = Scoped().Match(segments[i]);
            if (scoped.Success)
            {
                var runtime = scoped.Groups["prefix"].Value switch
                {
                    "docker-" => "docker",
                    "cri-containerd-" => "containerd",
                    "crio-" => "cri-o",
                    _ => "podman",
                };
                return new ContainerReference(runtime, scoped.Groups["id"].Value);
            }

            if (!Bare().IsMatch(segments[i]))
            {
                continue;
            }

            if (i >= 1 && segments[i - 1] == "docker")
            {
                return new ContainerReference("docker", segments[i]);
            }

            if (segments.Take(i).Any(s => s.StartsWith("kubepods", StringComparison.Ordinal)))
            {
                return new ContainerReference("kubernetes", segments[i]);
            }
        }

        return null;
    }

    [GeneratedRegex(@"^(?<prefix>docker-|cri-containerd-|crio-|libpod-)(?<id>[0-9a-f]{64})\.scope$")]
    private static partial Regex Scoped();

    [GeneratedRegex(@"^[0-9a-f]{64}$")]
    private static partial Regex Bare();
}
