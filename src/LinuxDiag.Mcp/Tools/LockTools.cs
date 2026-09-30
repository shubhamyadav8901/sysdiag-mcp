using System.ComponentModel;
using System.Text;
using LinuxDiag.Mcp.Diagnostics.Handles;
using ModelContextProtocol.Server;

namespace LinuxDiag.Mcp.Tools;

/// <summary>Structured result of <c>who_locks_path</c>.</summary>
public sealed record WhoLocksPathResult(
    string Summary, string Path, IReadOnlyList<LockHolder> Holders, bool Exhaustive, IReadOnlyList<string> Limitations,
    int TotalMatched, bool Truncated);

[McpServerToolType]
public sealed class LockTools(ILockInspector locks)
{
    [McpServerTool(
        Name = "who_locks_path",
        Title = "Who holds or locks this path",
        ReadOnly = true,
        Destructive = false,
        Idempotent = true,
        OpenWorld = true,
        UseStructuredContent = true)]
    [Description(
        "Find which processes hold a file or directory open or locked. Every process's open files are compared by " +
        "device and inode, so a hard link, a rename or a container's own path still matches, and each holder is " +
        "shown with how it opened the file and any flock, POSIX lock, open-file-description lock or lease it holds " +
        "on it - plus processes blocked waiting for such a lock, and processes running the file, mapping it, or " +
        "using it as their working or root directory. Use it for 'text file busy', a lock file an agent will not " +
        "release, or a package manager waiting on a lock. It reports Exhaustive only when the server runs as root " +
        "and could read every process.")]
    public WhoLocksPathResult WhoLocksPath(
        [Description("Full path to the file or directory, for example /var/lib/dpkg/lock-frontend")] string path,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!Path.IsPathRooted(path))
        {
            throw new ArgumentException("Give a full path, for example /var/lib/dpkg/lock-frontend.", nameof(path));
        }

        var query = locks.Query(Path.GetFullPath(path), cancellationToken);
        return new WhoLocksPathResult(
            RenderLockSummary(query), query.Path, query.Holders, query.Exhaustive, query.Limitations,
            query.TotalMatched, query.Truncated);
    }

    internal static string RenderLockSummary(LockQuery query)
    {
        var builder = new StringBuilder();
        foreach (var limitation in query.Limitations)
        {
            builder.Append("WARNING: ").AppendLine(RenderLimits.Printable(limitation));
        }

        if (!query.PathExists)
        {
            return builder.Append(RenderLimits.Printable(query.Path)).Append(" does not exist, so nothing can hold it. Check the path.").ToString();
        }

        if (query.Holders.Count == 0)
        {
            builder.Append("No process holds ").Append(RenderLimits.Printable(query.Path)).Append(" open or locked.");
            builder.Append(query.Exhaustive
                ? " This is exhaustive: every process was checked."
                : " This is not exhaustive; see the warnings above.");
            return builder.ToString();
        }

        builder.Append(query.TotalMatched).Append(query.TotalMatched == 1 ? " holder of " : " holders of ")
            .Append(RenderLimits.Printable(query.Path)).AppendLine(":");
        foreach (var holder in query.Holders.Take(RenderLimits.MaxRenderedRows))
        {
            builder.Append("- ").Append(RenderLimits.Printable(holder.ProcessName)).Append(" (PID ").Append(holder.ProcessId).Append("): ")
                .Append(holder.Kind);
            if (holder.Access is not null)
            {
                builder.Append(' ').Append(RenderLimits.Printable(holder.Access));
            }

            if (holder.Waiting)
            {
                builder.Append(" - WAITING for the lock, not holding it");
            }

            if (!holder.Confirmed)
            {
                builder.Append(" - named by /proc/locks only, not confirmed through its open files");
            }

            // A PID of 0 or -1 names no process, so there is no PID to warn about acting on.
            if (!holder.StillRunning && holder.ProcessId > 0)
            {
                builder.Append(" (no longer running; do not act on this PID)");
            }

            builder.AppendLine();
        }

        RenderLimits.NoteElision(builder, query.Holders.Count, "returned holders");
        if (query.Truncated)
        {
            builder.Append("Showing the first ").Append(query.Holders.Count).Append(" of ").Append(query.TotalMatched)
                .AppendLine("; raise LINUXDIAG_MAX_RESULTS to see the rest.");
        }

        if (!query.Exhaustive)
        {
            builder.Append("Coverage is partial, so there may be holders this could not see.");
        }

        return builder.ToString().TrimEnd();
    }
}
