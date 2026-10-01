using System.ComponentModel;
using System.Text;
using MacDiag.Mcp.Diagnostics.Handles;
using ModelContextProtocol.Server;

namespace MacDiag.Mcp.Tools;

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
        "Find which processes hold a file or directory open. The file is matched by device and inode, so a hard " +
        "link or a rename still matches, and each holder is shown with how it holds it: open for reading or " +
        "writing, running it as its executable, mapping it as a library, or using it as its working or root " +
        "directory. Use it for 'text file busy', a file that will not delete, or a volume that will not eject. " +
        "macOS's lsof does not report lock state, so the result names who has the file open, not which of them " +
        "holds a lock. It reports Exhaustive only when the server runs as root.")]
    public async Task<WhoLocksPathResult> WhoLocksPath(
        [Description("Full path to the file or directory, for example /Users/me/Library/Application Support/App/lock")] string path,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!path.StartsWith('/'))
        {
            throw new ArgumentException("Give a full path, for example /Users/me/project/file.lock.", nameof(path));
        }

        var query = await locks.QueryAsync(Path.GetFullPath(path), cancellationToken).ConfigureAwait(false);
        return new WhoLocksPathResult(
            RenderLockSummary(query), query.Path, query.Holders, query.Exhaustive, query.Limitations, query.TotalMatched, query.Truncated);
    }

    internal static string RenderLockSummary(LockQuery query)
    {
        var builder = new StringBuilder();
        if (!query.PathExists)
        {
            return builder.Append(RenderLimits.Printable(query.Path)).Append(" does not exist.").ToString();
        }

        builder.Append(RenderLimits.Printable(query.Path)).Append(": ").Append(query.TotalMatched)
            .AppendLine(query.TotalMatched == 1 ? " holder" : " holders");
        foreach (var holder in query.Holders.Take(RenderLimits.MaxRenderedRows))
        {
            builder.Append("- ").Append(RenderLimits.Printable(holder.ProcessName)).Append(" [").Append(holder.ProcessId).Append("] ")
                .Append(holder.Kind);
            if (holder.Access is { } access)
            {
                builder.Append(" (").Append(RenderLimits.Printable(access)).Append(')');
            }

            builder.AppendLine();
        }

        RenderLimits.NoteElision(builder, query.Holders.Count, "holders");
        if (query.Truncated)
        {
            builder.Append("Showing the first ").Append(query.Holders.Count).Append(" of ").Append(query.TotalMatched)
                .AppendLine("; raise MACDIAG_MAX_RESULTS.");
        }

        foreach (var limitation in query.Limitations)
        {
            builder.Append("NOTE: ").AppendLine(RenderLimits.Printable(limitation));
        }

        return builder.ToString().TrimEnd();
    }
}
