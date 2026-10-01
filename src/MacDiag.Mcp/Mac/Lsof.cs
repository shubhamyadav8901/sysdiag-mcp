using MacDiag.Mcp.Mac.Parsers;

namespace MacDiag.Mcp.Mac;

/// <summary>The one way MacDiag runs lsof: numeric, non-blocking where it matters, NUL-terminated fields.</summary>
/// <remarks>
/// <para>-n and -P skip name and port lookups (a slow resolver must not stall a tool); -w drops warnings that
/// would otherwise land in stderr and read as errors. -b is for full listings: it skips the kernel calls that
/// block on a stale SMB, NFS or autofs mount, which would hang the whole call.</para>
/// <para>lsof exits 1 both when it found nothing and when it failed. Only stderr tells them apart.</para>
/// </remarks>
public static class Lsof
{
    public const string Fields = "-F0pcuRfatdDsinPT";

    public static bool IsError(int exitCode, string standardError) =>
        exitCode != 0 && (exitCode != 1 || (standardError ?? string.Empty).Trim().Length > 0);

    /// <param name="selection">What to list; a caller-supplied path goes after "--" so it cannot be read as an option.</param>
    public static async Task<IReadOnlyList<LsofProcess>> RunAsync(
        IExternalCommand commands, IReadOnlyList<string> selection, bool fullListing, TimeSpan timeout, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(commands);
        ArgumentNullException.ThrowIfNull(selection);

        string[] arguments = ["-n", "-P", "-w", Fields, .. fullListing ? new[] { "-b" } : [], .. selection];
        var result = await commands.RunAsync("lsof", arguments, timeout, cancellationToken).ConfigureAwait(false);
        if (IsError(result.ExitCode, result.StandardError))
        {
            throw new LsofException(
                $"lsof failed (exit {result.ExitCode}): {result.StandardError.Trim()}");
        }

        return LsofFields.Parse(result.StandardOutput);
    }
}

public sealed class LsofException : Exception, IDiagnosticException
{
    public LsofException(string message)
        : base(message)
    {
    }

    public LsofException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
