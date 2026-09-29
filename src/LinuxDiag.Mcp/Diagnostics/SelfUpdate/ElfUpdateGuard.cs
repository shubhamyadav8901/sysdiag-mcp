using Diag.Mcp.Server.SelfUpdate;

namespace LinuxDiag.Mcp.Diagnostics.SelfUpdate;

/// <summary>The staged build must be an x86-64 Linux executable. There is no signature ratchet: nothing is signed.</summary>
public sealed class ElfUpdateGuard : IUpdateGuard
{
    public void RequireAcceptable(string livePath, StagedBuild staged, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(staged);

        var header = new byte[20];
        int read;
        using (var stream = File.OpenRead(staged.Path))
        {
            read = stream.ReadAtLeast(header, header.Length, throwOnEndOfStream: false);
        }

        if (ElfHeader.Problem(header.AsSpan(0, read)) is { } problem)
        {
            throw new SelfUpdateRejectedException(
                $"'{staged.Path}' was refused because {problem} Nothing has been changed.");
        }
    }
}
