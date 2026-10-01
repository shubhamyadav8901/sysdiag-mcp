using System.Diagnostics;
using MacDiag.Mcp.Configuration;
using MacDiag.Mcp.Hosting;
using MacDiag.Mcp.Mac;
using MacDiag.Mcp.Mac.Parsers;

namespace MacDiag.Mcp.Diagnostics.Signatures;

/// <summary>Each file's SHA-256, code signature, Gatekeeper assessment and package receipt.</summary>
/// <remarks>
/// <para>Every file is hashed by shasum in a child process, never opened here. A path statted as a regular file
/// can be swapped for a FIFO before it is opened, and open(2) on a FIFO blocks in the kernel where no
/// cancellation token reaches it -- update_self's drain would wait on that call forever. A child the runner can
/// kill cannot hang the server.</para>
/// <para>codesign, spctl and pkgutil each get a rooted path. spctl and pkgutil take it without "--": pkgutil's
/// --file-info consumes the next argument as its path, and spctl does not document "--"; a rooted path cannot be
/// read as an option either way.</para>
/// </remarks>
public sealed class MacSignatureInspector(IExternalCommand commands, MacDiagOptions options) : ISignatureInspector
{
    internal const int MaxPaths = 200;

    internal const string TrustNote =
        "A valid signature says who signed the file and that it is unchanged since; it is not a verdict on whether the signer is trustworthy.";

    private static readonly TimeSpan GatekeeperTimeout = TimeSpan.FromSeconds(20);

    private static readonly TimeSpan MinimumCommandTime = TimeSpan.FromSeconds(1);

    internal Func<string, string> Resolve { get; init; } = StartupPermissions.RealPath;

    /// <summary>How long one call may spend; 200 codesign runs over large bundles can take minutes.</summary>
    internal TimeSpan Deadline { get; init; } = TimeSpan.FromSeconds(120);

    public async Task<SignatureQueryResult> InspectAsync(IReadOnlyList<string> paths, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(paths);
        if (paths.Count == 0)
        {
            throw new ArgumentException("Pass at least one full path.", nameof(paths));
        }

        if (paths.Count > MaxPaths)
        {
            throw new ArgumentException(
                $"{paths.Count:N0} paths is more than one call inspects; pass at most {MaxPaths} and call again for the rest.", nameof(paths));
        }

        var notFound = new List<string>();
        var wanted = new List<(string Full, string Real)>();
        foreach (var path in paths)
        {
            if (StatLines.HasControlCharacter(path) || MacPaths.Lexical(path) is not { } full)
            {
                notFound.Add(path);
                continue;
            }

            try
            {
                wanted.Add((full, Resolve(full)));
            }
            catch (Exception ex) when (ex is IOException or ArgumentException or NotSupportedException or UnauthorizedAccessException)
            {
                notFound.Add($"{path} ({ex.Message})");
            }
        }

        var stats = await StatLines.StatAsync(commands, wanted.Select(w => w.Real), options.ExternalToolTimeout, cancellationToken).ConfigureAwait(false);

        var files = new List<FileSignature>();
        var notInspected = new List<string>();
        var clock = Stopwatch.StartNew();

        // Every command gets at most what is left of the call's budget, so the file in flight cannot outrun it.
        TimeSpan Left() => Min(options.ExternalToolTimeout, Max(Deadline - clock.Elapsed, MinimumCommandTime));

        foreach (var (full, real) in wanted)
        {
            if (!stats.TryGetValue(real, out var stat))
            {
                notFound.Add(full);
                continue;
            }

            // Only regular files are handed to anything that opens them: a FIFO blocks, and a device can be anything.
            if (stat.Kind != StatKind.File)
            {
                notFound.Add($"{full} (not a regular file)");
                continue;
            }

            if (clock.Elapsed >= Deadline)
            {
                notInspected.Add(full);
                continue;
            }

            var hash = await RunAsync("shasum", ["-a", "256", real], Left(), cancellationToken).ConfigureAwait(false);
            if (hash.ExitCode != 0 || hash.StandardOutput.Split(' ', 2)[0] is not { Length: 64 } digest)
            {
                notFound.Add(hash.StandardError.Contains("Permission denied", StringComparison.OrdinalIgnoreCase)
                    ? $"{full} (permission denied)"
                    : $"{full} ({FirstLine(hash.StandardError, "could not be read")})");
                continue;
            }

            files.Add(await SignatureAsync(full, real, stat, digest.ToUpperInvariant(), Left, cancellationToken).ConfigureAwait(false));
        }

        var limitation = TrustNote;
        if (notInspected.Count > 0)
        {
            limitation += $" {notInspected.Count} {(notInspected.Count == 1 ? "file was" : "files were")} not inspected: the call's time budget " +
                          $"({Deadline.TotalSeconds:0} s) was spent. Call again for {string.Join(", ", notInspected)}.";
        }

        return new SignatureQueryResult(files, notFound, limitation);
    }

    private async Task<FileSignature> SignatureAsync(
        string full, string real, StatLine stat, string sha256, Func<TimeSpan> left, CancellationToken cancellationToken)
    {
        var verify = await RunAsync("codesign", ["--verify", "--strict", "--", real], left(), cancellationToken).ConfigureAwait(false);
        var display = await RunAsync("codesign", ["-dvvv", "--", real], left(), cancellationToken).ConfigureAwait(false);
        var details = CodesignDisplay.Details(display.StandardError);

        var (verdict, detail) = verify switch
        {
            { ExitCode: 0 } when details.AdHoc => (SignatureVerdict.AdHoc, "Signed ad hoc: no identity vouches for it"),
            { ExitCode: 0 } when details.SignedByApple => (SignatureVerdict.Valid, "Signed by Apple, verified"),
            { ExitCode: 0 } when details.Authorities.Count > 0 =>
                (SignatureVerdict.Valid, $"Signed by {details.Authorities[0]}{(details.TeamId is { } team ? $" (team {team})" : string.Empty)}, verified"),
            { ExitCode: 0 } => (SignatureVerdict.Valid, "Signed, verified"),
            _ when verify.StandardError.Contains("code object is not signed at all", StringComparison.Ordinal) => (SignatureVerdict.Unsigned, "Not signed"),
            { ExitCode: 1 or 3 } => (SignatureVerdict.Invalid, $"Signature does NOT verify: {Reason(verify.StandardError, real)}"),
            _ => (SignatureVerdict.Unknown, $"codesign could not judge it (exit {verify.ExitCode}): {Reason(verify.StandardError, real)}"),
        };

        var receipt = await RunAsync("pkgutil", ["--file-info", real], left(), cancellationToken).ConfigureAwait(false);
        var (package, version) = receipt.ExitCode == 0 ? PkgutilFileInfo.Parse(receipt.StandardOutput) : (null, null);

        return new FileSignature(
            full, verdict, detail, real == full ? null : real, details.Identifier, details.TeamId, details.Authorities, details.HardenedRuntime,
            await GatekeeperAsync(real, left, cancellationToken).ConfigureAwait(false), package, version, stat.Size,
            DateTimeOffset.FromUnixTimeSeconds(stat.ModifiedEpoch), sha256);
    }

    /// <summary>spctl's verdict on the app bundle the file belongs to; a bare tool has no Gatekeeper assessment to give.</summary>
    private async Task<string> GatekeeperAsync(string path, Func<TimeSpan> left, CancellationToken cancellationToken)
    {
        if (AppBundle(path) is not { } app)
        {
            return "not applicable";
        }

        var result = await RunAsync("spctl", ["--assess", "--type", "execute", "-v", app], Min(GatekeeperTimeout, left()), cancellationToken).ConfigureAwait(false);
        return result.ExitCode switch
        {
            0 => "accepted" + (Source(result.StandardError) is { } source ? $" ({source})" : string.Empty),
            3 => $"rejected: {Reason(result.StandardError, app)}",
            _ => $"not assessed: {Reason(result.StandardError, app)}",
        };
    }

    /// <summary>One command, whose failure to finish costs this file's answer, never the call's.</summary>
    /// <remarks>The runner throws when a program outlives its timeout or cannot be started; a slow online
    /// notarization check, or a file swapped for a FIFO after the hash, would otherwise discard every result.
    /// Exit -1 marks it, with the reason where the program's own complaint would be.</remarks>
    private async Task<ExternalResult> RunAsync(string program, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken)
    {
        try
        {
            return await commands.RunAsync(program, arguments, timeout, cancellationToken).ConfigureAwait(false);
        }
        catch (ExternalCommandException ex)
        {
            return new ExternalResult(-1, string.Empty, $"{program} did not finish: {ex.Message}");
        }
    }

    private static TimeSpan Min(TimeSpan a, TimeSpan b) => a < b ? a : b;

    private static TimeSpan Max(TimeSpan a, TimeSpan b) => a > b ? a : b;

    /// <summary>The outermost .app the path is, or is inside.</summary>
    internal static string? AppBundle(string path)
    {
        var index = path.IndexOf(".app/", StringComparison.OrdinalIgnoreCase);
        return index >= 0 ? path[..(index + 4)]
            : path.EndsWith(".app", StringComparison.OrdinalIgnoreCase) ? path
            : null;
    }

    private static string? Source(string standardError) =>
        standardError.Split('\n').Select(l => l.Trim()).FirstOrDefault(l => l.StartsWith("source=", StringComparison.Ordinal))?["source=".Length..];

    /// <summary>The first line of a tool's complaint, without the path it starts by repeating.</summary>
    private static string Reason(string standardError, string path)
    {
        var line = FirstLine(standardError, "no reason given");
        return line.StartsWith(path + ": ", StringComparison.Ordinal) ? line[(path.Length + 2)..] : line;
    }

    private static string FirstLine(string text, string fallback) =>
        text.Split('\n').Select(l => l.Trim()).FirstOrDefault(l => l.Length > 0) ?? fallback;
}
