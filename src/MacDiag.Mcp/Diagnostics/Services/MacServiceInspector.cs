using System.Globalization;
using MacDiag.Mcp.Configuration;
using MacDiag.Mcp.Mac.Launchd;
using MacDiag.Mcp.Mac.Parsers;

namespace MacDiag.Mcp.Diagnostics.Services;

/// <summary>A launchd job's runtime state from launchctl print, and its configuration from its plist.</summary>
/// <remarks>
/// launchctl print is documented by Apple as unstable, so it is read only for what nothing else says -- state, PID,
/// last exit, run count -- and only its top-level keys. Everything the job is configured to do comes from the plist.
/// </remarks>
public sealed class MacServiceInspector(IExternalCommand commands, MacDiagOptions options) : IServiceInspector
{
    private const int MaxCandidates = 15;

    internal LaunchdPlists Plists { get; init; } = new();

    public async Task<ServiceQueryResult> QueryAsync(string label, CancellationToken cancellationToken)
    {
        LaunchdLabel.Check(label, nameof(label));
        var limitations = new List<string>();

        var (domain, state) = await PrintAsync($"system/{label}", cancellationToken).ConfigureAwait(false) is { } system
            ? ("system", system)
            : ("system", (LaunchdJobState?)null);
        var plistPath = state?.Path;

        if (state is null)
        {
            plistPath = await Plists.FindAsync(commands, label, [.. LaunchdPlists.DaemonDirectories, .. LaunchdPlists.AgentDirectories], cancellationToken)
                .ConfigureAwait(false);
            if (plistPath is null)
            {
                return new ServiceQueryResult(label, null, await CandidatesAsync(label, cancellationToken).ConfigureAwait(false));
            }

            if (LaunchdPlists.IsAgent(plistPath))
            {
                var uid = await ConsoleUserAsync(cancellationToken).ConfigureAwait(false);
                if (uid is > 0)
                {
                    domain = $"gui/{uid}";
                    state = await PrintAsync($"{domain}/{label}", cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    domain = "gui";
                    limitations.Add("A LaunchAgent with no user logged in at the console: its per-user state is not read.");
                }
            }
        }
        else if (state.Missing.Count > 0)
        {
            limitations.Add($"launchctl print did not report: {string.Join(", ", state.Missing)}.");
        }

        PlistDictionary? plist = null;
        if (plistPath is not null)
        {
            try
            {
                plist = await Plutil.ReadAsync(commands, plistPath, options.ExternalToolTimeout, cancellationToken).ConfigureAwait(false);
            }
            catch (ServiceQueryException ex)
            {
                limitations.Add(ex.Message);
            }
        }

        var arguments = plist?.Strings("ProgramArguments") ?? [];
        var disabled = await DisabledAsync(domain, label, cancellationToken).ConfigureAwait(false) ?? plist?.Bool("Disabled");
        var info = new ServiceInfo(
            label,
            domain,
            plistPath,
            state?.State ?? "not loaded",
            state?.ProcessId,
            state?.LastExitCode,
            state?.LastExitText,
            state?.Runs,
            plist?.String("Program") ?? arguments.FirstOrDefault() ?? state?.Program,
            arguments,
            plist?.Bool("RunAtLoad") ?? false,
            KeepAlive(plist),
            plist?.String("UserName") ?? (plistPath is not null && LaunchdPlists.IsAgent(plistPath) ? "the logged-in user" : "root"),
            disabled,
            limitations);
        return new ServiceQueryResult(label, info, []);
    }

    /// <summary>The job's state in one domain, or null when launchd does not have it there.</summary>
    private async Task<LaunchdJobState?> PrintAsync(string target, CancellationToken cancellationToken)
    {
        var result = await commands.RunAsync("launchctl", ["print", target], options.ExternalToolTimeout, cancellationToken).ConfigureAwait(false);
        return result.ExitCode == 0 ? LaunchctlPrint.State(result.StandardOutput) : null;
    }

    private async Task<int?> ConsoleUserAsync(CancellationToken cancellationToken)
    {
        var result = await commands.RunAsync("stat", ["-f", "%u", "/dev/console"], options.ExternalToolTimeout, cancellationToken).ConfigureAwait(false);
        return result.ExitCode == 0 && int.TryParse(result.StandardOutput.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var uid) ? uid : null;
    }

    private async Task<bool?> DisabledAsync(string domain, string label, CancellationToken cancellationToken)
    {
        if (domain == "gui")
        {
            return null;
        }

        var result = await commands.RunAsync("launchctl", ["print-disabled", domain], options.ExternalToolTimeout, cancellationToken).ConfigureAwait(false);
        return result.ExitCode == 0 && LaunchctlDisabled.Parse(result.StandardOutput).TryGetValue(label, out var value) ? value : null;
    }

    private async Task<IReadOnlyList<string>> CandidatesAsync(string query, CancellationToken cancellationToken)
    {
        var result = await commands.RunAsync("launchctl", ["list"], options.ExternalToolTimeout, cancellationToken).ConfigureAwait(false);
        return result.ExitCode != 0
            ? []
            : LaunchctlList.Parse(result.StandardOutput)
                .Select(row => row.Label)
                .Where(l => l.Contains(query, StringComparison.OrdinalIgnoreCase))
                .Distinct(StringComparer.Ordinal)
                .Order(StringComparer.Ordinal)
                .Take(MaxCandidates)
                .ToList();
    }

    private static string? KeepAlive(PlistDictionary? plist) =>
        plist?.Bool("KeepAlive") is { } flag ? (flag ? "true" : "false")
        : plist?.Dict("KeepAlive") is { } conditions
            ? "when: " + string.Join(", ", conditions.Select(c => $"{c.Key}={Describe(c.Value)}"))
            : null;

    private static string Describe(PlistValue value) => value switch
    {
        PlistBool b => b.Value ? "true" : "false",
        PlistString s => s.Value,
        PlistInteger i => i.Value.ToString(CultureInfo.InvariantCulture),
        _ => "…",
    };
}
