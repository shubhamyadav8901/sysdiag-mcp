using System.Globalization;
using LinuxDiag.Mcp.Configuration;
using LinuxDiag.Mcp.Linux.External;
using LinuxDiag.Mcp.Linux.Parsers;

namespace LinuxDiag.Mcp.Diagnostics.Services;

public sealed class LinuxServiceInspector(IExternalCommand commands, LinuxDiagOptions options) : IServiceInspector
{
    internal static readonly string[] Properties =
    [
        "Id", "Names", "Description", "LoadState", "ActiveState", "SubState", "UnitFileState", "Type", "FragmentPath",
        "DropInPaths", "ExecStart", "MainPID", "User", "Restart", "NRestarts", "Result", "Requires", "Wants", "RequiredBy",
        "WantedBy", "ActiveEnterTimestamp", "ExecMainStatus", "BindsTo", "Requisite", "RequisiteOf", "BoundBy", "ConsistsOf",
        "DynamicUser", "LoadError",
    ];

    public async Task<ServiceQueryResult> QueryAsync(string name, CancellationToken cancellationToken)
    {
        var unit = ServiceNames.Normalise(name, nameof(name));
        var shown = await Systemctl(["show", "--timestamp=utc", "-p", string.Join(',', Properties), "--", unit], cancellationToken)
            .ConfigureAwait(false);

        var properties = SystemctlShow.Parse(shown).FirstOrDefault();
        if (properties is null || properties["LoadState"] == "not-found")
        {
            return new ServiceQueryResult(name, null, await CandidatesAsync(name, cancellationToken).ConfigureAwait(false));
        }

        return new ServiceQueryResult(name, ToInfo(properties), []);
    }

    public async Task<IReadOnlyList<string>> CandidatesAsync(string query, CancellationToken cancellationToken)
    {
        var loaded = await Systemctl(["list-units", "--all", "--type=service", "--plain", "--no-legend", "--no-pager"], cancellationToken)
            .ConfigureAwait(false);
        var installed = await Systemctl(["list-unit-files", "--type=service", "--plain", "--no-legend", "--no-pager"], cancellationToken)
            .ConfigureAwait(false);

        // list-units: UNIT LOAD ACTIVE SUB DESCRIPTION...; list-unit-files: UNIT STATE PRESET.
        var descriptions = new Dictionary<string, string?>(StringComparer.Ordinal);
        // A not-found row is a name another unit refers to; offering it would suggest a unit that does not exist.
        foreach (var fields in Lines(loaded).Select(l => l.Split(' ', 5, StringSplitOptions.RemoveEmptyEntries))
                     .Where(f => f.Length > 0 && !(f.Length > 1 && f[1] == "not-found")))
        {
            descriptions[fields[0]] = fields.Length == 5 ? fields[4] : null;
        }

        foreach (var fields in Lines(installed).Select(l => l.Split(' ', StringSplitOptions.RemoveEmptyEntries)).Where(f => f.Length > 0))
        {
            descriptions.TryAdd(fields[0], null);
        }

        var needle = query.Trim().EndsWith(".service", StringComparison.Ordinal) ? query.Trim()[..^8] : query.Trim();
        return descriptions
            .Where(d => d.Key.Contains(needle, StringComparison.OrdinalIgnoreCase) ||
                        d.Value?.Contains(needle, StringComparison.OrdinalIgnoreCase) == true)
            .OrderBy(d => d.Key, StringComparer.Ordinal)
            .Take(15)
            .Select(d => d.Value is null ? d.Key : $"{d.Key} ({d.Value})")
            .ToList();
    }

    /// <summary>systemctl with the server's bound, its standard output when it succeeds.</summary>
    internal async Task<string> Systemctl(IReadOnlyList<string> arguments, CancellationToken cancellationToken)
    {
        var result = await commands.RunAsync("systemctl", arguments, options.ExternalToolTimeout, cancellationToken).ConfigureAwait(false);
        return result.ExitCode == 0
            ? result.StandardOutput
            : throw new ExternalCommandException($"systemctl {arguments[0]} failed: {FirstLine(result.StandardError)}");
    }

    internal static ServiceInfo ToInfo(SystemdUnit unit)
    {
        var command = unit.All("ExecStart").Select(SystemctlShow.Command).FirstOrDefault(c => c is not null);
        return new ServiceInfo(
            unit["Id"] ?? "(unknown)",
            NullIfEmpty(unit["Description"]),
            $"{unit["ActiveState"]} ({unit["SubState"]})",
            NullIfEmpty(unit["UnitFileState"]) ?? "(none)",
            NullIfEmpty(unit["Type"]) ?? "(unknown)",
            command?.CommandLine,
            Account(unit),

            // What a stop takes down is the hard relations only: a unit that merely Wants this one keeps running.
            unit.List("Requires").Concat(unit.List("BindsTo")).Concat(unit.List("Requisite")).ToList(),
            unit.List("RequiredBy").Concat(unit.List("BoundBy")).Concat(unit.List("RequisiteOf")).Concat(unit.List("ConsistsOf")).ToList(),
            unit["LoadState"] ?? "(unknown)",
            Int(unit["MainPID"]) is int pid && pid > 0 ? pid : null,
            NullIfEmpty(unit["Restart"]),
            Int(unit["NRestarts"]) ?? 0,
            NullIfEmpty(unit["Result"]),
            NullIfEmpty(unit["FragmentPath"]),
            unit.List("DropInPaths"),
            Int(unit["ExecMainStatus"]),
            SystemctlShow.Timestamp(unit["ActiveEnterTimestamp"]),
            unit.List("Wants"),
            unit.List("WantedBy"),
            NullIfEmpty(unit["LoadError"]));
    }

    /// <summary>User=, or for DynamicUser=yes without one the name systemd derives from the unit; root otherwise.</summary>
    /// <remarks>An empty User= under DynamicUser is not root: reporting it as root is the wrong answer to "which account".</remarks>
    private static string Account(SystemdUnit unit)
    {
        if (NullIfEmpty(unit["User"]) is { } user)
        {
            return user;
        }

        var id = unit["Id"] ?? string.Empty;
        return unit["DynamicUser"] == "yes"
            ? $"dynamic user ({(id.EndsWith(".service", StringComparison.Ordinal) ? id[..^8] : id)})"
            : "root";
    }

    internal static string FirstLine(string text) =>
        text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).FirstOrDefault() ?? "(no message)";

    private static IEnumerable<string> Lines(string text) =>
        text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private static string? NullIfEmpty(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;

    private static int? Int(string? value) =>
        int.TryParse(value, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var number) ? number : null;
}
