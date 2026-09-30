using LinuxDiag.Mcp.Configuration;
using LinuxDiag.Mcp.Diagnostics.Services;
using LinuxDiag.Mcp.Linux.External;
using LinuxDiag.Mcp.Linux.Parsers;

namespace LinuxDiag.Mcp.Diagnostics.Journal;

public sealed class LinuxJournalInspector : IJournalInspector
{
    private readonly IExternalCommand _commands;
    private readonly IServiceInspector _services;
    private readonly LinuxDiagOptions _options;
    private readonly Func<DateTimeOffset> _now;

    public LinuxJournalInspector(IExternalCommand commands, IServiceInspector services, LinuxDiagOptions options)
        : this(commands, services, options, () => DateTimeOffset.UtcNow)
    {
    }

    internal LinuxJournalInspector(IExternalCommand commands, IServiceInspector services, LinuxDiagOptions options, Func<DateTimeOffset> now)
    {
        _commands = commands;
        _services = services;
        _options = options;
        _now = now;
    }

    public async Task<EventQueryResult> QueryAsync(
        string? unit, int minutes, string[]? levels, string? provider, string[]? match, int maxEvents,
        CancellationToken cancellationToken)
    {
        if (minutes < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(minutes), minutes, "Look-back must be at least one minute.");
        }

        var checkedUnit = unit is null ? null : ServiceNames.CheckUnit(unit, nameof(unit));
        var checkedProvider = provider is null ? null : ExternalArgument.Check(provider, nameof(provider));
        var matches = (match ?? []).Select(JournalQuery.Match).ToList();
        var priorities = JournalQuery.Priorities(levels);
        var limit = Math.Clamp(maxEvents, 1, _options.MaxResults);

        var result = await _commands.RunAsync(
            "journalctl",
            JournalQuery.Arguments(checkedUnit, _now().AddMinutes(-minutes), priorities, checkedProvider, matches, limit + 1),
            _options.ExternalToolTimeout,
            cancellationToken).ConfigureAwait(false);
        if (result.ExitCode != 0)
        {
            throw new ExternalCommandException($"journalctl failed: {LinuxServiceInspector.FirstLine(result.StandardError)}");
        }

        var (entries, skipped) = JournalJson.Parse(result.StandardOutput);
        var wanted = priorities.ToHashSet();
        var events = entries
            .Where(e => wanted.Contains(e.Priority))
            .Take(limit)
            .Select(e => new EventEntry(e.Time, LevelName(e.Priority), e.Priority, e.Identifier ?? e.Command ?? "(unknown)", e.Unit, e.Message, e.ProcessId))
            .ToList();

        var limitations = new List<string>();
        if (result.StandardError.Contains("not seeing messages from other users", StringComparison.Ordinal))
        {
            limitations.Add("The server is not root and not in the systemd-journal or adm group, so only this account's own records are visible.");
        }

        if (skipped > 0)
        {
            limitations.Add($"{skipped} journal records could not be read and were left out.");
        }

        IReadOnlyList<string> candidates = [];
        if (events.Count == 0 && checkedUnit is not null)
        {
            try
            {
                var query = await _services.QueryAsync(checkedUnit, cancellationToken).ConfigureAwait(false);
                candidates = query.Service is null ? query.Candidates : [];
            }
            catch (ArgumentException)
            {
                // Not a service -- a timer or a scope -- so there are no service names to suggest.
            }
        }

        return new EventQueryResult(checkedUnit, minutes, events, entries.Count > limit, candidates, limitations);
    }

    internal static string LevelName(int priority) => priority switch
    {
        <= 2 => "Critical",
        3 => "Error",
        4 => "Warning",
        <= 6 => "Information",
        _ => "Verbose",
    };
}
