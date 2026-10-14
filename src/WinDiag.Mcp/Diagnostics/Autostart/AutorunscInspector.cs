using WinDiag.Mcp.Configuration;
using WinDiag.Mcp.Diagnostics.External;

namespace WinDiag.Mcp.Diagnostics.Autostart;

/// <summary>Autostart audit backed by Sysinternals <c>autorunsc</c>.</summary>
/// <remarks>
/// The one shell-out here whose argument vector contains <strong>no caller-supplied element at all</strong>.
/// Autoruns has no name-filter switch, so filtering happens after parsing -- which turns the usual
/// injection question into a non-question rather than something to guard. Category letters are mapped
/// from a fixed table, so even those are server-authored.
/// </remarks>
public sealed class AutorunscInspector : IAutostartInspector
{
    internal const string BaseName = "autorunsc";

    /// <summary>autorunsc's <c>[user]</c> argument meaning every profile on the machine.</summary>
    internal const string AllUserProfiles = "*";

    private const string WrongArchitectureSymptom =
        "it enumerates the WOW64 view of the registry, so 64-bit services, drivers and Run keys are " +
        "simply absent from the report rather than reported as unreadable.";

    /// <summary>
    /// A wider budget than the global default, because this can outrun it.
    /// </summary>
    /// <remarks>
    /// Every category with signature verification means an Authenticode check per entry. Measured on a
    /// 32-bit Windows 10 VM, elevated: <c>-a * -s -u</c> took <strong>59s wall</strong> over roughly
    /// 600 entries. That fits inside the 120s global default with little room, and a machine with more
    /// installed -- or one checking revocation over a slow link -- would not. Ten minutes is chosen to
    /// be clearly past any plausible case rather than tuned to this one; the tool answers in a minute
    /// on the hardware it was measured on.
    /// </remarks>
    private static readonly TimeSpan VerificationBudget = TimeSpan.FromMinutes(10);

    private readonly IExternalToolRunner _runner;
    private readonly IToolLocator _locator;
    private readonly IPrivilegeProbe _privileges;
    private readonly WinDiagOptions _options;

    public AutorunscInspector(
        IExternalToolRunner runner,
        IToolLocator locator,
        IPrivilegeProbe privileges,
        WinDiagOptions options)
    {
        _runner = runner;
        _locator = locator;
        _privileges = privileges;
        _options = options;
    }

    public async Task<AutostartAuditResult> AuditAsync(
        AutostartQuery query,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);

        var verify = query.VerifySignatures || query.UnsignedOnly || query.HideMicrosoft;

        // Flags are pinned here and nowhere else, for the same reason handle.exe's are: the CSV column
        // set is flag-dependent -- -s inserts a Signer column -- so composing them at the call site
        // would let the parser and the output drift apart.
        //   -c  CSV
        //   -t  timestamps as normalised UTC; the default is a locale-formatted local time that
        //       cannot be read portably ("01-04-2024" is either 1 April or 4 January)
        //   -a  categories
        //   -s  verify signatures, which also adds the Signer column
        //   -m  hide entries that are signed AND Microsoft's
        //   -u  show only the unsigned ones
        //   *   the trailing user argument: every user profile, not only the account autorunsc runs
        //       as. Without it a LocalSystem service -- the normal deployment -- reported SYSTEM's own
        //       HKCU Run keys and Startup folder and nobody else's, while the summary called the list
        //       complete because the server was elevated. Elevation is what lets autorunsc load the
        //       hives of users who are logged off; unelevated it still reads the ones it can.
        var arguments = new List<ToolArgument>(9)
        {
            ToolArgument.Flag("-c"),
            ToolArgument.Flag("-t"),
            ToolArgument.Flag("-a"),
            ToolArgument.Flag(query.Categories)
        };

        if (verify)
        {
            arguments.Add(ToolArgument.Flag("-s"));
        }

        if (query.HideMicrosoft)
        {
            arguments.Add(ToolArgument.Flag("-m"));
        }

        if (query.UnsignedOnly)
        {
            arguments.Add(ToolArgument.Flag("-u"));
        }

        // Last, after every switch: autorunsc reads it positionally, as [user].
        arguments.Add(ToolArgument.Flag(AllUserProfiles));

        var executable = SysinternalsArchitecture.ResolveName(_locator, BaseName, WrongArchitectureSymptom);

        var policy = ExternalToolPolicy.UnicodeConsoleTool;
        if (verify && _options.ExternalToolTimeout < VerificationBudget)
        {
            policy = policy with { Timeout = VerificationBudget };
        }

        var result = await _runner
            .RunAsync(executable, arguments, policy, cancellationToken)
            .ConfigureAwait(false);

        var parsed = AutorunscCsvParser.Parse(result.StandardOutput);
        var entries = parsed.Entries;

        if (!string.IsNullOrWhiteSpace(query.NameFilter))
        {
            entries = entries.Where(e => Matches(e, query.NameFilter)).ToList();
        }

        var ordered = entries
            .OrderBy(e => e.Category, StringComparer.OrdinalIgnoreCase)
            .ThenBy(e => e.Entry, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var truncated = ordered.Count > _options.MaxResults;
        var page = truncated ? ordered.Take(_options.MaxResults).ToList() : ordered;

        return new AutostartAuditResult(
            Entries: page,
            TotalMatched: ordered.Count,
            Truncated: truncated,
            Elevated: _privileges.IsElevated,
            SignaturesVerified: verify,

            // Counted over the whole match, not the page: "3 unsigned" must not become "0 unsigned"
            // because the unsigned ones sorted past the row cap.
            UnsignedCount: ordered.Count(e => e.SignatureVerdict == "Not verified"),

            // Also counted over the whole match: an entry pointing at a file that is gone is a finding
            // in its own right, and it is invisible to the signature count because there is nothing
            // there to verify.
            MissingImageCount: ordered.Count(e => e.ImageMissing),

            // Not narrowed by the name filter: a broken record has no trustworthy name to filter on,
            // and the entry it hid may be exactly the one the filter was looking for.
            MalformedRowCount: parsed.MalformedRows);
    }

    /// <summary>
    /// Matches the fields someone would actually search by.
    /// </summary>
    /// <remarks>
    /// Deliberately wide: the caller may know the product name, the DLL, or the registry key, and
    /// which of those they have is exactly what they do not know when they start looking.
    /// </remarks>
    private static bool Matches(AutostartEntry entry, string filter) =>
        Contains(entry.Entry, filter)
        || Contains(entry.ImagePath, filter)
        || Contains(entry.Location, filter)
        || Contains(entry.Description, filter)
        || Contains(entry.Company, filter)
        || Contains(entry.LaunchString, filter);

    private static bool Contains(string? value, string filter) =>
        value is not null && value.Contains(filter, StringComparison.OrdinalIgnoreCase);
}
