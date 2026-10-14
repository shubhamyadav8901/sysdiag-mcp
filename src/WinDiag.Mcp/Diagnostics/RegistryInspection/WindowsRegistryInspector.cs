using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32;
using WinDiag.Mcp.Configuration;

namespace WinDiag.Mcp.Diagnostics.RegistryInspection;

/// <summary>Reads registry values through the managed registry API.</summary>
/// <remarks>
/// The gap this fills is narrow but real: <c>effective_access</c> answers who may read a key and
/// <c>service_config</c> reads the handful of service values it needs, but nothing could answer
/// "what does this key actually say". That question comes up constantly -- a feature flag, an
/// install path, a policy value someone swears is set -- and the alternative was asking a human to
/// open regedit on the target.
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class WindowsRegistryInspector : IRegistryInspector
{
    /// <summary>
    /// How much of a value to render.
    /// </summary>
    /// <remarks>
    /// A single REG_BINARY can hold megabytes -- some policy and certificate values do -- and the
    /// whole point of this server's output budgeting is that a tool cannot flood the caller. Truncated
    /// values still report their real size, so a large one is visible as large rather than as short.
    /// </remarks>
    private const int MaxRenderedChars = 512;

    private const int MaxBinaryPreviewBytes = 64;

    /// <summary>The server account's SID, whose own HKU hive needs no grant.</summary>
    private static readonly Lazy<string?> OwnSid =
        new(() => System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value);

    private readonly WinDiagOptions _options;

    public WindowsRegistryInspector(WinDiagOptions options)
    {
        _options = options;
    }

    public RegistryKeyContents Read(
        string path,
        string? valueName,
        string? view,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        cancellationToken.ThrowIfCancellationRequested();

        var (hive, subKey) = RegistryPath.Split(path);
        var registryView = RegistryPath.ParseView(view);

        // The SID is only consulted for HKU, so no other read pays for the identity lookup.
        RegistryReadScope.RequireReadable(
            hive, subKey, _options.AllowArbitraryRead, hive == RegistryHive.Users ? OwnSid.Value : null);

        using var root = RegistryKey.OpenBaseKey(hive, registryView);

        // Open returns `root` itself for a bare hive such as "HKCR", so ownership is tracked rather
        // than assumed: a second `using` over the same object would dispose the base key twice.
        var key = subKey.Length == 0 ? root : Open(root, subKey, path, registryView);

        List<RegistryValue> values;
        List<string> subKeyNames;

        try
        {
            values = ReadValues(key, valueName, path, cancellationToken);
            subKeyNames = ReadSubKeyNames(key);
        }
        finally
        {
            if (!ReferenceEquals(key, root))
            {
                key.Dispose();
            }
        }

        var truncated = values.Count > _options.MaxResults || subKeyNames.Count > _options.MaxResults;

        return new RegistryKeyContents(
            Path: path,
            View: RegistryPath.Describe(registryView),
            Values: values.Take(_options.MaxResults).ToList(),
            SubKeyNames: subKeyNames.Take(_options.MaxResults).ToList(),
            TotalValues: values.Count,
            TotalSubKeys: subKeyNames.Count,
            Truncated: truncated);
    }

    private static RegistryKey Open(RegistryKey root, string subKey, string path, RegistryView view)
    {
        try
        {
            return root.OpenSubKey(subKey, writable: false)
                   ?? throw new RegistryQueryException(
                       $"The registry key '{path}' does not exist in the " +
                       $"{RegistryPath.Describe(view)} view. " +

                       // Named because it is the most common cause of a key being "missing", and the
                       // caller cannot see the view from the path they typed.
                       (view == RegistryView.Registry64
                           ? "A 32-bit product writes under HKLM\\SOFTWARE\\WOW6432Node instead; call " +
                             "again with view='32' to look there."
                           : "Call again with view='native' to look in the 64-bit view."));
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException)
        {
            throw new RegistryQueryException(
                $"Access denied opening '{path}'. Run the server elevated, or call effective_access on " +
                "the same path to see which account is allowed to read it.", ex);
        }
        catch (IOException ex)
        {
            throw new RegistryQueryException($"Could not open '{path}': {ex.Message}", ex);
        }
    }

    private List<RegistryValue> ReadValues(
        RegistryKey key,
        string? valueName,
        string path,
        CancellationToken cancellationToken)
    {
        var names = valueName is null
            ? key.GetValueNames()
            : key.GetValueNames()
                .Where(n => n.Equals(valueName, StringComparison.OrdinalIgnoreCase))
                .ToArray();

        if (valueName is not null && names.Length == 0)
        {
            // Distinguished from an empty key: "the value is not set" and "the key holds nothing" lead
            // somewhere different, and the caller asked about one value.
            throw new RegistryQueryException(
                $"'{path}' exists but has no value named '{valueName}'. Call again without valueName " +
                "to list what it does have.");
        }

        var values = new List<RegistryValue>(names.Length);

        foreach (var name in names.OrderBy(n => n, StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();
            values.Add(Describe(key, name));
        }

        return values;
    }

    private static List<string> ReadSubKeyNames(RegistryKey key)
    {
        try
        {
            return [.. key.GetSubKeyNames().OrderBy(n => n, StringComparer.OrdinalIgnoreCase)];
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException)
        {
            // The values were readable and the subkeys were not, which is a real ACL shape. Returning
            // what was read beats failing the whole call.
            return [];
        }
    }

    private static RegistryValue Describe(RegistryKey key, string name)
    {
        // DoNotExpandEnvironmentNames: an expanded REG_EXPAND_SZ hides what is actually stored, and
        // the stored form is what someone comparing against a known-good machine needs to see.
        var kind = key.GetValueKind(name);
        var raw = key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);

        var (rendered, size) = RenderValue(name, raw);
        var truncated = rendered.Length > MaxRenderedChars;

        return new RegistryValue(
            Name: name,
            Kind: KindName(kind),
            Value: truncated ? rendered[..MaxRenderedChars] + "..." : rendered,
            Truncated: truncated,
            SizeBytes: size);
    }

    /// <summary>Renders a value for reading, with any credential in it redacted.</summary>
    /// <remarks>
    /// <para>Redacted here, before the value reaches the structured content, not in the summary: the summary is
    /// not the only thing a caller reads.</para>
    /// <para>Redacted under every grant. A windiag service keeps its bearer token in its own key's Environment
    /// value, and a second instance's token holder -- a read-only one beside a full one is a documented setup
    /// -- could otherwise read the full instance's token there and act with its authority. No diagnostic
    /// question needs a credential's value; whether one is set, and its size, stays visible.</para>
    /// </remarks>
    internal static (string Rendered, int SizeBytes) RenderValue(string name, object? raw)
    {
        var (rendered, size) = Render(raw);

        if (raw is string[] multi)
        {
            // An Environment block: NAME=value entries, one of which may be a token.
            return (string.Join(" | ", multi.Select(RedactEntry)), size);
        }

        if (raw is string or byte[] && IsCredentialName(name))
        {
            return ($"(redacted: {size} bytes stored; this server never returns a value named like a credential)", size);
        }

        return (rendered, size);
    }

    private static string RedactEntry(string entry)
    {
        var equals = entry.IndexOf('=', StringComparison.Ordinal);
        return equals > 0 && IsCredentialName(entry[..equals]) ? entry[..(equals + 1)] + "(redacted)" : entry;
    }

    /// <summary>A name that says its value is a credential: *TOKEN, or containing PASSWORD, PASSWD or SECRET.</summary>
    /// <remarks>
    /// Applied only to string and binary data. A DWORD such as DisablePasswordChange is a setting, and
    /// hiding it would hide the answer.
    /// </remarks>
    private static bool IsCredentialName(string name)
    {
        var trimmed = name.Trim();
        return trimmed.EndsWith("TOKEN", StringComparison.OrdinalIgnoreCase)
               || trimmed.Contains("PASSWORD", StringComparison.OrdinalIgnoreCase)
               || trimmed.Contains("PASSWD", StringComparison.OrdinalIgnoreCase)
               || trimmed.Contains("SECRET", StringComparison.OrdinalIgnoreCase);
    }

    private static (string Rendered, int SizeBytes) Render(object? raw) => raw switch
    {
        null => ("(no data)", 0),

        // Both decimal and hex: registry numbers are documented either way depending on who wrote the
        // documentation, and converting by hand is where a comparison goes wrong.
        int i => ($"{i} (0x{i:X})", sizeof(int)),
        long l => ($"{l} (0x{l:X})", sizeof(long)),

        string[] multi => (string.Join(" | ", multi), multi.Sum(s => (s.Length + 1) * 2)),

        byte[] bytes => (RenderBinary(bytes), bytes.Length),

        _ => (raw.ToString() ?? string.Empty, (raw.ToString()?.Length ?? 0) * 2)
    };

    private static string RenderBinary(byte[] bytes)
    {
        var preview = bytes.Take(MaxBinaryPreviewBytes).ToArray();
        var builder = new StringBuilder(preview.Length * 3 + 32);

        foreach (var b in preview)
        {
            builder.Append(b.ToString("X2", CultureInfo.InvariantCulture)).Append(' ');
        }

        if (bytes.Length > preview.Length)
        {
            builder.Append("... (")
                .Append(bytes.Length.ToString("N0", CultureInfo.InvariantCulture))
                .Append(" bytes total)");
        }

        return builder.ToString().TrimEnd();
    }

    /// <summary>The REG_* name, which is what documentation and regedit both use.</summary>
    private static string KindName(RegistryValueKind kind) => kind switch
    {
        RegistryValueKind.String => "REG_SZ",
        RegistryValueKind.ExpandString => "REG_EXPAND_SZ",
        RegistryValueKind.Binary => "REG_BINARY",
        RegistryValueKind.DWord => "REG_DWORD",
        RegistryValueKind.MultiString => "REG_MULTI_SZ",
        RegistryValueKind.QWord => "REG_QWORD",
        RegistryValueKind.None => "REG_NONE",
        _ => kind.ToString()
    };
}
