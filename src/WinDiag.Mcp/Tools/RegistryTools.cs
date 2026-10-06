using System.ComponentModel;
using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using ModelContextProtocol.Server;
using WinDiag.Mcp.Diagnostics.RegistryInspection;

namespace WinDiag.Mcp.Tools;

/// <summary>Structured result of <c>registry_read</c>.</summary>
public sealed record RegistryReadResult(string Summary, RegistryKeyContents Key);

/// <summary>What the registry actually says.</summary>
[McpServerToolType]
[SupportedOSPlatform("windows")]
public sealed class RegistryTools
{
    private readonly IRegistryInspector _registry;

    public RegistryTools(IRegistryInspector registry)
    {
        _registry = registry;
    }

    [McpServerTool(
        Name = "registry_read",
        Title = "Read a registry key",
        ReadOnly = true,
        Destructive = false,
        Idempotent = true,
        OpenWorld = true,
        UseStructuredContent = true)]
    [Description(
        "Read the values under a registry key, with their REG_* types, plus the names of its subkeys. " +
        "Use it to check what a setting is actually set to on this machine - a feature flag, an install " +
        "path, a policy value, the configuration a product read at startup - rather than what someone " +
        "believes it is set to. " +
        "Pass valueName for a single value, or omit it to see everything the key holds. " +
        "On 64-bit Windows the same path names two different keys: view defaults to 'native', what " +
        "regedit shows, and view='32' reads the WOW6432Node copy a 32-bit product writes to. The view " +
        "that was read is always stated in the result, because an answer that does not say is ambiguous. " +
        "This reads only. To find out why a key cannot be read, use effective_access on the same path. " +
        "HKLM\\SAM, HKLM\\SECURITY and other users' hives under HKU need the server's arbitrary-read grant, " +
        "and a value named like a credential (a *TOKEN, a password or a secret, including NAME=value entries " +
        "in a service's Environment) is always returned redacted, with its size.")]
    public RegistryReadResult RegistryRead(
        [Description(@"Key path, for example HKLM\SOFTWARE\Vendor\Product. HKLM, HKCU, HKCR, HKU and HKCC are accepted.")]
        string path,
        [Description("Return only this value. Use an empty string for the key's unnamed default value.")]
        string? valueName = null,
        [Description("'native' (default), '64', or '32' for the WOW6432Node view")]
        string? view = null,
        CancellationToken cancellationToken = default)
    {
        var contents = _registry.Read(path, valueName, view, cancellationToken);

        return new RegistryReadResult(Render(contents, valueName), contents);
    }

    internal static string Render(RegistryKeyContents contents, string? valueName)
    {
        var builder = new StringBuilder();

        // "view: x" rather than "[x view]": the descriptions are noun phrases, and gluing a word on
        // the end of one produced "[32-bit Windows, single view view]" on the target.
        builder.Append(RenderLimits.Printable(contents.Path)).Append("  [view: ").Append(RenderLimits.Printable(contents.View)).AppendLine("]");

        if (contents.Values.Count == 0)
        {
            builder.AppendLine("No values.");
        }
        else
        {
            foreach (var value in contents.Values.Take(RenderLimits.MaxRenderedRows))
            {
                // The unnamed default value has an empty name in the API; printing nothing there would
                // read as a blank line rather than as the default. Names and data are escaped: any user
                // can write a REG_SZ under HKCU, and a newline in one would otherwise start a line of
                // this summary that reads as the server's own.
                builder.Append("  ")
                    .Append(value.Name.Length == 0 ? "(Default)" : RenderLimits.Printable(value.Name))
                    .Append("  ").Append(RenderLimits.Printable(value.Kind))
                    .Append("  = ").Append(RenderLimits.Printable(value.Value));

                if (value.Truncated)
                {
                    builder.Append("  [truncated, ")
                        .Append(value.SizeBytes.ToString("N0", CultureInfo.InvariantCulture))
                        .Append(" bytes stored]");
                }

                builder.AppendLine();
            }

            RenderLimits.NoteElision(builder, contents.Values.Count, "returned values");
        }

        if (contents.SubKeyNames.Count > 0)
        {
            // Elided rather than joined wholesale: a key like HKCR carries tens of thousands of subkeys,
            // and at the current row cap this was one unwrapped line of well over a million characters.
            builder.Append(contents.TotalSubKeys)
                .Append(contents.TotalSubKeys == 1 ? " subkey: " : " subkeys: ")
                .AppendLine(RenderLimits.Join(contents.SubKeyNames.Select(n => RenderLimits.Printable(n)).ToList()));
        }
        else if (valueName is null)
        {
            builder.AppendLine("No subkeys.");
        }

        if (contents.Truncated)
        {
            builder.Append("Showing the first ").Append(contents.Values.Count).Append(" of ")
                .Append(contents.TotalValues).Append(" values and ").Append(contents.SubKeyNames.Count)
                .Append(" of ").Append(contents.TotalSubKeys)
                .AppendLine(" subkeys; raise WINDIAG_MAX_RESULTS or name a valueName.");
        }

        // Said on every 64-bit read, not only when something looks wrong: the failure mode here is
        // finding a plausible key in the wrong view and never questioning it.
        if (contents.View == "64-bit")
        {
            builder.Append("Read the 64-bit view. A 32-bit product's settings live under " +
                           "HKLM\\SOFTWARE\\WOW6432Node - pass view='32' to read those.");
        }

        return builder.ToString().TrimEnd();
    }
}
