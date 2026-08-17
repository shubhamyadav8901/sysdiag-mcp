using System.Text.Json;
using System.Text.Json.Serialization;

namespace WinDiag.Mcp.Relay;

/// <summary>One target to pre-connect at launch: its alias, address, token and optional port.</summary>
internal sealed record RelayTargetEntry(string? As, string Target, string Token, int? Port);

/// <summary>
/// Reads the optional targets file the relay pre-connects at startup.
/// </summary>
/// <remarks>
/// <para>The relay's tool list is dynamic, but this client fixes the callable tool set when it first
/// enumerates the server -- a target connected later, mid-session, is not picked up until a reload, and
/// a reload restarts the relay and drops the connection. So targets listed here are connected <em>before</em>
/// the stdio host starts answering, which puts each target's <c>alias__tool</c> tools in the very first
/// <c>tools/list</c>. Changing the fleet is an edit to this file plus a fresh session, never a change to
/// the MCP registration -- the addresses still live in data, not configuration.</para>
/// <para>One shape, one path: a JSON object with a <c>targets</c> array at
/// <c>%USERPROFILE%\.windiag-targets.json</c>. A missing file means "pre-connect nothing"; a malformed
/// one is logged and treated the same, so a typo never costs the operator the control tools.</para>
/// </remarks>
internal static class RelayTargetsFile
{
    public const string FileName = ".windiag-targets.json";

    /// <summary>The single path the relay looks for the targets file at.</summary>
    public static string DefaultPath() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), FileName);

    /// <summary>Loads and validates the targets file, or null when it does not exist.</summary>
    /// <exception cref="RelayException">The file exists but is not valid, so the caller can log it.</exception>
    public static IReadOnlyList<RelayTargetEntry>? Load(string path)
    {
        if (!File.Exists(path))
        {
            return null;
        }

        return Parse(File.ReadAllText(path));
    }

    /// <summary>Parses the targets-file JSON, validating that every entry has a target and a token.</summary>
    public static IReadOnlyList<RelayTargetEntry> Parse(string json)
    {
        RelayTargetsDocument? document;
        try
        {
            document = JsonSerializer.Deserialize<RelayTargetsDocument>(json, JsonOptions);
        }
        catch (JsonException ex)
        {
            throw new RelayException($"the targets file is not valid JSON: {ex.Message}", ex);
        }

        if (document?.Targets is not { } targets)
        {
            throw new RelayException(
                "the targets file must be a JSON object with a \"targets\" array, for example " +
                "{\"targets\":[{\"as\":\"w11\",\"target\":\"192.168.32.93\",\"token\":\"...\"}]}.");
        }

        var result = new List<RelayTargetEntry>(targets.Count);
        for (var i = 0; i < targets.Count; i++)
        {
            var entry = targets[i];
            if (string.IsNullOrWhiteSpace(entry.Target) || string.IsNullOrWhiteSpace(entry.Token))
            {
                throw new RelayException($"targets[{i}] needs both a \"target\" and a \"token\".");
            }

            result.Add(new RelayTargetEntry(
                As: string.IsNullOrWhiteSpace(entry.As) ? null : entry.As.Trim(),
                Target: entry.Target.Trim(),
                Token: entry.Token,
                Port: entry.Port));
        }

        return result;
    }

    /// <summary>
    /// Adds or replaces one target in the file, keeping every other entry, so a target connected at
    /// runtime survives a relay restart and is pre-connected next launch.
    /// </summary>
    /// <remarks>
    /// A matching alias is replaced (a repoint), otherwise the target is appended. The file is parsed
    /// first, not blindly appended to, so a malformed file throws here rather than being overwritten
    /// with a half-file that would lose whatever it already held.
    /// </remarks>
    public static void Upsert(string path, RelayTargetEntry entry)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(entry.As);

        var entries = File.Exists(path)
            ? new List<RelayTargetEntry>(Parse(File.ReadAllText(path)))
            : new List<RelayTargetEntry>();

        var index = entries.FindIndex(e => string.Equals(e.As, entry.As, StringComparison.OrdinalIgnoreCase));
        if (index >= 0)
        {
            entries[index] = entry;
        }
        else
        {
            entries.Add(entry);
        }

        File.WriteAllText(path, Serialize(entries));
    }

    private static string Serialize(IReadOnlyList<RelayTargetEntry> entries)
    {
        var document = new RelayTargetsDocument
        {
            Targets = entries
                .Select(e => new RelayTargetEntryDto { As = e.As, Target = e.Target, Token = e.Token, Port = e.Port })
                .ToList()
        };

        return JsonSerializer.Serialize(document, WriteOptions);
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true
    };

    private static readonly JsonSerializerOptions WriteOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private sealed class RelayTargetsDocument
    {
        public List<RelayTargetEntryDto>? Targets { get; set; }
    }

    private sealed class RelayTargetEntryDto
    {
        public string? As { get; set; }
        public string? Target { get; set; }
        public string? Token { get; set; }
        public int? Port { get; set; }
    }
}
