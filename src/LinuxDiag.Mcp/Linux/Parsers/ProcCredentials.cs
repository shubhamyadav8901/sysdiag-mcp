using System.Globalization;

namespace LinuxDiag.Mcp.Linux.Parsers;

/// <param name="FsUserId">The filesystem uid: what the kernel checks file access against, which a setfsuid process can move away from the effective one.</param>
/// <param name="Groups">Supplementary groups, as the process holds them now.</param>
public sealed record ProcessCredentials(uint FsUserId, uint FsGroupId, IReadOnlyList<uint> Groups, ulong EffectiveCapabilities)
{
    public bool Has(int capability) => (EffectiveCapabilities & (1UL << capability)) != 0;
}

/// <summary>The credential lines of <c>/proc/&lt;pid&gt;/status</c>.</summary>
public static class ProcCredentials
{
    public const int CapDacOverride = 1;
    public const int CapDacReadSearch = 2;

    public static ProcessCredentials Parse(string status)
    {
        ArgumentNullException.ThrowIfNull(status);

        uint? fsUid = null, fsGid = null;
        ulong? capabilities = null;
        var groups = new List<uint>();
        foreach (var line in status.Split('\n'))
        {
            var colon = line.IndexOf(':', StringComparison.Ordinal);
            if (colon < 0)
            {
                continue;
            }

            var values = line[(colon + 1)..].Split(['\t', ' '], StringSplitOptions.RemoveEmptyEntries);
            switch (line[..colon])
            {
                // Real, effective, saved, filesystem.
                case "Uid" when values.Length == 4:
                    fsUid = uint.Parse(values[3], NumberStyles.None, CultureInfo.InvariantCulture);
                    break;
                case "Gid" when values.Length == 4:
                    fsGid = uint.Parse(values[3], NumberStyles.None, CultureInfo.InvariantCulture);
                    break;
                case "Groups":
                    groups.AddRange(values.Select(v => uint.Parse(v, NumberStyles.None, CultureInfo.InvariantCulture)));
                    break;
                case "CapEff" when values.Length == 1:
                    capabilities = ulong.Parse(values[0], NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture);
                    break;
            }
        }

        return fsUid is { } uid && fsGid is { } gid && capabilities is { } caps
            ? new ProcessCredentials(uid, gid, groups, caps)
            : throw new FormatException("The status text has no Uid, Gid or CapEff line.");
    }
}
