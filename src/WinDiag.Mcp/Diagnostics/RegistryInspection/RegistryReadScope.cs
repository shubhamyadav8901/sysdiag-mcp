using Microsoft.Win32;

namespace WinDiag.Mcp.Diagnostics.RegistryInspection;

/// <summary>
/// Which parts of the registry registry_read reaches without the arbitrary-read grant.
/// </summary>
/// <remarks>
/// <para>registry_read is registered under every grant, read-only included, and runs as the server's account,
/// usually SYSTEM. Without this it read HKLM\SAM, HKLM\SECURITY and every loaded user's hive for any token
/// holder -- while get_file needed the arbitrary-read grant for an ordinary file, and the README said a
/// read-only server could not read a single config file. So the same grant now gates the hives that hold
/// other accounts' secrets.</para>
/// <para>A denylist, not an allowlist: HKLM\SOFTWARE, HKLM\SYSTEM, HKCR and HKCC are what this tool is for, and
/// the parts that are not are few and fixed. HKU is the exception, read by SID: the well-known service
/// accounts and the server's own hive are allowed, and any other user's is not.</para>
/// </remarks>
internal static class RegistryReadScope
{
    private static readonly HashSet<string> MachineSecretHives = new(StringComparer.OrdinalIgnoreCase)
    {
        "SAM", "SECURITY"
    };

    /// <summary>LocalSystem, LocalService and NetworkService, and the default profile.</summary>
    private static readonly HashSet<string> ServiceAccountHives = new(StringComparer.OrdinalIgnoreCase)
    {
        ".DEFAULT", "S-1-5-18", "S-1-5-19", "S-1-5-20"
    };

    /// <param name="ownSid">The server account's SID, whose own hive is always readable; null if unknown.</param>
    /// <exception cref="RegistryQueryException">The key is outside what this server may read.</exception>
    public static void RequireReadable(RegistryHive hive, string subKey, bool allowArbitraryRead, string? ownSid)
    {
        if (allowArbitraryRead)
        {
            return;
        }

        // Leading separators trimmed: "HKLM\\SAM" splits to "\SAM", which must not walk past the check.
        var first = subKey.TrimStart('\\').Split('\\', 2)[0];
        if (first.Length == 0)
        {
            return;
        }

        var refused = hive switch
        {
            RegistryHive.LocalMachine => MachineSecretHives.Contains(first),
            RegistryHive.Users => !IsServiceOrOwnHive(first, ownSid),
            _ => false
        };

        if (refused)
        {
            throw new RegistryQueryException(
                $"Refusing to read '{Describe(hive)}\\{subKey}'. HKLM\\SAM, HKLM\\SECURITY and other users' hives " +
                "under HKU hold other accounts' secrets, so they are readable only with the arbitrary-read grant " +
                "(--allow-arbitrary-read, WINDIAG_ALLOW_ARBITRARY_READ=1) -- the same one get_file needs outside " +
                "this server's own directories. Nothing was read.");
        }
    }

    private static bool IsServiceOrOwnHive(string sidKey, string? ownSid)
    {
        // Each loaded profile has a second hive, <sid>_Classes, holding the same user's file associations.
        var sid = sidKey.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase) ? sidKey[..^"_Classes".Length] : sidKey;

        return ServiceAccountHives.Contains(sid)
               || (ownSid is not null && string.Equals(sid, ownSid, StringComparison.OrdinalIgnoreCase));
    }

    private static string Describe(RegistryHive hive) => hive switch
    {
        RegistryHive.LocalMachine => "HKLM",
        RegistryHive.Users => "HKU",
        RegistryHive.CurrentUser => "HKCU",
        RegistryHive.ClassesRoot => "HKCR",
        RegistryHive.CurrentConfig => "HKCC",
        _ => hive.ToString()
    };
}
