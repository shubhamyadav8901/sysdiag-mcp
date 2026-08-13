using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32;

namespace WinDiag.Mcp.Diagnostics.Access;

/// <summary>
/// Reads security descriptors and, separately, tries the access for real.
/// </summary>
/// <remarks>
/// Both halves are needed. The ACL explains <em>why</em>, but only an actual open answers
/// <em>whether</em> -- share modes, integrity levels, filter drivers and privileges all change the
/// outcome without being visible in any single ACE, which is why ACL-reading tools and reality
/// sometimes disagree.
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class WindowsAccessInspector : IAccessInspector
{
    public AccessReport Inspect(string path, string? account, bool probeWrite, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        cancellationToken.ThrowIfCancellationRequested();

        return IsRegistryPath(path)
            ? InspectRegistry(path, account)
            : InspectFileSystem(path, account, probeWrite);
    }

    internal static bool IsRegistryPath(string path) =>
        path.StartsWith("HKLM", StringComparison.OrdinalIgnoreCase)
        || path.StartsWith("HKCU", StringComparison.OrdinalIgnoreCase)
        || path.StartsWith("HKCR", StringComparison.OrdinalIgnoreCase)
        || path.StartsWith("HKU", StringComparison.OrdinalIgnoreCase)
        || path.StartsWith("HKEY_", StringComparison.OrdinalIgnoreCase);

    private AccessReport InspectFileSystem(string path, string? account, bool probeWrite)
    {
        var full = Path.GetFullPath(path);
        var isDirectory = Directory.Exists(full);

        if (!isDirectory && !File.Exists(full))
        {
            throw new AccessQueryException(
                $"'{full}' does not exist, so it has no security descriptor. Check the path, or use " +
                "who_locks_path if you expected a file that may have been moved or deleted.");
        }

        FileSystemSecurity security;
        try
        {
            security = isDirectory
                ? new DirectoryInfo(full).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner)
                : new FileInfo(full).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or PrivilegeNotHeldException)
        {
            throw new AccessQueryException(
                $"Not permitted to read the security descriptor of '{full}'. Reading an object's ACL " +
                "itself requires READ_CONTROL, which this account does not have here. Run the server " +
                "elevated.", ex);
        }

        var rules = ReadRules(security, typeof(NTAccount));

        return new AccessReport(
            Path: full,
            Kind: isDirectory ? SecurableKind.Directory : SecurableKind.File,
            Owner: ReadOwner(security),
            Rules: rules,
            Account: account,
            RulesForAccount: MatchAccount(rules, account),
            Probe: ProbeFileSystem(full, isDirectory, probeWrite),
            ProbeIdentity: CurrentIdentity());
    }

    private AccessReport InspectRegistry(string path, string? account)
    {
        var (hive, subKey) = SplitRegistryPath(path);

        using var root = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
        using var key = OpenRegistryKey(root, subKey, path);

        RegistrySecurity security;
        try
        {
            security = key.GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
            throw new AccessQueryException(
                $"Not permitted to read the security descriptor of '{path}'. Run the server elevated.", ex);
        }

        var rules = ReadRules(security, typeof(NTAccount));

        return new AccessReport(
            Path: path,
            Kind: SecurableKind.RegistryKey,
            Owner: ReadOwner(security),
            Rules: rules,
            Account: account,
            RulesForAccount: MatchAccount(rules, account),

            // The key opened for read above, so read access is already proven. Probing for write would
            // mean requesting write access to a live registry key, which this tool will not do.
            Probe: new AccessProbe(true, null, null, "Write access to registry keys is not probed."),
            ProbeIdentity: CurrentIdentity());
    }

    private static RegistryKey OpenRegistryKey(RegistryKey root, string subKey, string original)
    {
        try
        {
            return root.OpenSubKey(subKey, RegistryRights.ReadKey | RegistryRights.ReadPermissions)
                   ?? throw new AccessQueryException($"The registry key '{original}' does not exist.");
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
            throw new AccessQueryException(
                $"Access denied opening the registry key '{original}'. That is itself the answer to " +
                "'why is this denied' for the current account; run the server elevated to read its ACL.", ex);
        }
    }

    internal static (RegistryHive Hive, string SubKey) SplitRegistryPath(string path)
    {
        var separator = path.IndexOfAny(['\\', '/']);
        var hiveName = (separator < 0 ? path : path[..separator]).ToUpperInvariant();
        var subKey = separator < 0 ? string.Empty : path[(separator + 1)..].Replace('/', '\\');

        var hive = hiveName switch
        {
            "HKLM" or "HKEY_LOCAL_MACHINE" => RegistryHive.LocalMachine,
            "HKCU" or "HKEY_CURRENT_USER" => RegistryHive.CurrentUser,
            "HKCR" or "HKEY_CLASSES_ROOT" => RegistryHive.ClassesRoot,
            "HKU" or "HKEY_USERS" => RegistryHive.Users,
            _ => throw new AccessQueryException(
                $"'{hiveName}' is not a registry hive. Use HKLM, HKCU, HKCR or HKU, for example " +
                @"HKLM\SOFTWARE\Vendor\Product.")
        };

        return (hive, subKey);
    }

    private static List<AccessRule> ReadRules(NativeObjectSecurity security, Type targetType)
    {
        var rules = new List<AccessRule>();

        foreach (System.Security.AccessControl.AccessRule rule in security.GetAccessRules(true, true, targetType))
        {
            rules.Add(new AccessRule(
                Identity: rule.IdentityReference.Value,
                Rights: DescribeRights(rule),
                Type: rule.AccessControlType.ToString(),
                Inherited: rule.IsInherited));
        }

        // Deny entries first: they win over any grant, so listing them last would bury the reason.
        return rules
            .OrderByDescending(r => r.Type == nameof(AccessControlType.Deny))
            .ThenBy(r => r.Identity, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static string DescribeRights(System.Security.AccessControl.AccessRule rule) => rule switch
    {
        FileSystemAccessRule file => file.FileSystemRights.ToString(),
        RegistryAccessRule registry => registry.RegistryRights.ToString(),
        _ => "(unknown rights)"
    };

    private static List<AccessRule> MatchAccount(List<AccessRule> rules, string? account) =>
        string.IsNullOrWhiteSpace(account)
            ? []
            : rules.Where(r => r.Identity.Contains(account, StringComparison.OrdinalIgnoreCase)).ToList();

    private static string? ReadOwner(NativeObjectSecurity security)
    {
        try
        {
            return security.GetOwner(typeof(NTAccount))?.Value;
        }
        catch (Exception ex) when (ex is IdentityNotMappedException or InvalidOperationException)
        {
            return security.GetOwner(typeof(SecurityIdentifier))?.Value;
        }
    }

    /// <summary>Attempts the access for real, reporting the Win32 reason on failure.</summary>
    private static AccessProbe ProbeFileSystem(string path, bool isDirectory, bool probeWrite)
    {
        bool? canRead;
        string? readError = null;

        try
        {
            if (isDirectory)
            {
                _ = Directory.EnumerateFileSystemEntries(path).Take(1).ToArray();
            }
            else
            {
                using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            }

            canRead = true;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or System.Security.SecurityException)
        {
            canRead = false;
            readError = ex.Message;
        }

        if (!probeWrite)
        {
            return new AccessProbe(canRead, null, readError,
                "Write access was not probed. Pass probeWrite to test it.");
        }

        if (isDirectory)
        {
            // Testing write access to a directory would mean creating something in it. This tool does
            // not modify the machine, so the honest answer is that it was not tested.
            return new AccessProbe(canRead, null, readError,
                "Write access to a directory is not probed, because doing so would require creating a file.");
        }

        try
        {
            // FileMode.Open, not Create or Truncate: this acquires a write handle without altering a
            // single byte of the file.
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);
            return new AccessProbe(canRead, true, readError, null);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or System.Security.SecurityException)
        {
            return new AccessProbe(canRead, false, readError, ex.Message);
        }
    }

    private static string CurrentIdentity()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return identity.Name;
    }
}
