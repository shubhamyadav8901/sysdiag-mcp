using Microsoft.Win32;

namespace WinDiag.Mcp.Diagnostics;

/// <summary>Raised when a registry path cannot be understood.</summary>
public sealed class RegistryPathException : Exception, IDiagnosticException
{
    public RegistryPathException(string message) : base(message)
    {
    }
}

/// <summary>
/// Splits <c>HKLM\SOFTWARE\Vendor</c> into a hive and a subkey, and decides which registry view to
/// open it in.
/// </summary>
/// <remarks>
/// <para>Shared because two tools read the registry and a third writes about it, and the view question
/// is one they must answer the same way.</para>
/// <para><strong>The view is the part that bites.</strong> On 64-bit Windows the registry has two
/// parallel copies of parts of <c>HKLM\SOFTWARE</c> and <c>HKCR</c>, and which one a process sees
/// depends on the bitness of the process rather than on the path it asked for.
/// <c>RegistryView.Default</c> means "whatever this process is", so the win-x86 build silently reads
/// <c>HKLM\SOFTWARE\WOW6432Node\...</c> when asked for <c>HKLM\SOFTWARE\...</c> -- returning a real
/// key, with real values, that is not the one anybody meant. Nothing in the answer says so.</para>
/// <para>So the view is chosen explicitly and reported back. The default is the OS's own view, which
/// is what someone typing a path into regedit would see, and the caller can ask for the 32-bit view
/// deliberately when the question is about a 32-bit component.</para>
/// </remarks>
internal static class RegistryPath
{
    /// <summary>The view to use when the caller has not asked for one.</summary>
    /// <remarks>
    /// <c>Registry64</c> on a 64-bit OS regardless of this process's own bitness, so the win-x86 and
    /// win-x64 builds answer the same question. <c>Registry32</c> would be the wrong default even for
    /// the 32-bit build -- the caller is asking about the machine, not about the server.
    /// </remarks>
    public static RegistryView NativeView =>
        Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Registry32;

    public static bool IsRegistryPath(string path) =>
        path.StartsWith("HKLM", StringComparison.OrdinalIgnoreCase)
        || path.StartsWith("HKCU", StringComparison.OrdinalIgnoreCase)
        || path.StartsWith("HKCR", StringComparison.OrdinalIgnoreCase)
        || path.StartsWith("HKU", StringComparison.OrdinalIgnoreCase)
        || path.StartsWith("HKCC", StringComparison.OrdinalIgnoreCase)
        || path.StartsWith("HKEY_", StringComparison.OrdinalIgnoreCase);

    public static (RegistryHive Hive, string SubKey) Split(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        var trimmed = path.Trim();
        var separator = trimmed.IndexOfAny(['\\', '/']);
        var hiveName = (separator < 0 ? trimmed : trimmed[..separator]).ToUpperInvariant();
        var subKey = separator < 0 ? string.Empty : trimmed[(separator + 1)..].Replace('/', '\\');

        var hive = hiveName switch
        {
            "HKLM" or "HKEY_LOCAL_MACHINE" => RegistryHive.LocalMachine,
            "HKCU" or "HKEY_CURRENT_USER" => RegistryHive.CurrentUser,
            "HKCR" or "HKEY_CLASSES_ROOT" => RegistryHive.ClassesRoot,
            "HKU" or "HKEY_USERS" => RegistryHive.Users,
            "HKCC" or "HKEY_CURRENT_CONFIG" => RegistryHive.CurrentConfig,
            _ => throw new RegistryPathException(
                $"'{hiveName}' is not a registry hive. Use HKLM, HKCU, HKCR, HKU or HKCC, for example " +
                @"HKLM\SOFTWARE\Vendor\Product.")
        };

        return (hive, subKey.TrimEnd('\\'));
    }

    /// <summary>Maps the caller's word for a view onto the enum, or refuses it.</summary>
    /// <remarks>
    /// An explicit request for a view this machine does not have is refused rather than quietly
    /// honoured. Windows accepts <c>Registry64</c> on 32-bit Windows and ignores it, so silently
    /// accepting the request would return the only view under a label saying otherwise.
    /// </remarks>
    public static RegistryView ParseView(string? view)
    {
        var requested = view?.Trim().ToLowerInvariant() switch
        {
            null or "" or "native" or "default" => NativeView,
            "64" or "x64" or "registry64" => RegistryView.Registry64,
            "32" or "x86" or "wow64" or "registry32" => RegistryView.Registry32,
            _ => throw new RegistryPathException(
                $"'{view}' is not a registry view. Use 'native' (the default, matching what regedit " +
                "shows), '64', or '32' for the WOW6432Node view a 32-bit process sees.")
        };

        if (!Environment.Is64BitOperatingSystem && requested == RegistryView.Registry64)
        {
            throw new RegistryPathException(
                "This is 32-bit Windows, which has one registry rather than two -- there is no 64-bit " +
                "view to read. Omit view, or pass 'native'.");
        }

        return requested;
    }

    /// <summary>How to describe the view in a result, so an answer is never ambiguous about which it read.</summary>
    /// <remarks>
    /// The 32-bit-OS case is not cosmetic. There is no WOW6432Node on 32-bit Windows -- there is one
    /// registry -- so labelling its only view "WOW6432Node" tells a reader they are looking at the
    /// redirected copy of a key and sends them hunting for a real one that does not exist. Caught on
    /// the live 32-bit target, which reported exactly that for every key.
    /// </remarks>
    public static string Describe(RegistryView view)
    {
        if (!Environment.Is64BitOperatingSystem)
        {
            return "32-bit Windows, which has only one";
        }

        return view switch
        {
            RegistryView.Registry32 => "32-bit (WOW6432Node)",
            RegistryView.Registry64 => "64-bit",
            _ => "process default"
        };
    }
}
