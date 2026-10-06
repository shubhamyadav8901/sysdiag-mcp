using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace WinDiag.Mcp.Diagnostics;

/// <summary>
/// Loads every DLL this assembly and the event log package import from System32 by absolute path, never
/// from beside the server.
/// </summary>
/// <remarks>
/// <para>
/// A plain <c>[DllImport("dbghelp.dll")]</c> is probed first in the host's native search directories --
/// for this self-contained app, the server's own folder -- before Windows' own search order is asked at
/// all. dbghelp, wintrust, rstrtmgr and iphlpapi are not KnownDLLs, so a copy dropped beside the server
/// was mapped into a SYSTEM process by the next <c>capture_dump</c>, <c>file_signatures</c>,
/// <c>who_locks_path</c> or <c>network_owners</c>.
/// </para>
/// <para>
/// <c>[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]</c> looks like the fix and is not: the
/// runtime tries the host's directories before it consults that attribute, which the kit's
/// <c>SystemLibrary</c> records for libc on Linux. A resolver runs ahead of every probe, and an absolute
/// path is never searched for; the loader also takes that DLL's own dependencies from its directory, not
/// the server's. Under WOW64 <see cref="Environment.SystemDirectory"/> is still <c>system32</c>, and the
/// file-system redirector sends a 32-bit server to SysWOW64, which is the right copy.
/// </para>
/// <para>
/// Registered by a module initializer rather than from each declaring type's static constructor, as the
/// kit does: the imports are spread over a dozen types here, and the runtime accepts one resolver per
/// assembly. <c>SystemDllImportTests</c> sweeps the assembly for an import this cannot serve.
/// </para>
/// <para>
/// The same probe order applies to a package's imports, so <c>System.Diagnostics.EventLog</c> -- the one
/// referenced package that imports a DLL outside KnownDLLs, <c>wevtapi.dll</c> for <c>event_log_tail</c> --
/// gets the resolver too. The runtime's own assemblies are not covered: their imports (crypt32, ncrypt and
/// the like) are probed the same way, and serving them all from here would mean owning every name the
/// framework loads. For those the boundary is the server folder itself: its ACL, and <c>put_file</c>
/// writing there only with the self-update grant.
/// </para>
/// </remarks>
internal static class System32Library
{
    /// <summary>The assemblies whose imports are served from System32.</summary>
    internal static Assembly[] Covered =>
        [typeof(System32Library).Assembly, typeof(System.Diagnostics.Eventing.Reader.EventLogQuery).Assembly];

    [ModuleInitializer]
    internal static void Register()
    {
        foreach (var assembly in Covered)
        {
            NativeLibrary.SetDllImportResolver(assembly, Resolve);
        }
    }

    /// <summary>Where <paramref name="libraryName"/> is loaded from, or a refusal for a name that is not a bare DLL.</summary>
    /// <remarks>
    /// A rooted name would come back from <see cref="Path.Combine(string, string)"/> unchanged, and a name
    /// without <c>.dll</c> is given variations by the runtime; either would hand the search back to
    /// whoever wrote the import. Checked by spelling, so the rule holds on any OS the tests run on.
    /// </remarks>
    internal static string PathFor(string libraryName, string systemDirectory)
    {
        if (libraryName.IndexOfAny(['\\', '/', ':']) >= 0 ||
            !libraryName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
        {
            throw new DllNotFoundException(
                $"'{libraryName}' is not a bare DLL file name, so it cannot be loaded from System32. " +
                "Every import served here names a Windows DLL, such as \"dbghelp.dll\".");
        }

        return Path.Combine(systemDirectory, libraryName);
    }

    private static IntPtr Resolve(string libraryName, Assembly assembly, DllImportSearchPath? searchPath) =>
        NativeLibrary.Load(PathFor(libraryName, Environment.SystemDirectory));
}
