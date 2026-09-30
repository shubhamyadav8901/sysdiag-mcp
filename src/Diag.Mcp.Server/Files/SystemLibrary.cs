using System.Reflection;
using System.Runtime.InteropServices;

namespace Diag.Mcp.Server.Files;

/// <summary>Loads the C library the system loader would, never one found beside the server.</summary>
/// <remarks>
/// <para>
/// A plain <c>[DllImport("libc")]</c> is probed first in the host's native search directories -- the
/// application directory -- and then in the assembly's directory, before the system loader is asked at
/// all. So a <c>libc.so</c> dropped into <c>/opt/linuxdiag</c> would be mapped into a root process, and
/// <c>put_file</c> can write there.
/// </para>
/// <para>
/// <c>[DefaultDllImportSearchPaths]</c> without <c>AssemblyDirectory</c> looks like the fix and is not:
/// the runtime tries the host's native search directories before it consults that attribute, and for
/// this app they are the application directory. A resolver runs ahead of every probe, and
/// <see cref="NativeLibrary.Load(string)"/> with a bare file name is a plain <c>dlopen</c>, which
/// searches only the system paths. The name is glibc's soname: a linux-x64 build targets glibc, which is
/// the only place <see cref="LinuxNoFollow"/> is used.
/// </para>
/// <para>
/// The resolver is registered once per assembly, and a second registration throws, so it is registered
/// in one place: the static constructor of the type that declares the import. An import in another
/// assembly registers it for that assembly the same way. <c>NativeImportGuard</c> sweeps both servers'
/// assemblies for an import that does not.
/// </para>
/// </remarks>
internal static class SystemLibrary
{
    /// <summary>The name the imports declare, and the only one this resolver answers for.</summary>
    public const string C = "libc";

    /// <summary>What <see cref="C"/> resolves to: glibc's soname, found by the system loader.</summary>
    public const string CLibrary = "libc.so.6";

    public static void RegisterFor(Assembly assembly) => NativeLibrary.SetDllImportResolver(assembly, Resolve);

    /// <summary>Returns zero for any other name, which leaves that import to the default probing.</summary>
    public static IntPtr Resolve(string libraryName, Assembly assembly, DllImportSearchPath? searchPath) =>
        libraryName == C ? NativeLibrary.Load(CLibrary) : IntPtr.Zero;
}
