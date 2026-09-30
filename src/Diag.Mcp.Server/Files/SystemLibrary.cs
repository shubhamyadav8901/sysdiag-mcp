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
/// <see cref="NativeLibrary.Load(string)"/> with a bare file name is a plain <c>dlopen</c>. That is not
/// "only the system paths": the host's RUNPATH, <c>$ORIGIN/netcoredeps</c>, is searched first. What
/// makes <c>libc.so.6</c> safe is that it is already mapped -- it is the host's own NEEDED dependency --
/// and <c>dlopen</c> matches an already-loaded object by soname before it searches anything. The name is
/// glibc's soname: a linux-x64 build targets glibc, the only Linux place <see cref="LinuxNoFollow"/>
/// is used.
/// </para>
/// <para>
/// A future import of a library the host has <em>not</em> already mapped gets no such shortcut. It is
/// protected only by the server-directory gate in <see cref="FileReceiver"/> keeping
/// <c>netcoredeps</c> unwritable without the self-update grant; better, load it by its absolute system
/// path.
/// </para>
/// <para>
/// The runtime accepts one resolver per assembly and throws on a second, so <see cref="RegisterFor"/>
/// remembers what it registered: the kit holds both <see cref="LinuxNoFollow"/> and <c>MacNoFollow</c>,
/// and each registers from the static constructor of the type that declares the import. An import in another
/// assembly registers it for that assembly the same way, which is why this type is public: each server's
/// own imports go through it. <c>NativeImportGuard</c> sweeps both servers'
/// assemblies for an import that does not.
/// </para>
/// </remarks>
public static class SystemLibrary
{
    /// <summary>The name the imports declare, and the only one this resolver answers for.</summary>
    public const string C = "libc";

    /// <summary>What <see cref="C"/> resolves to on Linux: glibc's soname, found by the system loader.</summary>
    public const string LinuxLibrary = "libc.so.6";

    /// <summary>What <see cref="C"/> resolves to on macOS: libSystem by its absolute path, from the dyld shared cache.</summary>
    /// <remarks>An absolute path is never searched for, so nothing beside the server can stand in for it.</remarks>
    public const string MacLibrary = "/usr/lib/libSystem.B.dylib";

    public static string LibraryFor(bool isMacOS) => isMacOS ? MacLibrary : LinuxLibrary;

    private static readonly HashSet<Assembly> Registered = [];

    /// <summary>Sets the resolver once per assembly; later calls are no-ops, because the runtime throws on a second set.</summary>
    public static void RegisterFor(Assembly assembly)
    {
        lock (Registered)
        {
            if (Registered.Add(assembly))
            {
                NativeLibrary.SetDllImportResolver(assembly, Resolve);
            }
        }
    }

    /// <summary>Returns zero for any other name, which leaves that import to the default probing.</summary>
    public static IntPtr Resolve(string libraryName, Assembly assembly, DllImportSearchPath? searchPath) =>
        libraryName == C ? NativeLibrary.Load(LibraryFor(OperatingSystem.IsMacOS())) : IntPtr.Zero;
}
