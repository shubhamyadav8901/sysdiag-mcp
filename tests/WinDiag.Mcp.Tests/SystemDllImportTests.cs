using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using WinDiag.Mcp.Diagnostics;

namespace WinDiag.Mcp.Tests;

/// <summary>Every Windows DLL this server imports is loaded from System32, never from beside the server.</summary>
/// <remarks>
/// A bare <c>[DllImport("dbghelp.dll")]</c> is probed in the host's native search directories -- the
/// server's own folder -- before anything else, so a <c>dbghelp.dll</c> put there was mapped into a SYSTEM
/// process by the next <c>capture_dump</c>. The fix is a resolver for the whole assembly, and it is swept
/// rather than remembered: the next import in the next file is the one that would forget it.
/// </remarks>
public sealed class SystemDllImportTests
{
    private static readonly Assembly Server = typeof(ServerBuilder).Assembly;

    // System.Diagnostics.EventLog imports wevtapi.dll, which is not a KnownDLL either, and the runtime
    // probes the server's folder first for a package's imports exactly as it does for this assembly's.
    private static readonly Assembly EventLog = typeof(System.Diagnostics.Eventing.Reader.EventLogQuery).Assembly;

    private static MethodInfo[] Imports() => Imports(Server);

    private static MethodInfo[] Imports(Assembly assembly) => assembly.GetTypes()
        .SelectMany(type => type.GetMethods(
            BindingFlags.Static | BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic |
            BindingFlags.DeclaredOnly))
        .Where(method => method.Attributes.HasFlag(MethodAttributes.PinvokeImpl))
        .ToArray();

    [Fact]
    public void The_server_assembly_has_a_dll_import_resolver_registered()
    {
        Assert.NotEmpty(Imports());

        // The module initializer registers it. Once that has run, a second registration for the same
        // assembly must be refused -- that refusal is the only observable sign one is in place.
        RuntimeHelpers.RunModuleConstructor(Server.ManifestModule.ModuleHandle);

        var ex = Record.Exception(() => NativeLibrary.SetDllImportResolver(Server, (_, _, _) => IntPtr.Zero));

        Assert.True(
            ex is InvalidOperationException,
            "WinDiag.Mcp has no DllImport resolver, so its imports are probed in the server's own folder first.");
    }

    [Fact]
    public void The_event_log_package_has_the_same_resolver_registered()
    {
        RuntimeHelpers.RunModuleConstructor(Server.ManifestModule.ModuleHandle);

        var ex = Record.Exception(() => NativeLibrary.SetDllImportResolver(EventLog, (_, _, _) => IntPtr.Zero));

        Assert.True(
            ex is InvalidOperationException,
            "System.Diagnostics.EventLog has no DllImport resolver, so a wevtapi.dll beside the server is loaded by event_log_tail.");
    }

    [Fact]
    public void The_event_log_package_imports_wevtapi_and_nothing_the_resolver_cannot_serve()
    {
        // Windows only, like the rest of this suite: elsewhere the test host loads the package's
        // platform-neutral build, which imports nothing.
        var libraries = Imports(EventLog).Select(m => m.GetCustomAttribute<DllImportAttribute>()!.Value).Distinct().ToArray();

        Assert.Contains(libraries, name => name.Equals("wevtapi.dll", StringComparison.OrdinalIgnoreCase));
        foreach (var library in libraries)
        {
            Assert.Equal(Path.Combine(Environment.SystemDirectory, library), System32Library.PathFor(library, Environment.SystemDirectory));
        }
    }

    [Fact]
    public void Every_import_names_a_bare_dll_that_the_resolver_places_in_the_system_directory()
    {
        const string system = @"C:\Windows\system32";

        foreach (var method in Imports())
        {
            var library = method.GetCustomAttribute<DllImportAttribute>()!.Value;

            Assert.Equal(Path.Combine(system, library), System32Library.PathFor(library, system));
        }
    }

    [Theory]
    [InlineData(@"..\dbghelp.dll")]
    [InlineData(@"C:\WinDiag\dbghelp.dll")]
    [InlineData("dbghelp")]
    public void A_name_that_is_not_a_bare_dll_file_name_is_refused_rather_than_searched_for(string library)
    {
        // Path.Combine with a rooted second argument returns it unchanged, and a name without .dll is
        // given variations by the runtime: either would put the search back in the caller's hands.
        Assert.Throws<DllNotFoundException>(() => System32Library.PathFor(library, @"C:\Windows\system32"));
    }

    [Fact]
    public void Every_imported_dll_is_present_in_this_machines_system_directory()
    {
        foreach (var library in Imports().Select(m => m.GetCustomAttribute<DllImportAttribute>()!.Value).Distinct())
        {
            Assert.True(
                File.Exists(Path.Combine(Environment.SystemDirectory, library)),
                $"{library} is not in {Environment.SystemDirectory}; loading it only from there would break its tool.");
        }
    }
}
