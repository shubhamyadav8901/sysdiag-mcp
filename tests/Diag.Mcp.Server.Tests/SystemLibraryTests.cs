using System.Reflection;
using System.Runtime.Loader;
using Diag.Mcp.Server.Files;

namespace Diag.Mcp.Server.Tests;

public sealed class SystemLibraryTests
{
    [Fact]
    public void The_c_library_is_glibcs_soname_on_linux_and_libsystems_absolute_path_on_macos()
    {
        // macOS has no libc.so.6: loading it throws DllNotFoundException on the first call. libSystem lives in
        // the dyld shared cache, which NativeLibrary.Load accepts by this path.
        Assert.Equal("libc.so.6", SystemLibrary.LibraryFor(isMacOS: false));
        Assert.Equal("/usr/lib/libSystem.B.dylib", SystemLibrary.LibraryFor(isMacOS: true));
    }

    [Fact]
    public void Registering_the_resolver_twice_for_one_assembly_is_harmless()
    {
        // LinuxNoFollow and MacNoFollow share the kit's assembly and each registers from its static
        // constructor; the runtime throws on a second SetDllImportResolver for one assembly.
        // A fresh runtime copy of this assembly in its own load context: one no resolver was ever set on.
        var context = new AssemblyLoadContext($"reg-{Guid.NewGuid():N}", isCollectible: true);
        var assembly = context.LoadFromAssemblyPath(typeof(SystemLibraryTests).Assembly.Location);

        SystemLibrary.RegisterFor(assembly);
        SystemLibrary.RegisterFor(assembly);
        context.Unload();
    }
}
