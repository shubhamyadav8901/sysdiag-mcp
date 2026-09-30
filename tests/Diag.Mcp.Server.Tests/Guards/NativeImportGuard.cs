using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Diag.Mcp.Server.Tests;

/// <summary>
/// Every P/Invoke into the C library goes through a resolver that loads it by its system name.
/// </summary>
/// <remarks>
/// A bare <c>[DllImport("libc")]</c> is probed in the application directory before the system loader
/// is asked -- the host's native search directories come first, whatever
/// <see cref="DefaultDllImportSearchPathsAttribute"/> says -- so a <c>libc.so</c> dropped beside a root
/// server would be loaded in place of the real one. The fix is a per-assembly resolver, and a resolver
/// is easy to forget on the next import in the next assembly. So the rule is swept, not remembered:
/// each import names the library the resolver answers for, and its assembly has a resolver registered.
/// </remarks>
public static class NativeImportGuard
{
    /// <summary>The library name the resolver answers for; any other name falls through to probing.</summary>
    public const string LibraryName = "libc";

    /// <returns>How many imports were checked, so a caller can see the sweep was not vacuous.</returns>
    public static int AssertEveryImportUsesTheSystemResolver(params Assembly[] assemblies)
    {
        ArgumentNullException.ThrowIfNull(assemblies);

        var imports = assemblies
            .SelectMany(assembly => assembly.GetTypes())
            .SelectMany(type => type.GetMethods(
                BindingFlags.Static | BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic |
                BindingFlags.DeclaredOnly))
            .Where(method => method.Attributes.HasFlag(MethodAttributes.PinvokeImpl))
            .ToArray();

        foreach (var method in imports)
        {
            var type = method.DeclaringType!;
            var library = method.GetCustomAttribute<DllImportAttribute>()?.Value;
            Assert.True(
                library == LibraryName,
                $"{type.FullName}.{method.Name} imports '{library}'. Import '{LibraryName}', which the " +
                "system-name resolver answers for; any other name is probed in the application directory.");

            // The resolver is registered by the declaring type's static constructor. Once it has run, a
            // second registration for the same assembly must be refused -- that refusal is the only
            // observable sign one is in place.
            RuntimeHelpers.RunClassConstructor(type.TypeHandle);
            var registered = false;
            try
            {
                NativeLibrary.SetDllImportResolver(type.Assembly, (_, _, _) => IntPtr.Zero);
            }
            catch (InvalidOperationException)
            {
                registered = true;
            }

            Assert.True(
                registered,
                $"{type.Assembly.GetName().Name} has no DllImport resolver, so {type.FullName}.{method.Name} " +
                "would load libc from the application directory first. Register the system-name resolver " +
                "for the assembly in the declaring type's static constructor.");
        }

        return imports.Length;
    }
}
