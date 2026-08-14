// Deliberately NOT WinDiag.Mcp.Diagnostics.Registry. A namespace named Registry under Diagnostics
// shadows the Microsoft.Win32.Registry TYPE for every file in Diagnostics.*, so unrelated code that
// says Registry.LocalMachine stops compiling -- ToolLocator and the service inspector both broke the
// moment that namespace existed.
namespace WinDiag.Mcp.Diagnostics.RegistryInspection;

/// <summary>One value under a registry key.</summary>
/// <param name="Name">Empty string for the key's unnamed default value, which is how the API names it.</param>
/// <param name="Kind">The <c>REG_*</c> type, as Windows records it.</param>
/// <param name="Value">
/// Rendered for reading: numbers in decimal and hex, multi-strings joined, binary as a hex preview.
/// Never the raw bytes -- a single value can be megabytes.
/// </param>
/// <param name="Truncated">True when <see cref="Value"/> is a prefix of what is stored.</param>
/// <param name="SizeBytes">Size of the stored data, so a truncated value still reports its real size.</param>
public sealed record RegistryValue(
    string Name,
    string Kind,
    string Value,
    bool Truncated,
    int SizeBytes);

/// <summary>What one registry key holds.</summary>
/// <param name="View">
/// Which of the two registry views was read, stated because on 64-bit Windows the same path names two
/// different keys and an answer that does not say which is not an answer.
/// </param>
/// <param name="SubKeyNames">Immediate children, for walking down without guessing.</param>
public sealed record RegistryKeyContents(
    string Path,
    string View,
    IReadOnlyList<RegistryValue> Values,
    IReadOnlyList<string> SubKeyNames,
    int TotalValues,
    int TotalSubKeys,
    bool Truncated);

/// <summary>Reads registry keys and values.</summary>
public interface IRegistryInspector
{
    RegistryKeyContents Read(string path, string? valueName, string? view, CancellationToken cancellationToken);
}

/// <summary>Raised when a registry key or value could not be read.</summary>
public sealed class RegistryQueryException : Exception
{
    public RegistryQueryException(string message) : base(message)
    {
    }

    public RegistryQueryException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
