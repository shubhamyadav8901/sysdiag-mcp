namespace WinDiag.Mcp.Diagnostics.External;

/// <summary>
/// One element of a child process's argument vector, tagged with who authored it.
/// </summary>
/// <remarks>
/// The tag is the entire point of this type. Passing arguments as an array (rather than a single
/// command string) already prevents shell injection, but it does nothing about the <em>target
/// binary's own</em> argument parser: a caller-supplied value that begins with '-' or '/' is read by
/// the tool as a flag, not as data.
/// <para>
/// Concretely, <c>path_handle_search(path: "-c")</c> would otherwise compose
/// <c>handle.exe ... -c</c>, which closes the handle and, per handle.exe's own documentation, can
/// cause "application or system instability".
/// </para>
/// <para>
/// <see cref="ExternalToolRunner"/> rejects caller-authored values that look like flags. That check
/// is only possible because provenance travels with the value instead of being guessed later.
/// </para>
/// </remarks>
public readonly record struct ToolArgument
{
    private ToolArgument(string value, bool isCallerSupplied)
    {
        Value = value;
        IsCallerSupplied = isCallerSupplied;
    }

    /// <summary>The literal text passed as one argv element.</summary>
    public string Value { get; }

    /// <summary>True when the value originated outside the server and must be validated.</summary>
    public bool IsCallerSupplied { get; }

    /// <summary>A flag or literal chosen by the server itself. Never validated, always allowed.</summary>
    public static ToolArgument Flag(string value) => new(value, isCallerSupplied: false);

    /// <summary>A value that came from the caller. Validated by the runner before use.</summary>
    public static ToolArgument Caller(string value) => new(value, isCallerSupplied: true);

    public override string ToString() => Value;
}
