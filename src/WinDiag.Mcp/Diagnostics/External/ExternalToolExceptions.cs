namespace WinDiag.Mcp.Diagnostics.External;

/// <summary>
/// Base for failures invoking a bundled external tool.
/// </summary>
/// <remarks>
/// Messages on these exceptions are written <em>for the model</em>: they state what went wrong and
/// what to do about it, because the text is surfaced directly in the tool result. Resist the urge to
/// shorten them into developer shorthand.
/// </remarks>
public class ExternalToolException : Exception, IDiagnosticException
{
    public ExternalToolException(string message) : base(message)
    {
    }

    public ExternalToolException(string message, Exception innerException) : base(message, innerException)
    {
    }
}

/// <summary>The tool is not installed, or could not be located.</summary>
public sealed class ToolNotFoundException : ExternalToolException
{
    public ToolNotFoundException(string executableName)
        : base($"'{executableName}' was not found on this machine. It ships with Sysinternals Suite; " +
               "install it (Store package 'Sysinternals Suite', or copy the exe onto PATH) and retry. " +
               "Tools backed by native Windows APIs are unaffected and still work.")
    {
        ExecutableName = executableName;
    }

    public string ExecutableName { get; }
}

/// <summary>A tool was found beside the server, but Microsoft did not sign it, so it is not run.</summary>
/// <remarks>
/// Distinct from <see cref="ToolNotFoundException"/>: the file is there, and "install it" would send the
/// operator looking for something they can see. Every Sysinternals binary Microsoft ships is signed, so an
/// unsigned or foreign-signed one in the server's folder is a corrupt copy or a planted one.
/// </remarks>
public sealed class UntrustedToolException : ExternalToolException
{
    public UntrustedToolException(string path, string verdict)
        : base($"'{path}' is beside the server but is not signed by Microsoft ({verdict}), so it was not " +
               "run: anything in the server's folder runs as the server's account, and every Sysinternals " +
               "binary is Microsoft-signed. Replace it with the copy from download.sysinternals.com -- " +
               "tools/deploy-target.ps1 stages and verifies one -- or delete it to use an installed copy.")
    {
        Path = path;
    }

    public string Path { get; }
}

/// <summary>
/// A caller-supplied argument was shaped like a command-line flag and was refused.
/// </summary>
/// <seealso cref="ToolArgument"/>
public sealed class UnsafeArgumentException : ExternalToolException
{
    public UnsafeArgumentException(string value)
        : base($"Refused the argument \"{value}\": values supplied to this tool must not begin with " +
               "'-' or '/', because the underlying program would interpret them as command-line " +
               "switches rather than as data. Pass a literal path, name, or PID.")
    {
        Value = value;
    }

    public string Value { get; }
}

/// <summary>The tool did not finish inside its time budget and was terminated.</summary>
public sealed class ToolTimeoutException : ExternalToolException
{
    public ToolTimeoutException(string executableName, TimeSpan timeout, string partialStandardOutput = "")
        : base($"'{executableName}' did not finish within {timeout.TotalSeconds:0.#}s and was terminated" +
               (partialStandardOutput.Length > 0
                   ? $" after producing {partialStandardOutput.Length} characters of partial output, which were discarded"
                   : string.Empty) +
               ". Narrow the query (a more specific path or a single process) or raise " +
               "WINDIAG_EXTERNAL_TOOL_TIMEOUT_SECONDS.")
    {
        ExecutableName = executableName;
        Timeout = timeout;
        PartialStandardOutput = partialStandardOutput;
    }

    public string ExecutableName { get; }

    public TimeSpan Timeout { get; }

    /// <summary>Whatever the tool managed to write before being killed. May be empty.</summary>
    public string PartialStandardOutput { get; }
}
