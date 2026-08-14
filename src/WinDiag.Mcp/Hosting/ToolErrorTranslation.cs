using Microsoft.Extensions.DependencyInjection;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using WinDiag.Mcp.Diagnostics;
using WinDiag.Mcp.Diagnostics.Access;
using WinDiag.Mcp.Diagnostics.Activity;
using WinDiag.Mcp.Diagnostics.Control;
using WinDiag.Mcp.Diagnostics.Dumps;
using WinDiag.Mcp.Diagnostics.EventLogs;
using WinDiag.Mcp.Diagnostics.External;
using WinDiag.Mcp.Diagnostics.Locks;
using WinDiag.Mcp.Diagnostics.Modules;
using WinDiag.Mcp.Diagnostics.Network;
using WinDiag.Mcp.Diagnostics.Pipes;
using WinDiag.Mcp.Diagnostics.RegistryInspection;
using WinDiag.Mcp.Diagnostics.SelfUpdate;

namespace WinDiag.Mcp.Hosting;

/// <summary>
/// Turns a thrown diagnostic failure into a tool result the caller can actually read.
/// </summary>
/// <remarks>
/// <para>Without this, every failure arrives as <c>"An error occurred invoking 'service_control'."</c>
/// and nothing else. The SDK does not surface exception messages by default, which is a sound default
/// for a general server and exactly wrong here: the messages <em>are</em> the product. "PID 1234 is
/// 'svchost', not 'notepad'. Nothing has been done." tells the caller what to do next;
/// "an error occurred" sends them round the loop again.</para>
/// <para>This is also where the MCP distinction is honoured: a tool that ran and refused is not a
/// protocol error, it is a tool result with <c>IsError</c> set. Throwing a protocol error for it would
/// mean an argument the model got wrong looks the same as the server being broken.</para>
/// <para>Unexpected exception types are deliberately NOT unwrapped here. Those are bugs rather than
/// diagnoses, and their messages can carry internals that are no use to a caller and unwise to publish
/// over a network endpoint.</para>
/// </remarks>
public static class ToolErrorTranslation
{
    /// <summary>Failures that represent a diagnosis, not a defect, and are safe to report verbatim.</summary>
    /// <remarks>
    /// <c>ToolErrorTranslationTests.Translates_every_diagnostic_exception_this_assembly_defines</c>
    /// reflects over the assembly and fails if a new exception type is not listed here. Without that
    /// guard the omission is invisible until someone triggers the failure on a target and gets back
    /// "An error occurred invoking 'x'." -- which is how <see cref="ModuleQueryException"/> and
    /// <see cref="ToolArchitectureException"/> both got missed.
    /// </remarks>
    internal static bool IsDiagnostic(Exception exception) => exception is
        ExternalToolException          // missing, wrong architecture, timed out, or refused
        or LockQueryException
        or AccessQueryException
        or EventLogQueryException
        or NetworkQueryException
        or NamedPipeQueryException
        or DumpCaptureException
        or ActivityCaptureException
        or ModuleQueryException
        or RegistryQueryException
        or RegistryPathException
        or ProcessControlException
        or ServiceControlException
        or SelfUpdateRejectedException
        or ArgumentException            // a parameter the caller can correct
        or FormatException;             // tool output that did not match the expected shape

    /// <summary>Registers the filter on the call-tool pipeline.</summary>
    public static IMcpServerBuilder WithReadableToolErrors(this IMcpServerBuilder builder)
    {
        builder.WithRequestFilters(filters =>
            filters.AddCallToolFilter(next => async (request, cancellationToken) =>
            {
                try
                {
                    return await next(request, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex) when (IsDiagnostic(ex))
                {
                    return new CallToolResult
                    {
                        IsError = true,
                        Content = [new TextContentBlock { Text = Describe(ex) }]
                    };
                }
            }));

        return builder;
    }

    /// <summary>Flattens the message chain, since the cause often carries the actionable part.</summary>
    internal static string Describe(Exception exception)
    {
        var messages = new List<string>();

        for (var current = exception; current is not null; current = current.InnerException)
        {
            var message = current.Message?.Trim();

            // Skip repeats: wrapping an exception often restates its cause almost word for word.
            if (!string.IsNullOrEmpty(message)
                && !messages.Any(existing => existing.Contains(message, StringComparison.Ordinal)))
            {
                messages.Add(message);
            }
        }

        return messages.Count == 0 ? exception.GetType().Name : string.Join(" ", messages);
    }
}
