using Microsoft.Extensions.DependencyInjection;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace WinDiag.Mcp.Hosting;

/// <summary>
/// Reports every tool call to <see cref="ToolActivity"/>, and turns callers away during an update.
/// </summary>
/// <remarks>
/// <para>One filter on the call-tool pipeline is enough to see every tool on both transports, which is
/// why the count can be trusted: nothing reaches a tool without passing through here.</para>
/// <para>A refusal is <em>returned</em> rather than thrown. That keeps it out of
/// <see cref="ToolErrorTranslation.IsDiagnostic"/> -- which a reflection test would otherwise require
/// updating for a new exception type -- and it is also the honest shape: a server that declines to
/// start new work has produced a result, not suffered a fault.</para>
/// </remarks>
public static class ToolActivityGate
{
    /// <summary>Registers the counter on the call-tool pipeline.</summary>
    /// <remarks>
    /// Takes the instance rather than resolving it, because a request filter closure has no service
    /// provider to resolve from. The caller registers the same object as a singleton so the updater
    /// gets it by constructor injection; both then talk about the same count.
    /// </remarks>
    public static IMcpServerBuilder WithToolActivityGate(this IMcpServerBuilder builder, ToolActivity activity)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(activity);

        builder.WithRequestFilters(filters =>
            filters.AddCallToolFilter(next => async (request, cancellationToken) =>
            {
                if (!activity.TryBegin(out var refusal))
                {
                    return new CallToolResult
                    {
                        IsError = true,
                        Content = [new TextContentBlock { Text = refusal }]
                    };
                }

                try
                {
                    return await next(request, cancellationToken).ConfigureAwait(false);
                }
                finally
                {
                    // In a finally, not after the await: a tool that throws still has to give its slot
                    // back, or the count never reaches zero and every later update waits out its budget.
                    activity.End();
                }
            }));

        return builder;
    }
}
