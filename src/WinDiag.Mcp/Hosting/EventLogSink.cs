using System.Diagnostics;
using System.Runtime.Versioning;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting.WindowsServices;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.EventLog;

namespace WinDiag.Mcp.Hosting;

/// <summary>
/// Makes the event log a safe place to log to, or stops logging there at all.
/// </summary>
/// <remarks>
/// <para>A service has no stderr, so <c>AddWindowsService()</c> redirects logging to the Windows event
/// log. Writing there needs a registered <em>source</em>, and if it is missing the write throws --
/// which is how a diagnostics server came to fail a tool call because it could not write a log line
/// nobody asked for.</para>
/// <para>It cost an afternoon to find, because the failure looked nothing like its cause: the event log
/// provider's minimum level is Warning, so every Information line was filtered out and never attempted
/// a write. The server started, served every tool, and then <c>update_self</c> died -- because the
/// first Warning in the process's life is the one noting that the live build is unsigned, and it fires
/// halfway through an update. The caller saw only "An error occurred".</para>
/// <para>So the rule here is the one this project keeps relearning: a diagnostic channel must never be
/// able to break the thing it is reporting on. If the source cannot be guaranteed, the sink is removed
/// rather than left to throw.</para>
/// </remarks>
[SupportedOSPlatform("windows")]
public static class EventLogSink
{
    /// <summary>
    /// The source windiag logs under.
    /// </summary>
    /// <remarks>
    /// Pinned rather than left to default to the application name, so the name the installer registers
    /// and the name the server writes to cannot drift apart.
    /// </remarks>
    public const string SourceName = "windiag";

    /// <summary>The log the source belongs to.</summary>
    public const string LogName = "Application";

    /// <summary>
    /// Guarantees that logging cannot throw, by registering the source or dropping the sink.
    /// </summary>
    /// <remarks>
    /// Only relevant under the Service Control Manager: interactively the provider is never added, and
    /// stderr is always writable.
    /// </remarks>
    public static void MakeSafe(IServiceCollection services) =>
        MakeSafe(services, WindowsServiceHelpers.IsWindowsService(), TryRegisterSource);

    /// <summary>The whole of <see cref="MakeSafe(IServiceCollection)"/>, with its two facts injected.</summary>
    /// <remarks>
    /// Both are unfakeable statics -- whether this process is under the SCM, and whether a registry key
    /// could be written -- and a test host is neither a service nor short of the assembly, so without
    /// this seam every line below the guard is unreachable in the suite. That is not hypothetical
    /// tidiness: the descriptor match is against a BCL implementation detail, so if <c>AddEventLog()</c>
    /// ever registers through a factory instead, <c>ImplementationType</c> becomes null, the match finds
    /// nothing, and this method removes nothing while reporting success -- restoring the exact throwing
    /// sink it exists to prevent, with a green build. The test asserts the count actually dropped, so
    /// that day fails here rather than on a target.
    /// </remarks>
    internal static void MakeSafe(IServiceCollection services, bool isWindowsService, Func<bool> tryRegister)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(tryRegister);

        if (!isWindowsService)
        {
            return;
        }

        services.Configure<EventLogSettings>(settings => settings.SourceName = SourceName);

        if (tryRegister())
        {
            return;
        }

        // Registration needs administrator rights and can still be refused by policy. Rather than leave
        // a sink that throws on first use, take it out: losing log lines degrades diagnosis, while
        // keeping it costs tool calls.
        var provider = services.FirstOrDefault(descriptor =>
            descriptor.ServiceType == typeof(ILoggerProvider)
            && descriptor.ImplementationType == typeof(EventLogLoggerProvider));

        if (provider is not null)
        {
            services.Remove(provider);
        }
    }

    /// <summary>Creates the event log source if it is missing. Safe to call repeatedly.</summary>
    /// <returns>True when the source exists afterwards.</returns>
    /// <remarks>
    /// Called by <c>--install-service</c> as well, where it is far more likely to succeed: the
    /// installer is elevated by construction, and creating a source is a one-time administrative act
    /// rather than something a running service should depend on.
    /// </remarks>
    public static bool TryRegisterSource() => TryRegisterSource(RegisterCore);

    /// <summary>The never-throw contract on its own, separated from what it is protecting.</summary>
    /// <remarks>
    /// Split out so the contract is testable against a failure nobody predicted, which is the only
    /// kind that matters here -- with the assembly present, the narrow catch this replaced passes every
    /// test and every live run alike, so nothing else would notice it coming back.
    /// </remarks>
    internal static bool TryRegisterSource(Func<bool> register)
    {
        ArgumentNullException.ThrowIfNull(register);

        try
        {
            return register();
        }
        catch (Exception)
        {
            // Deliberately every exception, not a list of the plausible ones. The list version shipped
            // first and was wrong within the hour: the real failure was a FileNotFoundException for
            // System.Threading.AccessControl, which EventLog reaches only through the named-mutex path
            // and which the single-file publish had left out. It escaped the filter and took the
            // installer down with an unhandled stack trace -- turning a missing log line into a target
            // that could not be set up at all.
            //
            // Nothing above this call can act on *why* registration failed; the only answer is the same
            // one either way, which is to run without the sink. A method whose entire contract is
            // "never throw, just tell me if it worked" has no business rehearsing which failures it
            // predicted.
            return false;
        }
    }

    /// <summary>Writes one entry if the source can be had, and otherwise nothing. Never throws.</summary>
    /// <remarks>
    /// For what happens before the host -- and so before the logging provider -- exists: a refusal to
    /// start is exactly the line an operator of a service needs, and under the SCM stderr goes nowhere.
    /// </remarks>
    public static void TryWrite(string message, EventLogEntryType type)
    {
        try
        {
            if (TryRegisterSource())
            {
                EventLog.WriteEntry(SourceName, message, type);
            }
        }
        catch (Exception)
        {
            // Every exception, for the reason TryRegisterSource gives: this channel must never be what
            // stops the thing it reports on.
        }
    }

    /// <summary>Creates the source if it is missing, and reports whether it is there afterwards.</summary>
    /// <remarks>
    /// The probe is not merely a proxy for the write path, it removes it: inside
    /// <c>EventLogInternal.VerifyAndCreateSource</c> the named-mutex path -- the one needing
    /// <c>System.Threading.AccessControl</c> -- is entered only when the source does not already exist.
    /// Guaranteeing it exists here therefore guarantees no later <c>WriteEntry</c> goes near it.
    /// </remarks>
    private static bool RegisterCore()
    {
        if (!EventLog.SourceExists(SourceName))
        {
            EventLog.CreateEventSource(new EventSourceCreationData(SourceName, LogName));
        }

        return EventLog.SourceExists(SourceName);
    }
}
