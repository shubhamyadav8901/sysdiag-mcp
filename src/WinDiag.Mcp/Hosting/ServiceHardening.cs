using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Principal;

namespace WinDiag.Mcp.Hosting;

/// <summary>
/// What a server started by the SCM checks about itself before it serves anything: that nobody but an
/// administrator can write its directories or anything in them, that neither is reached through a link,
/// and that nobody else can read its token.
/// </summary>
/// <remarks>
/// Run on every service start, not only at install, because a target installed by an older build, or
/// registered by hand with sc.exe, has neither protection -- and <c>update_self</c> is how most targets
/// will receive this build, without an install ever running again.
/// </remarks>
[SupportedOSPlatform("windows")]
public static class ServiceHardening
{
    /// <summary>Protects or refuses; see <see cref="StartupPermissions"/>.</summary>
    /// <exception cref="ConfigurationException">A directory stays writable by someone else.</exception>
    public static void Apply(string artifactDirectory)
    {
        ArgumentNullException.ThrowIfNull(artifactDirectory);

        using var identity = WindowsIdentity.GetCurrent();
        var account = identity.User is { } user && user != ProtectedAcl.LocalSystem ? user : null;
        var serverDirectory = Path.GetDirectoryName(Environment.ProcessPath) ?? AppContext.BaseDirectory;

        // Only SYSTEM may hand a directory to Administrators. A NetworkService or LocalService token holds
        // neither the Administrators group nor SeRestorePrivilege, so setting that owner fails -- and on the
        // default artifact directory, which does not exist until the first start, that failure refused
        // every start of such a service. Left alone, the owner is the service account, which is trusted.
        void Protect(string path) => ProtectedAcl.ProtectDirectory(path, account, ownedByAdministrators: account is null);

        try
        {
            // Made here, protected, rather than left for the first dump to create: Directory.CreateDirectory
            // inherits whatever the parent hands down, and under C:\ that is "Authenticated Users: Modify".
            if (!Directory.Exists(artifactDirectory))
            {
                Protect(artifactDirectory);
            }

            foreach (var (what, path) in new[] { ("server directory", serverDirectory), ("artifact directory", artifactDirectory) })
            {
                StartupPermissions.RequireProtected(
                    what, path, p => ProtectedAcl.DirectoryExposures(p, account), Protect, Warn);
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or InvalidOperationException)
        {
            // A service account that cannot even read who may write its own directories -- a
            // NetworkService install pointed somewhere it was never given -- cannot vouch for them either.
            // Refused with the reason, rather than left to escape as an unhandled crash.
            throw new ConfigurationException(
                $"Refusing to start as a service: could not check or create its directories ({ex.Message}). "
                + "Re-run --install-service from an elevated prompt, which sets them up.");
        }

        ProtectOwnKey(runsAsLocalSystem: account is null);
    }

    /// <summary>Restricts the service key if it is still readable; see <see cref="StartupPermissions.ProtectServiceKey"/>.</summary>
    /// <remarks>
    /// Named by WINDIAG_SERVICE_NAME, which --install-service writes; a hand-registered service without it
    /// is not looked for.
    /// </remarks>
    private static void ProtectOwnKey(bool runsAsLocalSystem)
    {
        var name = Environment.GetEnvironmentVariable("WINDIAG_SERVICE_NAME");
        if (string.IsNullOrWhiteSpace(name))
        {
            return;
        }

        StartupPermissions.ProtectServiceKey(
            name, runsAsLocalSystem, ProtectedAcl.ServiceKeyExposures, ProtectedAcl.ProtectServiceKey, Warn);
    }

    /// <summary>To stderr and, because a service has no stderr anyone sees, to the event log.</summary>
    public static void Warn(string message) => Report(message, EventLogEntryType.Warning);

    /// <summary>A refusal to start, written where an operator of a service will look for it.</summary>
    public static void Refuse(string message) => Report(message, EventLogEntryType.Error);

    private static void Report(string message, EventLogEntryType type)
    {
        Console.Error.WriteLine($"[windiag] {message}");
        EventLogSink.TryWrite(message, type);
    }
}
