using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using System.Security.Principal;
using Microsoft.Win32;
using WinDiag.Mcp.Configuration;

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
    /// <summary>
    /// <paramref name="options"/> with the token from the service's token key, which --install-service writes;
    /// unchanged when there is none, as on a target an older build installed, whose token is in its environment.
    /// </summary>
    /// <remarks>
    /// Found by WINDIAG_SERVICE_NAME, which --install-service writes into the environment beside it. A key that is
    /// there but cannot be read refuses the start rather than falling back: the server would otherwise make up a
    /// token of its own, and serve with one nobody holds.
    /// </remarks>
    /// <exception cref="ConfigurationException">The token key exists and cannot be read.</exception>
    public static WinDiagOptions WithStoredToken(WinDiagOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var name = Environment.GetEnvironmentVariable("WINDIAG_SERVICE_NAME");
        if (string.IsNullOrWhiteSpace(name))
        {
            return options;
        }

        var path = ServiceInstallOptions.TokenKeyPath(name);
        string? stored;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(path);
            stored = key?.GetValue(ServiceInstallOptions.TokenValueName) as string;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            throw new ConfigurationException(
                $@"could not read the bearer token from HKLM\{path} ({ex.Message}). Re-run --install-service from an "
                + "elevated prompt, which creates that key readable by the service's account.");
        }

        if (string.IsNullOrWhiteSpace(stored) && options.Token is not null)
        {
            Warn($"This service's bearer token is in its registry key's Environment value, where an older build put it, "
                 + "in a key every local user could read until it was restricted. Change it: --uninstall-service, then "
                 + "--install-service --token-stdin with a new one, which goes into a key of its own; then update the "
                 + "relay's targets file.");
        }

        return options with { Token = ServiceInstallOptions.ServiceToken(stored, options.Token) };
    }

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
            // The default is %TEMP%\windiag, a name anyone may have taken first where SYSTEM's temp directory is
            // C:\Windows\Temp. A directory the operator named was made, or refused, by the installer.
            if (IsDefault(artifactDirectory))
            {
                StartupPermissions.ReplaceForeign(
                    "artifact directory", artifactDirectory, p => ProtectedAcl.ForeignOwner(p, account), MoveAside, Warn);
            }

            // Made here, protected, rather than left for the first dump to create: Directory.CreateDirectory
            // inherits whatever the parent hands down, and under C:\ that is "Authenticated Users: Modify". One
            // that appears between the look and the create is somebody else's, and refused.
            if (!Directory.Exists(artifactDirectory))
            {
                ProtectedAcl.ProtectDirectory(artifactDirectory, account, ownedByAdministrators: account is null, adoptExisting: false);
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

    private static bool IsDefault(string artifactDirectory) => string.Equals(
        Path.TrimEndingDirectorySeparator(Path.GetFullPath(artifactDirectory)),
        Path.TrimEndingDirectorySeparator(Path.GetFullPath(WinDiagOptions.DefaultArtifactDirectory)),
        StringComparison.OrdinalIgnoreCase);

    /// <summary>Renames a directory to a name beside it that is not taken, and returns that name.</summary>
    /// <remarks>
    /// A rename moves a link itself, never what it leads to (MoveFileEx acts on the reparse point), so a junction
    /// in the way is moved, not followed. One held open without FILE_SHARE_DELETE cannot be renamed, which is the
    /// refusal ReplaceForeign gives.
    /// </remarks>
    private static string MoveAside(string path)
    {
        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        var stamp = DateTime.UtcNow.ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture);
        for (var attempt = 0; ; attempt++)
        {
            var aside = $"{full}.not-windiag-{stamp}{(attempt == 0 ? string.Empty : $"-{attempt}")}";
            if (Path.Exists(aside))
            {
                continue;
            }

            // A file in the way is moved too; GetAttributes reads the name itself, not what a link leads to.
            if (File.GetAttributes(full).HasFlag(FileAttributes.Directory))
            {
                Directory.Move(full, aside);
            }
            else
            {
                File.Move(full, aside);
            }

            return aside;
        }
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
            name, runsAsLocalSystem, ProtectedAcl.ServiceKeyExposures, ProtectedAcl.ProtectServiceKey, Warn,
            holdsToken: Environment.GetEnvironmentVariable("WINDIAG_TOKEN") is not null);
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
