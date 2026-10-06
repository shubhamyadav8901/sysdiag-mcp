using System.Security;

namespace WinDiag.Mcp.Hosting;

/// <summary>
/// Refuses to run as a service from a directory someone other than an administrator can write, after
/// first trying to put that right; and restricts a service key whose token others can read.
/// </summary>
/// <remarks>
/// <para>MacDiag refuses outright. Here a plain refusal would strand every target installed before
/// directories were protected: <c>update_self</c> swaps in this build, the build refuses to start, and
/// the machine goes quiet with nobody at its console -- the exact visit a service exists to remove.
/// A service normally runs as SYSTEM, the same rights the installer has, so it applies the installer's
/// ACL itself and says so in the event log. It refuses only when that does not work -- as it will not
/// for a NetworkService service on a directory it does not own -- because then a local user can still
/// plant what it is about to run.</para>
/// <para>The decisions are separated from the ACL calls so they can be tested anywhere; the Windows
/// half is <see cref="ProtectedAcl"/>.</para>
/// </remarks>
public static class StartupPermissions
{
    /// <summary>Makes <paramref name="path"/> writable only by trusted accounts, or throws.</summary>
    /// <param name="what">What the path is to the server, for the messages: "server directory".</param>
    /// <param name="path">The directory.</param>
    /// <param name="exposures">Who else can write it, as readable phrases; empty when nobody can.</param>
    /// <param name="protect">Applies the protected ACL.</param>
    /// <param name="warn">Where a repair is reported. Under the SCM, that is the event log.</param>
    public static void RequireProtected(
        string what, string path, Func<string, IReadOnlyList<string>> exposures, Action<string> protect, Action<string> warn)
    {
        ArgumentNullException.ThrowIfNull(exposures);
        ArgumentNullException.ThrowIfNull(protect);
        ArgumentNullException.ThrowIfNull(warn);

        var found = exposures(path);
        if (found.Count == 0)
        {
            return;
        }

        string? failure = null;
        try
        {
            protect(path);
        }
        catch (Exception ex)
        {
            // Every exception: whatever stopped the repair, the re-check below is what decides, and the
            // refusal carries this reason so the operator is not left guessing why it did not take.
            failure = $" Restricting it failed: {ex.Message}";
        }

        var left = failure is null ? exposures(path) : found;
        if (left.Count > 0)
        {
            throw new ConfigurationException(
                $"Refusing to start as a service: the {what} {path} can be changed by accounts other than "
                + $"SYSTEM and Administrators ({string.Join("; ", left)}), and this server runs what it finds "
                + $"there with its own rights.{failure} Re-run --install-service from an elevated prompt, which "
                + "restricts it, or move the server somewhere only administrators can write.");
        }

        warn(
            $"The {what} {path} could be changed by accounts other than SYSTEM and Administrators "
            + $"({string.Join("; ", found)}). It is now restricted to them. Anything placed there before "
            + "this is still there: check the files against the deployment (windiag-staged.json), and "
            + "redeploy if in doubt.");
    }

    /// <summary>Restricts the service key if others can read the token in it, and says the token must change.</summary>
    /// <param name="serviceName">The service, for the messages.</param>
    /// <param name="runsAsLocalSystem">Whether this process is SYSTEM, which can always read its own key.</param>
    /// <param name="exposures">Who else can read or change the key; empty when nobody can.</param>
    /// <param name="protect">Applies the protected ACL.</param>
    /// <param name="warn">Where the outcome is reported. Under the SCM, that is the event log.</param>
    /// <remarks>
    /// Best-effort, and never a reason to stop: the token was already readable, refusing to start does
    /// not make it less so, and a server that will not start cannot be reached to rotate it.
    /// </remarks>
    public static void ProtectServiceKey(
        string serviceName, bool runsAsLocalSystem, Func<string, IReadOnlyList<string>> exposures,
        Action<string> protect, Action<string> warn)
    {
        ArgumentNullException.ThrowIfNull(exposures);
        ArgumentNullException.ThrowIfNull(protect);
        ArgumentNullException.ThrowIfNull(warn);

        IReadOnlyList<string> found;
        try
        {
            found = exposures(serviceName);
        }
        catch (Exception ex) when (!runsAsLocalSystem && ex is SecurityException or UnauthorizedAccessException)
        {
            // A protected key admits only SYSTEM and Administrators, so a NetworkService or LocalService
            // service being refused even its ACL is the protected state seen from outside it. A warning
            // here would be one on every start of a correctly installed service.
            return;
        }
        catch (Exception ex)
        {
            // Every other exception, deliberately: this is a check on the way to serving, and a failure
            // to make it must be reported rather than become the reason the server never comes up.
            warn($"Could not check who can read the registry key of service '{serviceName}': {ex.Message}");
            return;
        }

        if (found.Count == 0)
        {
            return;
        }

        var who = string.Join("; ", found);
        try
        {
            protect(serviceName);
        }
        catch (Exception ex)
        {
            warn(
                $"The registry key of service '{serviceName}', which holds its bearer token, is readable by "
                + $"accounts other than SYSTEM and Administrators ({who}), and this service could not restrict "
                + $"it: {ex.Message} From an elevated prompt, run --uninstall-service, then --install-service "
                + "--token-stdin with a new token -- the installer restricts the key -- and update the relay's "
                + "targets file: any local user may already have the current one.");
            return;
        }

        warn(
            $"The registry key of service '{serviceName}', which holds its bearer token, was readable by accounts "
            + $"other than SYSTEM and Administrators ({who}). It is now restricted to them, but any local user "
            + "may already have the token: change it (--uninstall-service, then --install-service "
            + "--token-stdin with a new one) and update the relay's targets file.");
    }
}
