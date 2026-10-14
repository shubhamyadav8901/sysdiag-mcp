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
                + $"there with its own rights.{failure} Remove the rights named; or move the server into a directory "
                + @"restricted when it was made, such as one made elevated under C:\Program Files, and reinstall it from "
                + "there (--uninstall-service, then --install-service, which refuses a directory others can change).");
        }

        // What the repair cannot undo is said, not left to be assumed: a file planted while the directory
        // was writable is restricted now but still there, and a handle opened then keeps its access.
        warn(
            $"The {what} {path} could be changed by accounts other than SYSTEM and Administrators "
            + $"({string.Join("; ", found)}). It and everything in it are now restricted to them. Anything "
            + "placed there before this is still there, and a handle opened on it before keeps the access it "
            + "had until it is closed: check the files against the deployment (windiag-staged.json), restart "
            + "the machine, which closes every such handle, and redeploy if in doubt.");
    }

    /// <summary>
    /// Moves a directory someone else made out of the way, so that it is made afresh with the ACL already on it
    /// rather than taken over; or refuses to start when it cannot be moved.
    /// </summary>
    /// <param name="what">What the path is to the server, for the messages: "artifact directory".</param>
    /// <param name="path">The directory.</param>
    /// <param name="foreign">Why it is not to be used as it is, as a phrase ("DOMAIN\bob owns it"); null when nothing is there or it is the service's own.</param>
    /// <param name="moveAside">Renames it and returns the new name.</param>
    /// <param name="warn">Where the move is reported. Under the SCM, that is the event log.</param>
    /// <remarks>
    /// <para>For the default artifact directory, <c>%TEMP%\windiag</c>, which nothing creates before the
    /// service first starts. Where SYSTEM's temp directory is <c>C:\Windows\Temp</c>, any user may create
    /// folders in it, so the name may be taken by someone waiting for the service to arrive. Taking such a
    /// directory over -- what <see cref="RequireProtected"/> does to an exposed one -- would leave its owner
    /// any handle they opened beforehand, and an owner can open one for WRITE_DAC that no share mode refuses,
    /// then put their own ACE back on the directory self-update.cmd and the dumps are later written to.</para>
    /// <para>Moved, not deleted: what is in it is evidence, and an administrator should see it. Not done to a
    /// directory the operator named with --artifacts, which the installer made itself or refused.</para>
    /// </remarks>
    public static void ReplaceForeign(
        string what, string path, Func<string, string?> foreign, Func<string, string> moveAside, Action<string> warn)
    {
        ArgumentNullException.ThrowIfNull(foreign);
        ArgumentNullException.ThrowIfNull(moveAside);
        ArgumentNullException.ThrowIfNull(warn);

        var why = foreign(path);
        if (why is null)
        {
            return;
        }

        string aside;
        try
        {
            aside = moveAside(path);
        }
        catch (Exception ex)
        {
            // Every exception: whatever stopped the move, the directory is still someone else's, and using it
            // is what this exists to prevent.
            throw new ConfigurationException(
                $"Refusing to start as a service: the {what} {path} was already there and is not this service's ({why}), "
                + $"and moving it aside failed: {ex.Message} Taking it over would leave whoever made it any handle they "
                + "hold on it. Restart the machine, which closes every such handle, and start the service again; or "
                + "reinstall it with --artifacts naming a directory that does not exist yet, which the installer creates.");
        }

        warn(
            $"The {what} {path} was already there and was not this service's ({why}). It was moved to {aside}, "
            + "unchanged, and a new one is made in its place, restricted to SYSTEM and Administrators from the start. "
            + "Look at what the old one holds: whoever made it was expecting this service.");
    }

    /// <summary>What <c>--install-service</c> does with a server or artifact directory it is given.</summary>
    public enum InstallDirectory
    {
        /// <summary>It does not exist: create it with the ACL already on it.</summary>
        Create,

        /// <summary>It exists and only trusted accounts can change it or anything in it: use it.</summary>
        Use,

        /// <summary>
        /// It exists, and what makes it exposed is held only by direct members of the local Administrators
        /// group -- files an administrator copied in, owned by their own account: restrict it.
        /// </summary>
        TakeOver,

        /// <summary>It exists and someone who is not an administrator can change it: refuse, changing nothing.</summary>
        Refuse
    }

    /// <summary>Decides what the installer does with a directory.</summary>
    /// <param name="exists">Whether the directory is there.</param>
    /// <param name="exposures">Who other than SYSTEM, Administrators, TrustedInstaller and the service's account can change it or what it holds.</param>
    /// <param name="exposuresBeyondAdministrators">The same, with each direct member of the local Administrators group trusted too.</param>
    /// <remarks>
    /// <para>A directory anyone else can change is refused, not taken over as the service does on start. Taking it
    /// over cannot reach a handle opened before: an owner can hold one open for WRITE_DAC, which is not data
    /// access, so no share mode refuses it, and anyone with write access one on a file inside; Windows checks
    /// access only when a handle is opened. The service takes over because a refusal there would strand a target
    /// with nobody at its console; the installer has an operator at the console, who can rename the directory
    /// aside so that it is created fresh. That is what tools/windiag-acl.ps1 has always done.</para>
    /// <para>Taken over, still, when only administrators could have changed it: the bootstrap scripts create the
    /// server directory restricted and then copy files in, which a machine that gives new objects to their
    /// creator hands to the administrator's own account. An administrator can elevate and do anything SYSTEM
    /// can, so nothing they could hold open is a way in for anyone else.</para>
    /// <para>A directory an earlier windiag left needs no recognising: the installer made or refused it, and the
    /// service restricts both of its directories on every start, so it reads as restricted and is used.</para>
    /// </remarks>
    public static InstallDirectory JudgeForInstall(
        bool exists, IReadOnlyCollection<string> exposures, IReadOnlyCollection<string> exposuresBeyondAdministrators)
    {
        ArgumentNullException.ThrowIfNull(exposures);
        ArgumentNullException.ThrowIfNull(exposuresBeyondAdministrators);

        return !exists ? InstallDirectory.Create
            : exposures.Count == 0 ? InstallDirectory.Use
            : exposuresBeyondAdministrators.Count == 0 ? InstallDirectory.TakeOver
            : InstallDirectory.Refuse;
    }

    /// <summary>The installer's refusal of an exposed directory, with what to do instead.</summary>
    /// <param name="what">"server directory" or "artifact directory".</param>
    /// <param name="path">The directory.</param>
    /// <param name="exposures">Who else can change it.</param>
    /// <param name="foreign">For the server directory, the names in it that are not windiag's.</param>
    /// <param name="serverDirectory">Whether it is the directory the executable is in, which the installer cannot create.</param>
    public static string InstallRefusal(
        string what, string path, IReadOnlyCollection<string> exposures, IReadOnlyCollection<string> foreign, bool serverDirectory)
    {
        ArgumentNullException.ThrowIfNull(exposures);
        ArgumentNullException.ThrowIfNull(foreign);

        var why = $"The {what} {path} can be changed by accounts other than SYSTEM and Administrators "
                  + $"({string.Join("; ", exposures)}), and the service would run, or write, what is there with its own "
                  + "rights. Restricting it now would not shut out a handle opened on it, or on a file in it, while it "
                  + "was open, so it is not restricted for you. Nothing was installed. ";

        if (!serverDirectory)
        {
            // Split by hand rather than with Path.GetFileName, so the message is the same wherever it is tested.
            var trimmed = path.TrimEnd('\\', '/');
            var name = trimmed[(trimmed.LastIndexOfAny(['\\', '/']) + 1)..];
            return why + $"Rename it aside (ren \"{path}\" {name}.old) or name a directory that does "
                       + "not exist yet, and run this again: the installer creates it with the ACL already on it.";
        }

        // A folder that holds other things -- Downloads, a desktop -- is the operator's own, and renaming it
        // aside is not the remedy; the server needs a directory of its own.
        var instead = foreign.Count > 0
            ? $"It also holds files that are not windiag's ({string.Join(", ", foreign.Take(3))}{(foreign.Count > 3 ? ", ..." : string.Empty)}). "
            : "If it is left from an earlier windiag, rename it aside. ";

        return why + instead
               + @"Put WinDiag.Mcp.exe in a directory that was restricted when it was made, and install from there: one "
               + @"made from an elevated prompt under C:\Program Files (md ""%ProgramFiles%\WinDiag""), whose ACL lets "
               + "only administrators write, or the C:\\WinDiag the bootstrap scripts make. A folder made by hand under C:\\ "
               + "is not: it inherits \"Authenticated Users: Modify\".";
    }

    /// <summary>Restricts the service key if others can read the token in it, and says the token must change.</summary>
    /// <param name="serviceName">The service, for the messages.</param>
    /// <param name="runsAsLocalSystem">Whether this process is SYSTEM, which can always read its own key.</param>
    /// <param name="exposures">Who else can read or change the key; empty when nobody can.</param>
    /// <param name="protect">Applies the protected ACL.</param>
    /// <param name="warn">Where the outcome is reported. Under the SCM, that is the event log.</param>
    /// <param name="holdsToken">
    /// Whether the key's Environment value holds the token, as only an older build's install leaves it. When it
    /// does not, the token is in a key of its own that was never readable, and telling the operator to change it
    /// would send them to rotate a secret nobody could have read.
    /// </param>
    /// <remarks>
    /// Best-effort, and never a reason to stop: the token was already readable, refusing to start does
    /// not make it less so, and a server that will not start cannot be reached to rotate it.
    /// </remarks>
    public static void ProtectServiceKey(
        string serviceName, bool runsAsLocalSystem, Func<string, IReadOnlyList<string>> exposures,
        Action<string> protect, Action<string> warn, bool holdsToken = true)
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
        catch (Exception ex) when (!holdsToken)
        {
            warn(
                $"The registry key of service '{serviceName}', which holds its grants, is readable by accounts other than "
                + $"SYSTEM and Administrators ({who}), and this service could not restrict it: {ex.Message} Its token is "
                + "not in it. Restrict it from an elevated prompt with --service-status.");
            return;
        }
        catch (Exception ex)
        {
            warn(
                $"The registry key of service '{serviceName}', which holds its grants -- and, where an older build installed it, its bearer token -- is readable by "
                + $"accounts other than SYSTEM and Administrators ({who}), and this service could not restrict "
                + $"it: {ex.Message} From an elevated prompt, run --uninstall-service, then --install-service "
                + "--token-stdin with a new token -- the installer restricts the key -- and update the relay's "
                + "targets file: any local user may already have the current one.");
            return;
        }

        if (!holdsToken)
        {
            warn(
                $"The registry key of service '{serviceName}', which holds its grants, was readable by accounts other "
                + $"than SYSTEM and Administrators ({who}). It is now restricted to them. Its token is not in it, so "
                + "nothing needs changing.");
            return;
        }

        warn(
            $"The registry key of service '{serviceName}', which holds its grants -- and, where an older build installed it, its bearer token -- was readable by accounts "
            + $"other than SYSTEM and Administrators ({who}). It is now restricted to them, but any local user "
            + "may already have the token: change it (--uninstall-service, then --install-service "
            + "--token-stdin with a new one) and update the relay's targets file.");
    }
}
