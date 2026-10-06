namespace WinDiag.Mcp.Hosting;

/// <summary>
/// Refuses to run as a service from a directory someone other than an administrator can write, after
/// first trying to put that right.
/// </summary>
/// <remarks>
/// <para>MacDiag refuses outright. Here a plain refusal would strand every target installed before
/// directories were protected: <c>update_self</c> swaps in this build, the build refuses to start, and
/// the machine goes quiet with nobody at its console -- the exact visit a service exists to remove.
/// This process is SYSTEM, the same rights the installer has, so it applies the installer's ACL itself
/// and says so in the event log. It refuses only when that does not work, because then a local user
/// can still plant what it is about to run.</para>
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
}
