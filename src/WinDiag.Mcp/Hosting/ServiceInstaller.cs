using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.ServiceProcess;
using Microsoft.Win32;
using WinDiag.Mcp.Configuration;

namespace WinDiag.Mcp.Hosting;

/// <summary>
/// Registers, removes and reports on this executable as a Windows service.
/// </summary>
/// <remarks>
/// <para>Exists so a target can be set up from the one file that is already on it. Everything here can
/// be done by hand with sc.exe, reg.exe and netsh, and doing it by hand is how three separate details
/// get missed: the token ends up somewhere every local user can read, the artifact directory silently
/// moves to <c>C:\Windows\SystemTemp</c>, and the grants the by-hand server had are quietly dropped so
/// the service comes back with fewer tools than it went away with.</para>
/// <para>The pure parts -- parsing and argument construction -- live in
/// <see cref="ServiceInstallOptions"/> and are tested. This file runs the commands.</para>
/// <para>One thing install adds that uninstall deliberately does not remove: the
/// <see cref="EventLogSink.SourceName"/> event log source. It is machine-global and shared by every
/// windiag on the box regardless of <c>--service-name</c>, so deleting it with one service would
/// silence any other instance still running. It is a one-time administrative registration that costs
/// a single registry key, and leaving it is the lesser of the two surprises.</para>
/// </remarks>
[SupportedOSPlatform("windows")]
public static class ServiceInstaller
{
    /// <summary>True when this process can talk to the Service Control Manager.</summary>
    public static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    /// <summary>
    /// Runs this executable again, elevated, with the same arguments.
    /// </summary>
    /// <remarks>
    /// A UAC prompt is the honest way to ask: it is user-initiated, it names the executable, and it
    /// shows its signature. Declining is a normal answer, not a failure to handle -- the caller is told
    /// how to proceed rather than left with a stack trace.
    /// </remarks>
    public static int RelaunchElevated(IReadOnlyList<string> args)
    {
        var exe = Environment.ProcessPath
                  ?? throw new ConfigurationException("Cannot determine this executable's own path.");

        var start = new ProcessStartInfo
        {
            FileName = exe,
            UseShellExecute = true,
            Verb = "runas"
        };

        foreach (var arg in args)
        {
            start.ArgumentList.Add(arg);
        }

        try
        {
            using var elevated = Process.Start(start);
            if (elevated is null)
            {
                return 1;
            }

            elevated.WaitForExit();

            // The child ran in its own console window, which closed the instant it exited, taking every
            // line it wrote with it. Without this the unelevated caller -- the common path, since that
            // is what triggers elevation at all -- sees "requesting elevation...", a window flash, and
            // an exit code, which is less than they had before any of this reported errors at all.
            if (elevated.ExitCode != 0)
            {
                Console.Error.WriteLine(
                    $"[windiag] the elevated run exited {elevated.ExitCode} and its window has closed. "
                    + "Re-run this from an already-elevated terminal to see what it said.");
            }

            return elevated.ExitCode;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            // 1223 is "the operation was cancelled by the user" -- a declined prompt, not a fault.
            Console.Error.WriteLine(
                "[windiag] elevation was refused. Re-run this from an elevated terminal, or approve the "
                + "prompt. Registering a service requires administrator rights.");
            return 3;
        }
    }

    /// <summary>Creates the service, configures it, and starts it.</summary>
    public static int Install(ServiceInstallOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var exe = Environment.ProcessPath
                  ?? throw new ConfigurationException("Cannot determine this executable's own path.");

        if (Exists(options.Name))
        {
            Console.Error.WriteLine(
                $"[windiag] a service named '{options.Name}' already exists. Remove it first with "
                + $"--uninstall-service, or install under a different --service-name.");
            return 2;
        }

        // Before the service exists, because this is the moment the rights are certainly there. A
        // service has no stderr, so the event log is its only sink -- and an unregistered source makes
        // writing to it throw, which once cost a working update_self on a running service.
        if (!EventLogSink.TryRegisterSource())
        {
            Console.Error.WriteLine(
                $"[windiag] could not register the '{EventLogSink.SourceName}' event log source; the "
                + "service will run without event log output. Tools are unaffected.");
        }

        // Before the service exists, so a refusal leaves nothing registered. The server runs Sysinternals
        // binaries from beside itself and self-update.cmd from the artifact directory, as SYSTEM; under
        // C:\ both directories would otherwise inherit "Authenticated Users: Modify".
        var account = ProtectedAcl.AccountSid(options.Account);
        PrepareDirectory("server directory", Path.GetDirectoryName(exe)!, account, serverDirectory: true);
        if (!string.IsNullOrWhiteSpace(options.ArtifactDirectory))
        {
            PrepareDirectory("artifact directory", options.ArtifactDirectory, account, serverDirectory: false);
        }

        Run("sc.exe", options.CreateArguments(exe), "create the service");

        // sc.exe creates the key with the Services key's ACL, which lets every local user read its values.
        // Nothing secret goes into it any more, but its grants should not be readable by everyone either, and
        // the service's own start-up check would otherwise find it open and warn on every start.
        ProtectedAcl.ProtectServiceKey(options.Name);

        // The token goes into a subkey created restricted, never into this key's Environment value: this key
        // was readable until the line above, and a handle opened on it meanwhile still reads whatever is
        // written to it now. See ProtectedAcl.CreateTokenKey.
        ProtectedAcl.CreateTokenKey(options.Name, account, options.Token);

        // Written after creation because the key does not exist until the service does.
        WriteEnvironment(options);

        if (options.RestartOnFailure)
        {
            Run("sc.exe", options.FailureArguments(), "configure restart-on-failure");
        }

        if (!string.IsNullOrWhiteSpace(options.FirewallFrom))
        {
            Run("netsh", options.FirewallAddArguments(), "add the firewall rule");
        }

        Run("sc.exe", ["start", options.Name], "start the service");

        Console.Error.WriteLine($"[windiag] installed '{options.Name}' and started it on {options.Bind}.");

        // Printed so a grant that did not make it -- the failure mode the install flags have always had --
        // is on the screen at the moment it can still be corrected.
        Console.Error.WriteLine(
            $"[windiag] read-only: {YesNo(options.ReadOnly)}; self-update: {YesNo(options.AllowSelfUpdate)}; "
            + $"command execution: {YesNo(options.AllowCommandExecution)}; arbitrary write: "
            + $"{YesNo(options.AllowArbitraryWrite)}; arbitrary read: {YesNo(options.AllowArbitraryRead)}.");

        // Printed once, here, because a generated token exists nowhere a human can read it: the
        // registry key was restricted above and the server never logs it. Losing it means reinstalling.
        if (!options.TokenWasSupplied)
        {
            Console.Error.WriteLine();
            Console.Error.WriteLine($"    bearer token: {options.Token}");
            Console.Error.WriteLine("    This is shown once. It is stored in a registry key that was created");
            Console.Error.WriteLine("    readable only by SYSTEM, Administrators and the service's account.");
        }

        return 0;
    }

    /// <summary>Stops and deletes the service, and removes what install added alongside it.</summary>
    public static int Uninstall(ServiceInstallOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (!Exists(options.Name))
        {
            Console.Error.WriteLine($"[windiag] no service named '{options.Name}' is registered.");
            return 2;
        }

        // Best-effort: a service that is already stopped, or a rule that was never added, must not turn
        // an uninstall into a half-removed registration.
        Run("sc.exe", ["stop", options.Name], "stop the service", tolerateFailure: true);
        Run("netsh", options.FirewallDeleteArguments(), "remove the firewall rule", tolerateFailure: true);
        Run("sc.exe", ["delete", options.Name], "delete the service");

        Console.Error.WriteLine($"[windiag] removed '{options.Name}'.");
        return 0;
    }

    /// <summary>
    /// Reports whether this machine runs windiag as a service, and how it is configured.
    /// </summary>
    /// <remarks>
    /// The question this answers is one the machine cannot otherwise be asked in a single step: is this
    /// target running by hand or as a service? Those two look identical from the outside and behave
    /// differently on every restart.
    /// </remarks>
    public static int Status(string serviceName)
    {
        if (!Exists(serviceName))
        {
            Console.Error.WriteLine(
                $"[windiag] '{serviceName}' is not registered as a service on this machine. If a server "
                + "is answering here, it was started by hand.");
            return 1;
        }

        using var controller = new ServiceController(serviceName);
        var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{serviceName}");

        var binPath = key?.GetValue("ImagePath") as string ?? "(unknown)";
        var startType = key?.GetValue("Start") switch
        {
            2 => key.GetValue("DelayedAutoStart") is 1 ? "delayed-auto" : "auto",
            3 => "demand",
            4 => "disabled",
            _ => "(unknown)"
        };

        var account = key?.GetValue("ObjectName") as string ?? "(unknown)";
        var environment = key?.GetValue("Environment") as string[] ?? [];
        var inEnvironment = environment.Any(v => v.StartsWith("WINDIAG_TOKEN=", StringComparison.OrdinalIgnoreCase));

        Console.Error.WriteLine($"  {serviceName}  {controller.Status}  {startType}  {account}");
        Console.Error.WriteLine($"  binPath   {binPath}");

        // Reported as configured-or-not, never echoed. The whole point of the token key is that the token is
        // not casually readable, and printing it here would undo that.
        Console.Error.WriteLine($"  token     {DescribeToken(serviceName, account, inEnvironment)}");

        // Installs made before the key was restricted are still out there, and this is the one command
        // an operator runs on a target to ask how it is set up.
        // Restricted here rather than left to the service: status runs elevated, while a service running as
        // NetworkService or LocalService cannot change its own key's DACL, so "restart it" would leave the
        // token readable for those accounts.
        var exposed = ProtectedAcl.ServiceKeyExposures(serviceName);
        if (exposed.Count == 0)
        {
            Console.Error.WriteLine("  key ACL   SYSTEM and Administrators only");
        }
        else
        {
            string outcome;
            try
            {
                ProtectedAcl.ProtectServiceKey(serviceName);
                outcome = ProtectedAcl.ServiceKeyExposures(serviceName).Count == 0
                    ? "Restricted it to SYSTEM and Administrators now"
                    : "Tried to restrict it, but it is still exposed";
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
            {
                outcome = $"Could not restrict it ({ex.Message})";
            }

            Console.Error.WriteLine(
                $"  key ACL   WARNING: {string.Join("; ", exposed)}. {outcome}. Any local user may already have "
                + "the token: change it - --uninstall-service, then --install-service --token-stdin with a new one.");
        }

        foreach (var value in environment.Where(v => !v.StartsWith("WINDIAG_TOKEN=", StringComparison.OrdinalIgnoreCase)))
        {
            Console.Error.WriteLine($"  env       {value}");
        }

        key?.Dispose();
        return 0;
    }

    private static string YesNo(bool value) => value ? "yes" : "no";

    /// <summary>Where the token is, and whether anyone else can read it there.</summary>
    /// <remarks>
    /// A token still in the Environment value is from an older build's install. It is not moved here: status
    /// reports, and the token was readable while it sat in a key sc.exe made, so the remedy is a new one.
    /// </remarks>
    private static string DescribeToken(string serviceName, string account, bool inEnvironment)
    {
        System.Security.Principal.SecurityIdentifier? sid = null;
        try
        {
            sid = ProtectedAcl.AccountSid(account);
        }
        catch (Exception ex) when (ex is ConfigurationException or SystemException)
        {
            // An account this machine cannot name any more; judged as LocalSystem, so its ACE is reported.
        }

        IReadOnlyList<string>? exposed;
        try
        {
            exposed = ProtectedAcl.TokenKeyExposures(serviceName, sid);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            return $"could not read the token key's ACL ({ex.Message})";
        }

        if (exposed is null)
        {
            return inEnvironment
                ? "configured in the service key's Environment value, as an older build installed it. Any local user "
                  + "could read that key until it was restricted: reinstall (--uninstall-service, then --install-service "
                  + "--token-stdin) with a new token, which goes into a key of its own"
                : "NOT configured";
        }

        return exposed.Count == 0
            ? @$"configured (HKLM\{ServiceInstallOptions.TokenKeyPath(serviceName)}, SYSTEM, Administrators and the service's account only)"
            : $"WARNING: the token key can be read by others ({string.Join("; ", exposed)}). Reinstall with a new token.";
    }

    /// <summary>Creates a directory the service will use, uses one that is already restricted, or refuses.</summary>
    /// <remarks>
    /// Never takes an exposed directory over: see <see cref="StartupPermissions.JudgeForInstall"/>. One that is
    /// restricted is used as it is, so a server installed from Program Files keeps the ACL Windows gave it rather
    /// than being rewritten to an equivalent one. The drive-root refusal lives in ProtectDirectory.
    /// </remarks>
    private static void PrepareDirectory(
        string what, string path, System.Security.Principal.SecurityIdentifier? account, bool serverDirectory)
    {
        var exists = Directory.Exists(path);
        var exposures = exists ? ProtectedAcl.DirectoryExposures(path, account) : [];
        var beyondAdministrators = exposures.Count > 0 ? ProtectedAcl.DirectoryExposures(path, account, trustAdministratorMembers: true) : [];
        var verdict = StartupPermissions.JudgeForInstall(exists, exposures, beyondAdministrators);

        // A folder that also holds other things -- an administrator's own Downloads -- is theirs, and restricting it
        // to SYSTEM and Administrators would take it away from them; refused even when only they could change it.
        var foreign = serverDirectory && (verdict is StartupPermissions.InstallDirectory.Refuse or StartupPermissions.InstallDirectory.TakeOver)
            ? ServiceInstallOptions.ForeignToServerDirectory(Directory.EnumerateFileSystemEntries(path).Select(e => Path.GetFileName(e)))
            : [];
        if (verdict == StartupPermissions.InstallDirectory.Refuse || foreign.Count > 0)
        {
            throw new ConfigurationException(StartupPermissions.InstallRefusal(
                what, path, beyondAdministrators.Count > 0 ? beyondAdministrators : exposures, foreign, serverDirectory));
        }

        if (verdict == StartupPermissions.InstallDirectory.TakeOver)
        {
            // Elevated, so it can make Administrators the owner of everything in it.
            ProtectedAcl.ProtectDirectory(path, account, ownedByAdministrators: true);
            Console.Error.WriteLine(
                $"[windiag] handed what the {what} {path} holds to Administrators ({string.Join("; ", exposures)}); only "
                + "administrators could change it.");
            return;
        }

        if (verdict == StartupPermissions.InstallDirectory.Create)
        {
            // Created with the ACL in the create call, and refused if somebody made it in the moment since it
            // was found missing: that one is theirs.
            ProtectedAcl.ProtectDirectory(path, account, ownedByAdministrators: true, adoptExisting: false);
            Console.Error.WriteLine($"[windiag] created the {what} {path}, restricted to SYSTEM and Administrators.");
            return;
        }

        // Already restricted -- by the bootstrap scripts, or an earlier LocalSystem install -- but a service
        // running as another account still needs its own ACE, or the SCM cannot start the image and the
        // service cannot write its artifacts. Given by protecting it again, not by adding the ACE by path:
        // that carries it down the tree as Windows does, into the file behind any hard link an
        // administrator left there, while ProtectDirectory refuses one and writes each item itself.
        if (account is not null && account != ProtectedAcl.LocalSystem
            && !ProtectedAcl.GrantsServiceAccount(new DirectoryInfo(path).GetAccessControl(System.Security.AccessControl.AccessControlSections.Access), account))
        {
            ProtectedAcl.ProtectDirectory(path, account, ownedByAdministrators: true);
            Console.Error.WriteLine($"[windiag] gave {account.Translate(typeof(System.Security.Principal.NTAccount))} access to the {what} {path}.");
        }
    }

    private static bool Exists(string name) =>
        ServiceController.GetServices().Any(s => string.Equals(s.ServiceName, name, StringComparison.OrdinalIgnoreCase));

    private static void WriteEnvironment(ServiceInstallOptions options)
    {
        using var key = Registry.LocalMachine.OpenSubKey(
            $@"SYSTEM\CurrentControlSet\Services\{options.Name}", writable: true)
            ?? throw new ConfigurationException(
                $"The service '{options.Name}' was created but its registry key could not be opened to "
                + "store its settings. Remove it with --uninstall-service and try again.");

        key.SetValue("Environment", options.EnvironmentBlock().ToArray(), RegistryValueKind.MultiString);
    }

    private static void Run(
        string fileName, IReadOnlyList<string> arguments, string what, bool tolerateFailure = false)
    {
        var start = new ProcessStartInfo
        {
            FileName = fileName,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        using var process = Process.Start(start)
            ?? throw new ConfigurationException($"Could not run {fileName} to {what}.");

        var output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
        process.WaitForExit();

        if (process.ExitCode != 0 && !tolerateFailure)
        {
            throw new ConfigurationException(
                $"Failed to {what}: {fileName} exited {process.ExitCode}. {output.Trim()}");
        }
    }
}
