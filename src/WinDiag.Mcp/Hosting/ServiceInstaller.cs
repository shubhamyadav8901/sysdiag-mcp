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

        Run("sc.exe", options.CreateArguments(exe), "create the service");

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

        // Printed once, here, because a generated token exists nowhere a human can read it: the
        // registry value is ACL'd and the server never logs it. Losing it means reinstalling.
        if (!options.TokenWasSupplied)
        {
            Console.Error.WriteLine();
            Console.Error.WriteLine($"    bearer token: {options.Token}");
            Console.Error.WriteLine("    This is shown once. It is stored in the service's own registry");
            Console.Error.WriteLine("    key, which only SYSTEM and Administrators can read.");
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
        var hasToken = environment.Any(v => v.StartsWith("WINDIAG_TOKEN=", StringComparison.OrdinalIgnoreCase));

        Console.Error.WriteLine($"  {serviceName}  {controller.Status}  {startType}  {account}");
        Console.Error.WriteLine($"  binPath   {binPath}");

        // Reported as configured-or-not, never echoed. The whole point of the per-service key is that
        // the token is not casually readable, and printing it here would undo that.
        Console.Error.WriteLine($"  token     {(hasToken ? "configured (per-service key)" : "NOT configured")}");

        foreach (var value in environment.Where(v => !v.StartsWith("WINDIAG_TOKEN=", StringComparison.OrdinalIgnoreCase)))
        {
            Console.Error.WriteLine($"  env       {value}");
        }

        key?.Dispose();
        return 0;
    }

    private static bool Exists(string name) =>
        ServiceController.GetServices().Any(s => string.Equals(s.ServiceName, name, StringComparison.OrdinalIgnoreCase));

    private static void WriteEnvironment(ServiceInstallOptions options)
    {
        using var key = Registry.LocalMachine.OpenSubKey(
            $@"SYSTEM\CurrentControlSet\Services\{options.Name}", writable: true)
            ?? throw new ConfigurationException(
                $"The service '{options.Name}' was created but its registry key could not be opened to "
                + "store the token. Remove it with --uninstall-service and try again.");

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
