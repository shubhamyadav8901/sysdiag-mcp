using System.Diagnostics;
using System.Globalization;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using MacDiag.Mcp.Configuration;

namespace MacDiag.Mcp.Hosting;

/// <summary>Installs, removes and reports on the launchd daemon. Runs as root; never starts a server itself.</summary>
public static partial class MacServiceInstaller
{
    public const string InstallDirectory = "/Library/PrivilegedHelperTools/com.sysdiag.macdiag";
    public const string InstalledExecutable = InstallDirectory + "/MacDiag.Mcp";
    public const string SettingsDirectory = "/etc/macdiag";
    public const string LogDirectory = "/var/log/macdiag";

    private const UnixFileMode OwnerOnlyFile = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private const UnixFileMode OwnerOnlyDirectory = OwnerOnlyFile | UnixFileMode.UserExecute;
    private const UnixFileMode Executable = OwnerOnlyDirectory | UnixFileMode.GroupRead | UnixFileMode.GroupExecute
                                            | UnixFileMode.OtherRead | UnixFileMode.OtherExecute;

    /// <summary>The plist's mode: root writes it, launchd and everyone else read it.</summary>
    private const UnixFileMode PlistMode = OwnerOnlyFile | UnixFileMode.GroupRead | UnixFileMode.OtherRead;

    /// <summary>How long to wait for a booted-out job to go: past the plist's ExitTimeOut, after which launchd kills it.</summary>
    internal static readonly TimeSpan UnloadBudget = MacServiceInstallOptions.ExitTimeOut + TimeSpan.FromSeconds(10);
    private static readonly TimeSpan ListenBudget = TimeSpan.FromSeconds(30);

    public static int Install(MacServiceInstallOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var source = Environment.ProcessPath ?? throw new InvalidOperationException("Cannot determine this executable's path.");

        OwnedDirectory(InstallDirectory, Executable);
        if (!string.Equals(Path.GetFullPath(source), InstalledExecutable, StringComparison.Ordinal))
        {
            // Copied beside the target and renamed over it, so a running daemon's binary is replaced atomically
            // rather than written into while it executes.
            var temp = InstalledExecutable + ".installing";
            CopyFresh(source, temp, Executable);
            File.Move(temp, InstalledExecutable, overwrite: true);
        }

        OwnedDirectory(SettingsDirectory, OwnerOnlyDirectory);
        WriteFresh(options.EnvironmentFilePath, options.EnvironmentFile(), OwnerOnlyFile);
        ArtifactDirectory(options.ArtifactDirectory ?? MacDiagOptions.DefaultArtifactDirectory, chosen: options.ArtifactDirectory is not null);
        OwnedDirectory(LogDirectory, OwnerOnlyDirectory);

        // The same check the server makes at startup, made now, so a bad tree is reported here and not as a
        // daemon that silently never comes up.
        StartupPermissions.Require(options.EnvironmentFilePath, InstalledExecutable);

        WriteFresh(options.PlistPath, options.Plist(InstalledExecutable), PlistMode);

        var target = $"system/{options.LabelName}";
        var oldPid = Loaded(target, out var pid) ? pid : null;
        foreach (var command in BringUpCommands(options.LabelName, options.PlistPath))
        {
            if (command[0] == "bootout")
            {
                if (Launchctl(["print", target], out _) == 0)
                {
                    Launchctl(command, out _);
                    // bootout returns before the job is gone; an immediate bootstrap fails with error 5.
                    if (!WaitUntil(() => Launchctl(["print", target], out _) != 0, UnloadBudget))
                    {
                        Console.Error.WriteLine($"[macdiag] '{options.LabelName}' was still loaded {UnloadBudget.TotalSeconds:0} s after bootout.");
                        return 4;
                    }
                }

                continue;
            }

            var exit = Launchctl(command, out var output);
            if (exit != 0)
            {
                Console.Error.WriteLine($"[macdiag] 'launchctl {string.Join(' ', command)}' failed (exit {exit}): {output.Trim()}");
                return 4;
            }
        }

        var portOpen = WaitForPort(options.Bind, ListenBudget);
        var loaded = Launchctl(["print", target], out var printed) == 0;
        var newPid = loaded ? PidFrom(printed) : null;
        var installed = IsInstalled(portOpen, oldPid, newPid, loaded && IsRunning(printed), Listeners(ProbeAddress(options.Bind).Port));
        var (code, message) = Outcome(installed, options.LabelName, options.Bind, LogTail());
        Console.Error.WriteLine($"[macdiag] {message}");
        Console.Error.WriteLine($"[macdiag] Application Firewall: {FirewallState()}");
        if (code == 0 && !options.TokenWasSupplied)
        {
            // Printed once, here. It is in the root-only env file from now on and never logged.
            Console.Error.WriteLine($"[macdiag] generated bearer token: {options.Token}");
        }

        return code;
    }

    public static int Uninstall(string label, bool purge)
    {
        var plist = MacServiceInstallOptions.PlistPathFor(label);
        var plistExisted = File.Exists(plist) || new FileInfo(plist).LinkTarget is not null;
        var target = $"system/{label}";
        var bootoutExit = 0;
        if (plistExisted && Launchctl(["print", target], out _) == 0)
        {
            bootoutExit = Launchctl(["bootout", target], out _);
            if (bootoutExit == 0 && !WaitUntil(() => Launchctl(["print", target], out _) != 0, UnloadBudget))
            {
                bootoutExit = -1;
            }
        }

        if (plistExisted && bootoutExit == 0)
        {
            File.Delete(plist);
            File.Delete(MacServiceInstallOptions.EnvironmentFilePathFor(label));
            if (purge && Directory.Exists(MacDiagOptions.DefaultArtifactDirectory))
            {
                Directory.Delete(MacDiagOptions.DefaultArtifactDirectory, recursive: true);
            }
        }

        var (code, message) = UninstallOutcome(label, plistExisted, bootoutExit);
        Console.Error.WriteLine($"[macdiag] {message}");
        return code;
    }

    public static int Status(string label)
    {
        var exit = Launchctl(["print", $"system/{label}"], out var output);
        Console.Error.WriteLine(output);
        return exit;
    }

    /// <summary>bootout first (a loaded job must go), enable (a disabled job refuses to bootstrap), then bootstrap.</summary>
    internal static IReadOnlyList<string[]> BringUpCommands(string label, string plist) =>
        [["bootout", $"system/{label}"], ["enable", $"system/{label}"], ["bootstrap", "system", plist]];

    /// <summary>What install reports once launchd has the job: listening or not, with the logs to say why.</summary>
    internal static (int Code, string Message) Outcome(bool listening, string label, string bind, string logTail) =>
        listening
            ? (0, $"installed and started '{label}' on {bind}")
            : (4, $"launchd loaded '{label}' but nothing new is listening on {bind} after {ListenBudget.TotalSeconds:0} s. " +
                  $"Last log lines:\n{logTail}");

    /// <summary>What uninstall reports, decided from what it found and what launchctl said.</summary>
    /// <remarks>"removed" only when there was a job and booting it out worked, as linuxdiag's uninstall decides.</remarks>
    internal static (int Code, string Message) UninstallOutcome(string label, bool plistExisted, int bootoutExit) =>
        !plistExisted
            ? (1, $"no daemon labelled '{label}' is installed; nothing was removed.")
            : bootoutExit != 0
                ? (4, $"'launchctl bootout system/{label}' failed (exit {bootoutExit}); nothing was removed. See: sudo launchctl print system/{label}")
                // The binary and, without --purge, the artifact directory stay: the artifacts may be what someone came to collect.
                : (0, $"removed '{label}'. {InstallDirectory} was kept.");

    /// <summary>The PID in <c>launchctl print</c>'s output, or null when the job is not running.</summary>
    internal static int? PidFrom(string printOutput) => Mac.Parsers.LaunchctlPrint.State(printOutput ?? string.Empty).ProcessId;

    /// <summary>Whether the job just bootstrapped is the one serving: running, a new process, and the listener itself.</summary>
    /// <remarks>
    /// "The port accepts" alone passed for a by-hand server left on the port, or for the previous process, while
    /// the new job crash-looped on bind. launchd has no readiness signal, so each condition is checked outright.
    /// </remarks>
    internal static bool IsInstalled(bool portOpen, int? oldPid, int? newPid, bool running, IReadOnlyCollection<int> listeners) =>
        portOpen && running && newPid is { } pid && pid != oldPid && listeners.Contains(pid);

    /// <summary>Whether <c>launchctl print</c> reports the job as running.</summary>
    internal static bool IsRunning(string printOutput) => Mac.Parsers.LaunchctlPrint.State(printOutput ?? string.Empty).State == "running";

    /// <summary>The PIDs in <c>lsof -t</c>'s terse output, one per line; anything else is ignored.</summary>
    internal static IReadOnlyList<int> ParsePids(string text) =>
        (text ?? string.Empty).Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
            .Select(line => int.TryParse(line, NumberStyles.None, CultureInfo.InvariantCulture, out var pid) ? pid : (int?)null)
            .OfType<int>()
            .ToList();

    /// <summary>Where to connect to see the daemon listening: loopback for a wildcard bind.</summary>
    internal static (string Host, int Port) ProbeAddress(string bind)
    {
        // A '+' or '*' host is not a valid URI host, so it is replaced before parsing.
        var uri = new Uri(WildcardHost().Replace(bind, "://0.0.0.0:"));
        return (uri.Host is "0.0.0.0" or "[::]" ? "127.0.0.1" : uri.Host, uri.Port);
    }

    private static bool Loaded(string target, out int? pid)
    {
        var exit = Launchctl(["print", target], out var output);
        pid = exit == 0 ? PidFrom(output) : null;
        return exit == 0;
    }

    private static bool WaitForPort(string bind, TimeSpan budget)
    {
        var (host, port) = ProbeAddress(bind);
        return WaitUntil(() =>
        {
            try
            {
                using var client = new TcpClient();
                client.Connect(host, port);
                return true;
            }
            catch (SocketException)
            {
                return false;
            }
        }, budget);
    }

    private static bool WaitUntil(Func<bool> condition, TimeSpan budget)
    {
        var watch = Stopwatch.StartNew();
        while (watch.Elapsed < budget)
        {
            if (condition())
            {
                return true;
            }

            Thread.Sleep(500);
        }

        return condition();
    }

    /// <summary>The end of both logs: a refused configuration reaches only crash.log, a later failure macdiag.log.</summary>
    private static string LogTail()
    {
        static string Tail(string path) =>
            File.Exists(path) ? string.Join('\n', File.ReadLines(path).TakeLast(20)) : "(empty)";

        return $"{LogDirectory}/crash.log:\n{Tail($"{LogDirectory}/crash.log")}\n{LogDirectory}/macdiag.log:\n{Tail($"{LogDirectory}/macdiag.log")}";
    }

    /// <summary>The Application Firewall's state, which can block the port with no error anywhere; never throws.</summary>
    private static string FirewallState()
    {
        try
        {
            var start = new ProcessStartInfo("/usr/libexec/ApplicationFirewall/socketfilterfw")
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            start.ArgumentList.Add("--getglobalstate");
            using var process = Process.Start(start);
            if (process is null || !process.WaitForExit(10_000))
            {
                process?.Kill();
                return "unknown";
            }

            var state = process.StandardOutput.ReadToEnd().Trim();
            return state.Length > 0 ? state : "unknown";
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or IOException)
        {
            return "unknown";
        }
    }

    /// <summary>The PIDs listening on the TCP port, from lsof; empty when none, or when lsof could not say.</summary>
    private static IReadOnlyList<int> Listeners(int port)
    {
        try
        {
            var result = new Mac.MacSystemCommand().RunAsync(
                "lsof", ["-nP", $"-iTCP:{port}", "-sTCP:LISTEN", "-t"], TimeSpan.FromSeconds(15), CancellationToken.None).GetAwaiter().GetResult();
            return ParsePids(result.StandardOutput);
        }
        catch (ExternalCommandException ex)
        {
            Console.Error.WriteLine($"[macdiag] could not ask lsof who listens on {port}: {ex.Message}");
            return [];
        }
    }

    /// <summary>Uses an existing artifact directory root alone controls, never re-chmodded, or creates one root-only.</summary>
    /// <remarks>Checked before it is created, by the directories above it: see <see cref="StartupPermissions.RequireRootOnlyDirectory"/>.</remarks>
    private static void ArtifactDirectory(string path, bool chosen)
    {
        StartupPermissions.RequireRootOnlyDirectory(path, chosen ? "--artifacts" : "The artifact directory");
        if (!Directory.Exists(path))
        {
            OwnedDirectory(path, OwnerOnlyDirectory);
        }
    }

    /// <summary>Creates the directory, or tightens an existing one: CreateDirectory leaves an existing mode alone.</summary>
    /// <remarks>Only for the installer's own fixed directories; an operator-chosen one goes through <see cref="ArtifactDirectory"/>.</remarks>
    private static void OwnedDirectory(string path, UnixFileMode mode)
    {
        Directory.CreateDirectory(path, mode);
        File.SetUnixFileMode(path, mode);
    }

    /// <summary>Copies into a file this process creates, so it is owned by the installer (root), with exactly this mode.</summary>
    /// <remarks>
    /// Not File.Copy: on macOS it clones the file, and a clone made by root keeps the source's owner. The binary an
    /// admin copied over was theirs, so the installed one was too, and the startup check refused it -- every install
    /// failed (first seen in CI's install smoke).
    /// </remarks>
    internal static void CopyFresh(string source, string path, UnixFileMode mode)
    {
        File.Delete(path);
        using var input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var output = new FileStream(path, new FileStreamOptions
        {
            Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None, UnixCreateMode = mode
        });
        input.CopyTo(output);
        File.SetUnixFileMode(path, mode);
    }

    /// <summary>Replaces whatever is at the path with a new file of exactly this mode, never writing through a link.</summary>
    internal static void WriteFresh(string path, string text, UnixFileMode mode)
    {
        File.Delete(path);
        using var stream = new FileStream(path, new FileStreamOptions
        {
            Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None, UnixCreateMode = mode
        });
        using var writer = new StreamWriter(stream);
        writer.Write(text);
    }

    private static int Launchctl(string[] args, out string output)
    {
        var start = new ProcessStartInfo("/bin/launchctl")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var a in args)
        {
            start.ArgumentList.Add(a);
        }

        using var process = Process.Start(start)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        process.WaitForExit();
        output = stdout.GetAwaiter().GetResult() + stderr.GetAwaiter().GetResult();
        return process.ExitCode;
    }

    [GeneratedRegex(@"://[+*]:")]
    private static partial Regex WildcardHost();
}
