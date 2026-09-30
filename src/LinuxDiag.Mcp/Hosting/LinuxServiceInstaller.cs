using System.Diagnostics;
using LinuxDiag.Mcp.Configuration;

namespace LinuxDiag.Mcp.Hosting;

/// <summary>Installs, removes and reports on the systemd service. Runs as root; never starts a server itself.</summary>
public static class LinuxServiceInstaller
{
    public const string InstallDirectory = "/opt/linuxdiag";
    public const string InstalledExecutable = "/opt/linuxdiag/LinuxDiag.Mcp";

    private const UnixFileMode OwnerOnlyFile = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private const UnixFileMode OwnerOnlyDirectory = OwnerOnlyFile | UnixFileMode.UserExecute;
    private const UnixFileMode Executable = OwnerOnlyDirectory | UnixFileMode.GroupRead | UnixFileMode.GroupExecute
                                            | UnixFileMode.OtherRead | UnixFileMode.OtherExecute;

    public static int Install(LinuxServiceInstallOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var source = Environment.ProcessPath ?? throw new InvalidOperationException("Cannot determine this executable's path.");

        Directory.CreateDirectory(InstallDirectory, Executable);
        if (NeedsCopy(source, InstalledExecutable))
        {
            // Copied beside the target and renamed over it, so a running service's binary is replaced
            // atomically rather than written into while it executes.
            var temp = InstalledExecutable + ".installing";
            File.Copy(source, temp, overwrite: true);
            File.SetUnixFileMode(temp, Executable);
            File.Move(temp, InstalledExecutable, overwrite: true);
        }

        Directory.CreateDirectory("/etc/linuxdiag", OwnerOnlyDirectory);
        WriteOwnerOnly(options.EnvironmentFilePath, options.EnvironmentFile());
        Directory.CreateDirectory(options.ArtifactDirectory ?? LinuxDiagOptions.DefaultArtifactDirectory, OwnerOnlyDirectory);

        WriteFresh(options.UnitFilePath, options.UnitFile(InstalledExecutable), UnitFileMode);

        foreach (var command in StartCommands(options.Name))
        {
            if (Systemctl(command) != 0)
            {
                Console.Error.WriteLine(
                    $"[linuxdiag] 'systemctl {string.Join(' ', command)}' failed; the service is not running. " +
                    $"See: systemctl status {options.Name}; journalctl -u {options.Name}");
                return 4;
            }
        }

        Console.Error.WriteLine($"[linuxdiag] installed and started '{options.Name}' on {options.Bind}");
        if (!options.TokenWasSupplied)
        {
            // Printed once, here. It is in the root-only env file from now on and never logged.
            Console.Error.WriteLine($"[linuxdiag] generated bearer token: {options.Token}");
        }

        return 0;
    }

    public static int Uninstall(string name)
    {
        var unit = $"/etc/systemd/system/{name}.service";
        var unitExisted = File.Exists(unit) || new FileInfo(unit).LinkTarget is not null;
        var disableExit = unitExisted ? Systemctl("disable", "--now", name) : 0;

        if (unitExisted && disableExit == 0)
        {
            File.Delete(unit);
            File.Delete($"/etc/linuxdiag/{name}.env");
            Systemctl("daemon-reload");
        }

        var (code, message) = UninstallOutcome(name, unitExisted, disableExit);
        Console.Error.WriteLine($"[linuxdiag] {message}");
        return code;
    }

    /// <summary>What uninstall reports, decided from what it found and what systemctl said.</summary>
    /// <remarks>
    /// "removed" only when there was a unit and disabling it worked. Printing it unconditionally told an
    /// operator a service was gone when it had never been there, or was still running.
    /// </remarks>
    internal static (int Code, string Message) UninstallOutcome(string name, bool unitExisted, int disableExit) =>
        !unitExisted
            ? (1, $"no service named '{name}' is installed; nothing was removed.")
            : disableExit != 0
                ? (4, $"'systemctl disable --now {name}' failed (exit {disableExit}); nothing was removed. See: systemctl status {name}")
                // The binary and the artifact directory stay: another instance may share the binary, and
                // the artifacts may be the dumps someone came to collect.
                : (0, $"removed '{name}'. {InstallDirectory} and the artifact directory were kept.");

    public static int Status(string name) => Systemctl("status", "--no-pager", name);

    /// <summary>How the service is brought up, each step's exit code checked.</summary>
    /// <remarks>
    /// Not `enable --now`: measured on Ubuntu 24.04, it exits 0 even when the start fails or the unit
    /// never becomes ready, so the installer announced a running service that was not. A plain (re)start
    /// waits for Type=notify readiness and reports its failure; is-active then catches a process that
    /// exited after starting. restart rather than start, because start on a service that is already
    /// running is a no-op that exits 0: a re-install that changed grants, bind or token would otherwise
    /// leave the old process serving the old configuration.
    /// </remarks>
    internal static IReadOnlyList<string[]> StartCommands(string name) =>
    [
        ["daemon-reload"],
        ["enable", name],
        ["restart", name],
        ["is-active", "--quiet", name]
    ];

    internal static bool NeedsCopy(string source, string destination) =>
        !string.Equals(Path.GetFullPath(source), Path.GetFullPath(destination), StringComparison.Ordinal);

    /// <summary>The unit file's mode: root writes it, systemd and everyone else read it.</summary>
    internal const UnixFileMode UnitFileMode = OwnerOnlyFile | UnixFileMode.GroupRead | UnixFileMode.OtherRead;

    /// <summary>Replaces a file with one created 0600, so it never inherits a looser mode.</summary>
    internal static void WriteOwnerOnly(string path, string text) => WriteFresh(path, text, OwnerOnlyFile);

    /// <summary>Replaces whatever is at the path with a new file of exactly this mode.</summary>
    /// <remarks>
    /// Deleted first, then created with CreateNew: an existing file's looser mode is never inherited, and
    /// a link at the path -- `systemctl mask` leaves the unit path as one to /dev/null -- is replaced
    /// rather than written through.
    /// </remarks>
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

    private static int Systemctl(params string[] args)
    {
        var start = new ProcessStartInfo("systemctl") { UseShellExecute = false };
        foreach (var a in args)
        {
            start.ArgumentList.Add(a);
        }

        using var process = Process.Start(start)!;
        process.WaitForExit();
        return process.ExitCode;
    }
}
