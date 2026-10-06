using System.Diagnostics;
using LinuxDiag.Mcp.Configuration;
using LinuxDiag.Mcp.Linux.Native;

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

        // First, so a refused --artifacts leaves everything as it was.
        ArtifactDirectory(options.ArtifactDirectory);

        OwnedDirectory(InstallDirectory, Executable);
        if (NeedsCopy(source, InstalledExecutable))
        {
            // Copied beside the target and renamed over it, so a running service's binary is replaced
            // atomically rather than written into while it executes. Deleted first, never overwritten: a file
            // left there by whoever owned the directory before keeps its owner when written into.
            var temp = InstalledExecutable + ".installing";
            File.Delete(temp);
            File.Copy(source, temp);
            File.SetUnixFileMode(temp, Executable);
            File.Move(temp, InstalledExecutable, overwrite: true);
        }
        else
        {
            // Installing from the installed path: the binary may be one the operator's own account put there,
            // so it is made root's, as a copied one is.
            LibC.ChangeOwner(InstalledExecutable, 0, 0);
            File.SetUnixFileMode(InstalledExecutable, Executable);
        }

        OwnedDirectory("/etc/linuxdiag", OwnerOnlyDirectory);
        WriteOwnerOnly(options.EnvironmentFilePath, options.EnvironmentFile());

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
        Console.Error.WriteLine($"[linuxdiag] grants: {options.Grants()}");
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

    /// <summary>Creates the artifact directory root-only, or uses an existing one only root controls -- never re-chmodded.</summary>
    /// <remarks>
    /// <para>update_self writes the script root runs into it, and the log root writes, and put_file writes there
    /// freely. An existing --artifacts directory another account could write, or replace through a directory above
    /// it, is root code execution at the next update, so it is refused rather than used.</para>
    /// <para>Never chmodded or chowned: --artifacts /tmp would make /tmp root's 0700 and break every other account
    /// (MacDiag did exactly that on a Mac). The default is the installer's own, and is made root's 0700.</para>
    /// </remarks>
    internal static void ArtifactDirectory(string? requested)
    {
        if (requested is null)
        {
            OwnedDirectory(LinuxDiagOptions.DefaultArtifactDirectory, OwnerOnlyDirectory);
            return;
        }

        if (!Directory.Exists(requested) && !File.Exists(requested) && new FileInfo(requested).LinkTarget is null)
        {
            // Judged before it is made: made first and checked after, a refusal left a new root directory, and
            // every missing one between, under the parent it refused.
            RefuseArtifacts(requested, TrustedDirectory.ProblemsBeforeCreating(requested, RootOnly));
            Directory.CreateDirectory(requested, OwnerOnlyDirectory);
        }

        RefuseArtifacts(requested, TrustedDirectory.Problems(requested, RootOnly));
    }

    private static void RefuseArtifacts(string requested, IReadOnlyList<string> problems)
    {
        if (problems.Count > 0)
        {
            throw new ConfigurationException(
                $"--artifacts {requested} cannot be used: {string.Join(" ", problems)} Choose a directory only root can " +
                "write, or let the installer create one. Nothing was installed.");
        }
    }

    /// <summary>Creates the directory, or takes an existing one over: root's, with exactly this mode.</summary>
    /// <remarks>
    /// Only for the installer's own fixed directories. CreateDirectory applies a mode only to a directory it creates,
    /// so /opt/linuxdiag pre-created by the operator's account -- to scp the binary into -- stayed theirs, and a root
    /// service ran a binary from a directory another account could write.
    /// </remarks>
    private static void OwnedDirectory(string path, UnixFileMode mode)
    {
        if (new FileInfo(path).LinkTarget is not null)
        {
            throw new ConfigurationException(
                $"{path} is a symbolic link. The installer makes it a directory only root controls; remove the link and install again.");
        }

        Directory.CreateDirectory(path, mode);
        LibC.ChangeOwner(path, 0, 0);
        File.SetUnixFileMode(path, mode);
        if (TrustedDirectory.Problems(path, RootOnly) is { Count: > 0 } problems)
        {
            throw new ConfigurationException(
                $"{path} cannot be used: {string.Join(" ", problems)} Make the directories above it root's and not " +
                "writable by group or others (chown root:root, chmod go-w), and install again.");
        }
    }

    private static readonly uint[] RootOnly = [0];

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
