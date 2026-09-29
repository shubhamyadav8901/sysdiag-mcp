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

        File.WriteAllText(options.UnitFilePath, options.UnitFile(InstalledExecutable));
        File.SetUnixFileMode(options.UnitFilePath, OwnerOnlyFile | UnixFileMode.GroupRead | UnixFileMode.OtherRead);

        if (Systemctl("daemon-reload") != 0 || Systemctl("enable", "--now", options.Name) != 0)
        {
            Console.Error.WriteLine($"[linuxdiag] systemctl failed; see: systemctl status {options.Name}");
            return 4;
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
        Systemctl("disable", "--now", name);
        File.Delete($"/etc/systemd/system/{name}.service");
        File.Delete($"/etc/linuxdiag/{name}.env");
        Systemctl("daemon-reload");

        // The binary and the artifact directory stay: another instance may share the binary, and the
        // artifacts may be the dumps someone came to collect.
        Console.Error.WriteLine($"[linuxdiag] removed '{name}'. {InstallDirectory} and the artifact directory were kept.");
        return 0;
    }

    public static int Status(string name) => Systemctl("status", "--no-pager", name);

    internal static bool NeedsCopy(string source, string destination) =>
        !string.Equals(Path.GetFullPath(source), Path.GetFullPath(destination), StringComparison.Ordinal);

    /// <summary>Replaces a file with one created 0600, so it never inherits a looser mode.</summary>
    internal static void WriteOwnerOnly(string path, string text)
    {
        File.Delete(path);
        using var stream = new FileStream(path, new FileStreamOptions
        {
            Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None, UnixCreateMode = OwnerOnlyFile
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
