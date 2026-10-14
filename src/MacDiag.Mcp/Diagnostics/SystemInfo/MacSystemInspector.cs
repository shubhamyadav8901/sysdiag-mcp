using System.Globalization;
using System.Runtime.InteropServices;
using MacDiag.Mcp.Configuration;
using MacDiag.Mcp.Mac.Parsers;

namespace MacDiag.Mcp.Diagnostics.SystemInfo;

/// <summary>Describes the Mac from documented tools: sw_vers, sysctl, vm_stat and mount.</summary>
public sealed class MacSystemInspector(IExternalCommand commands, IPrivilegeProbe privileges, MacDiagOptions options) : ISystemInspector
{
    /// <summary>How long one volume may take to answer: a stale network mount must not hang the call.</summary>
    private static readonly TimeSpan PerMountBudget = TimeSpan.FromSeconds(3);

    public async Task<SystemOverview> DescribeAsync(CancellationToken cancellationToken)
    {
        var limitations = new List<string>();

        async Task<string?> Run(string program, params string[] arguments)
        {
            try
            {
                var result = await commands.RunAsync(program, arguments, options.ExternalToolTimeout, cancellationToken).ConfigureAwait(false);
                if (result.ExitCode == 0)
                {
                    return result.StandardOutput;
                }

                limitations.Add($"{program} failed (exit {result.ExitCode}): {result.StandardError.Trim()}");
            }
            catch (ExternalCommandException ex)
            {
                limitations.Add(ex.Message);
            }

            return null;
        }

        var versions = await Run("sw_vers").ConfigureAwait(false) is { } swVers ? SwVers.Parse(swVers) : null;
        if (versions is not null && versions.Version is null)
        {
            limitations.Add("sw_vers printed no ProductVersion, so the macOS version is unknown.");
        }

        string?[] sysctl = [null, null, null, null];
        if (await Run("sysctl", "-n", "hw.model", "hw.memsize", "kern.osrelease", "kern.boottime").ConfigureAwait(false) is { } text)
        {
            try
            {
                sysctl = [.. Sysctl.ParseValues(text, 4)];
            }
            catch (FormatException ex)
            {
                limitations.Add(ex.Message);
            }
        }

        var memory = await Run("vm_stat").ConfigureAwait(false) is { } vm ? VmStat.Parse(vm) : null;
        if (memory is { Missing.Count: > 0 })
        {
            limitations.Add($"vm_stat's output lacked {string.Join(", ", memory.Missing)}, so available memory is unknown (shown as 0).");
        }
        var mounts = await Run("mount").ConfigureAwait(false) is { } mountText ? MountList.Parse(mountText) : [];

        var boot = Sysctl.BootTime(sysctl[3]);
        if (boot is null)
        {
            limitations.Add("kern.boottime could not be read, so boot time and uptime are unknown.");
        }

        var total = long.TryParse(sysctl[1], NumberStyles.None, CultureInfo.InvariantCulture, out var memsize) ? memsize : 0;
        if (total == 0)
        {
            limitations.Add("hw.memsize could not be read, so total memory is unknown (shown as 0).");
        }

        return new SystemOverview(
            Environment.MachineName,
            Environment.UserName,
            versions?.Version is null ? "macOS (version unknown)" : $"{versions.Name ?? "macOS"} {versions.Version} ({versions.Build ?? "?"})",
            sysctl[2] is { } release ? "Darwin " + release : "Darwin",
            RuntimeInformation.OSArchitecture.ToString(),
            sysctl[0],
            privileges.IsElevated,
            boot ?? DateTimeOffset.UnixEpoch,
            boot is { } b ? DateTimeOffset.UtcNow - b : TimeSpan.Zero,
            Environment.ProcessorCount,
            total,
            memory?.AvailableBytes ?? 0,
            Filesystems(MountList.ForSpace(mounts), DriveSize, PerMountBudget, limitations),
            limitations);
    }

    private static (long Total, long Free) DriveSize(string mountPoint)
    {
        var drive = new DriveInfo(mountPoint);
        return (drive.TotalSize, drive.AvailableFreeSpace);
    }

    /// <param name="size">Asks one volume its size; DriveInfo in production, which statfs(2)s it.</param>
    internal static List<MountedFilesystem> Filesystems(
        IEnumerable<MacMount> mounts, Func<string, (long Total, long Free)> size, TimeSpan perMount, List<string> limitations)
    {
        var result = new List<MountedFilesystem>();
        foreach (var mount in mounts)
        {
            long totalBytes = 0, freeBytes = 0;
            // A thread of its own, not the pool's: a probe stuck in the kernel on a dead network mount keeps its thread
            // for good, and on a small, busy pool the next mount's probe then waited for a thread longer than its whole
            // budget, so a healthy volume was reported as not answering (LinuxDiag, on a two-core CI runner).
            var probe = Task.Factory.StartNew(
                () => size(mount.MountPoint), CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);

            try
            {
                if (probe.Wait(perMount))
                {
                    (totalBytes, freeBytes) = probe.Result;
                }
                else
                {
                    limitations.Add($"{mount.MountPoint} did not answer within {perMount.TotalSeconds:0} s, so its size is unknown (shown as 0).");
                }
            }
            catch (AggregateException ex) when (ex.InnerException is IOException or UnauthorizedAccessException)
            {
                limitations.Add($"{mount.MountPoint}'s size could not be read: {ex.InnerException.Message}");
            }

            result.Add(new MountedFilesystem(mount.MountPoint, mount.Device, mount.FileSystem, totalBytes, freeBytes, mount.ReadOnly));
        }

        return result;
    }
}
