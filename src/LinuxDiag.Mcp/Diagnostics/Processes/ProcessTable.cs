using LinuxDiag.Mcp.Linux.Parsers;
using LinuxDiag.Mcp.Linux.Proc;

namespace LinuxDiag.Mcp.Diagnostics.Processes;

/// <summary>One process as one walk of /proc saw it.</summary>
/// <param name="StartTimeTicks">Raw start time: what identity checks compare, never the wall-clock form.</param>
/// <param name="CommandLineDenied">The command line exists but could not be read -- not the same as having none.</param>
/// <param name="InnermostProcessId">The PID inside its container's PID namespace, or null outside one.</param>
public sealed record ProcessRecord(
    int ProcessId, int ParentProcessId, string Name, string State, bool KernelThread, long StartTimeTicks,
    DateTimeOffset StartTime, long ResidentBytes, int ThreadCount, long? UserId, string? ExecutablePath,
    string? CommandLine, bool CommandLineDenied, string CgroupPath, ContainerReference? Container,
    int? InnermostProcessId, string? NetworkNamespace, string? MountNamespace);

/// <param name="Unreadable">Processes listed but not readable at all: counted, so a result can say it is partial.</param>
public sealed record ProcessTable(IReadOnlyList<ProcessRecord> Processes, int Unreadable);

public interface IProcessTable
{
    ProcessTable Read(CancellationToken cancellationToken);
}

/// <summary>The text one walk read for one process, before parsing.</summary>
public sealed record RawProcess(
    int ProcessId, string Stat, string? Status, string? CommandLine, string? Cgroup, string? ExecutablePath,
    string? NetworkNamespace, string? MountNamespace, bool CommandLineDenied);

public sealed class LinuxProcessTable : IProcessTable
{
    /// <summary>USER_HZ. Fixed at 100 by the x86 ABI, which is the only architecture this server runs on.</summary>
    internal const int ClockTicksPerSecond = 100;

    public ProcessTable Read(CancellationToken cancellationToken)
    {
        var boot = KernelStat.BootTime(ProcFiles.Read(ProcFiles.KernelStat));
        var processes = new List<ProcessRecord>();
        var unreadable = 0;

        foreach (var pid in ProcFiles.ProcessIds())
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                if (Collect(pid) is { } raw)
                {
                    processes.Add(Parse(raw, boot));
                }
            }
            catch (UnauthorizedAccessException)
            {
                unreadable++;
            }
        }

        return new ProcessTable(processes, unreadable);
    }

    /// <summary>Reads one process's files, or null when it exited before its stat could be read.</summary>
    internal static RawProcess? Collect(int pid)
    {
        var stat = ProcFiles.ReadProcess(pid, "stat");
        if (stat is null)
        {
            return null;
        }

        // A kernel thread has no command line and no executable; reading exe for one fails with ENOENT
        // while it is alive, which is not an error worth surfacing.
        var kernel = ProcStat.Parse(stat).IsKernelThread;
        string? cmdline = null;
        var denied = false;
        if (!kernel)
        {
            try
            {
                cmdline = ProcFiles.ReadProcess(pid, "cmdline");
            }
            catch (UnauthorizedAccessException)
            {
                denied = true;
            }
        }

        return new RawProcess(
            pid, stat,
            Optional(() => ProcFiles.ReadProcess(pid, "status")),
            cmdline,
            Optional(() => ProcFiles.ReadProcess(pid, "cgroup")),
            kernel ? null : Optional(() => ProcFiles.ReadProcessLink(pid, "exe")),
            Optional(() => ProcFiles.ReadProcessLink(pid, "ns/net")),
            Optional(() => ProcFiles.ReadProcessLink(pid, "ns/mnt")),
            denied);
    }

    internal static ProcessRecord Parse(RawProcess raw, DateTimeOffset bootTime)
    {
        var stat = ProcStat.Parse(raw.Stat);
        var status = raw.Status is null ? null : ProcStatus.Parse(raw.Status);
        var cgroup = raw.Cgroup is null ? "/" : CgroupPath.Parse(raw.Cgroup);

        return new ProcessRecord(
            stat.ProcessId, stat.ParentProcessId, stat.Name, stat.State, stat.IsKernelThread, stat.StartTimeTicks,
            bootTime + TimeSpan.FromSeconds(stat.StartTimeTicks / (double)ClockTicksPerSecond),
            stat.ResidentPages * Environment.SystemPageSize, stat.ThreadCount, status?.RealUserId,
            stat.IsKernelThread ? null : raw.ExecutablePath,
            stat.IsKernelThread ? null : CommandLine(raw.CommandLine),
            raw.CommandLineDenied,
            cgroup, raw.Cgroup is null ? null : CgroupPath.ContainerOf(raw.Cgroup), status?.InnermostProcessId,
            raw.NetworkNamespace, raw.MountNamespace);
    }

    /// <summary>argv as one line: NUL-separated in /proc, and empty for a zombie or a kernel thread.</summary>
    private static string? CommandLine(string? raw)
    {
        var line = raw?.TrimEnd('\0').Replace('\0', ' ');
        return string.IsNullOrEmpty(line) ? null : line;
    }

    /// <summary>An attribute that is nice to have: a failure to read it leaves it null rather than losing the process.</summary>
    private static string? Optional(Func<string?> read)
    {
        try
        {
            return read();
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            return null;
        }
    }
}
