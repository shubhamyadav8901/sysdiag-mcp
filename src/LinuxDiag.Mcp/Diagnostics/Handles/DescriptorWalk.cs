using System.Globalization;
using LinuxDiag.Mcp.Diagnostics.Processes;
using LinuxDiag.Mcp.Linux.Proc;

namespace LinuxDiag.Mcp.Diagnostics.Handles;

public sealed record OpenDescriptor(ProcessRecord Process, int Descriptor, string Target)
{
    /// <summary>The magic link itself: opening or statx-ing it reaches the open file, whatever its name now.</summary>
    public string LinkPath => ProcFiles.Of(Process.ProcessId, "fd/" + Descriptor.ToString(CultureInfo.InvariantCulture));
}

/// <param name="UnreadableProcesses">Includes the process table's own unreadable count.</param>
public sealed record DescriptorSnapshot(IReadOnlyList<OpenDescriptor> Descriptors, int UnreadableProcesses);

/// <summary>Every process's open descriptors, in one pass: the tools that search the whole machine share it.</summary>
public static class DescriptorWalk
{
    public static DescriptorSnapshot All(ProcessTable table, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(table);

        var descriptors = new List<OpenDescriptor>();
        var unreadable = table.Unreadable;
        foreach (var process in table.Processes)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (process.KernelThread)
            {
                continue;
            }

            try
            {
                foreach (var (fd, target) in ProcFiles.Descriptors(process.ProcessId) ?? Array.Empty<(int, string)>())
                {
                    descriptors.Add(new OpenDescriptor(process, fd, target));
                }
            }
            catch (UnauthorizedAccessException)
            {
                unreadable++;
            }
        }

        return new DescriptorSnapshot(descriptors, unreadable);
    }
}
