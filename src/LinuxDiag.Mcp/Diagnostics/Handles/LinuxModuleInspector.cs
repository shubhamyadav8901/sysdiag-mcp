using System.Globalization;
using LinuxDiag.Mcp.Configuration;
using LinuxDiag.Mcp.Linux.Parsers;
using LinuxDiag.Mcp.Linux.Proc;

namespace LinuxDiag.Mcp.Diagnostics.Handles;

public interface IModuleInspector
{
    ModuleListResult Read(int processId, string? nameFilter);
}

public sealed class LinuxModuleInspector(LinuxDiagOptions options) : IModuleInspector
{
    public ModuleListResult Read(int processId, string? nameFilter)
    {
        if (processId <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(processId), "A process id must be positive. Get one from process_list.");
        }

        var statText = ProcFiles.ReadProcess(processId, "stat")
            ?? throw new ModuleQueryException(LinuxHandleInspector.NotRunning(processId));
        var stat = ProcStat.Parse(statText);
        if (stat.IsKernelThread)
        {
            throw new ModuleQueryException($"PID {processId} ({stat.Name}) is a kernel thread, which maps no files.");
        }

        string? maps;
        try
        {
            maps = ProcFiles.ReadProcess(processId, "maps");
        }
        catch (UnauthorizedAccessException)
        {
            throw new ModuleQueryException(
                $"Could not read the memory map of {stat.Name} (PID {processId}): permission denied. Reading another " +
                "user's process needs root.");
        }

        IReadOnlyList<MappedFile> files = maps is null ? [] : ProcMaps.Files(ProcMaps.Parse(maps));
        if (files.Count == 0)
        {
            throw new ModuleQueryException(
                $"{stat.Name} (PID {processId}) has no mapped files at all; it has most likely just exited, and a " +
                "zombie maps nothing. Call process_list for a current PID.");
        }

        return Build(processId, stat.Name, files, nameFilter, options.MaxResults);
    }

    internal static ModuleListResult Build(
        int processId, string processName, IReadOnlyList<MappedFile> files, string? nameFilter, int maxResults)
    {
        var matched = files
            .Select(f => new LoadedModule(
                Path.GetFileName(f.Path), f.Path, "0x" + f.BaseAddress.ToString("x", CultureInfo.InvariantCulture),
                f.SizeBytes, f.Executable, f.Deleted))
            .Where(m => string.IsNullOrWhiteSpace(nameFilter) || m.Path.Contains(nameFilter, StringComparison.OrdinalIgnoreCase))
            .ToList();

        return new ModuleListResult(
            processId, processName, matched.Take(maxResults).ToList(), matched.Count, matched.Count > maxResults,
            matched.Count(m => m.Deleted));
    }
}
