using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using WinDiag.Mcp.Configuration;
using WinDiag.Mcp.Diagnostics.Signatures;

namespace WinDiag.Mcp.Diagnostics.Modules;

/// <summary>
/// Lists loaded modules from the managed process API, optionally verifying each one's signature.
/// </summary>
/// <remarks>
/// Answers the question a version conflict actually poses: not "which DLL should be loaded" but which
/// one <em>is</em>, from where, at what version — and whether anything unsigned got in. Sysinternals
/// listdlls covers the same ground, but this needs nothing installed on the target, which matters when
/// the target is a customer machine.
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class WindowsModuleInspector : IModuleInspector
{
    private readonly ISignatureInspector _signatures;
    private readonly WinDiagOptions _options;

    public WindowsModuleInspector(ISignatureInspector signatures, WinDiagOptions options)
    {
        _signatures = signatures;
        _options = options;
    }

    public ModuleListResult List(
        int processId,
        string? nameFilter,
        bool verifySignatures,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        using var process = Open(processId);
        var name = SafeName(process);

        var modules = new List<LoadedModule>();
        string? limitation = null;

        try
        {
            foreach (ProcessModule module in process.Modules)
            {
                cancellationToken.ThrowIfCancellationRequested();

                using (module)
                {
                    modules.Add(Describe(module));
                }
            }
        }
        catch (Win32Exception ex)
        {
            // The classic cause is a bitness mismatch: a 32-bit server cannot enumerate a 64-bit
            // process's modules and vice versa. Saying so beats an empty list, which reads as a
            // process that has loaded almost nothing.
            limitation = DescribeEnumerationFailure(ex);
        }
        catch (InvalidOperationException ex)
        {
            limitation = $"The process exited while its modules were being read ({ex.Message}).";
        }

        if (modules.Count == 0 && limitation is null)
        {
            throw new ModuleQueryException(
                $"No modules could be read from PID {processId}. The process may have exited, or it may " +
                "be protected.");
        }

        IEnumerable<LoadedModule> matched = modules;
        if (!string.IsNullOrWhiteSpace(nameFilter))
        {
            matched = matched.Where(m =>
                m.Name.Contains(nameFilter, StringComparison.OrdinalIgnoreCase)
                || m.Path.Contains(nameFilter, StringComparison.OrdinalIgnoreCase));
        }

        var ordered = matched.OrderBy(m => m.Name, StringComparer.OrdinalIgnoreCase).ToList();
        var truncated = ordered.Count > _options.MaxResults;
        var page = truncated ? ordered.Take(_options.MaxResults).ToList() : ordered;

        if (verifySignatures)
        {
            page = Verify(page, cancellationToken);
        }

        return new ModuleListResult(
            ProcessId: processId,
            ProcessName: name,
            Modules: page,
            TotalMatched: ordered.Count,
            Truncated: truncated,
            UnsignedCount: page.Count(m => m.SignatureVerdict is "Unsigned" or "Untrusted"),
            Limitation: limitation);
    }

    /// <summary>
    /// Verifies the returned page only, not every module in the process.
    /// </summary>
    /// <remarks>
    /// Authenticode verification is not cheap and a process can hold several hundred modules, so this
    /// is opt-in and scoped to what is actually being reported. Catalog lookup is included, which is
    /// what stops most of Windows being reported as unsigned.
    /// </remarks>
    private List<LoadedModule> Verify(List<LoadedModule> modules, CancellationToken cancellationToken)
    {
        var paths = modules.Select(m => m.Path).Where(p => !string.IsNullOrWhiteSpace(p)).Distinct().ToArray();
        if (paths.Length == 0)
        {
            return modules;
        }

        var verdicts = _signatures.Inspect(paths, cancellationToken).Files
            .ToDictionary(f => f.Path, StringComparer.OrdinalIgnoreCase);

        return modules
            .Select(m => verdicts.TryGetValue(m.Path, out var signature)
                ? m with
                {
                    SignatureVerdict = signature.Verdict.ToString(),
                    Signer = signature.Signer ?? (signature.CatalogSigned ? "(catalog)" : null)
                }
                : m)
            .ToList();
    }

    private static LoadedModule Describe(ProcessModule module)
    {
        var info = module.FileVersionInfo;

        return new LoadedModule(
            Name: module.ModuleName,
            Path: module.FileName,
            BaseAddress: "0x" + module.BaseAddress.ToInt64().ToString("X", CultureInfo.InvariantCulture),
            SizeBytes: module.ModuleMemorySize,
            FileVersion: NullIfEmpty(info?.FileVersion),
            CompanyName: NullIfEmpty(info?.CompanyName),
            SignatureVerdict: null,
            Signer: null);
    }

    private static string DescribeEnumerationFailure(Win32Exception ex)
    {
        var mismatch = Environment.Is64BitOperatingSystem && !Environment.Is64BitProcess;

        return mismatch
            ? "Only part of the module list could be read. This server is 32-bit on 64-bit Windows, " +
              "which cannot enumerate a 64-bit process's modules. Run the win-x64 build here. " +
              $"Underlying error: {ex.Message}"
            : $"Only part of the module list could be read: {ex.Message}. A bitness mismatch between " +
              "this server and the target is the usual cause; elevation is the next.";
    }

    private static Process Open(int processId)
    {
        try
        {
            var process = Process.GetProcessById(processId);
            _ = process.Handle;
            return process;
        }
        catch (ArgumentException ex)
        {
            throw new ModuleQueryException(
                $"No process with PID {processId} is running. Call process_list for a current one; PIDs " +
                "are reused.", ex);
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException)
        {
            throw new ModuleQueryException(
                $"Could not open PID {processId}: {ex.Message}. Elevation is the usual cause when the " +
                "target belongs to another user.", ex);
        }
    }

    private static string SafeName(Process process)
    {
        try
        {
            return process.ProcessName;
        }
        catch (Exception ex) when (ex is InvalidOperationException or Win32Exception)
        {
            return "(unreadable)";
        }
    }

    private static string? NullIfEmpty(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;
}
