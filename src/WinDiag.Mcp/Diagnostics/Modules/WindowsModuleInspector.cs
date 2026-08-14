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
        Exception? failure = null;

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
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException)
        {
            failure = ex;
        }

        // Enumeration fails on first access, not partway through, whenever the cause is bitness or
        // access -- so an empty list here is not a short answer, it is no answer, and returning it with
        // a warning attached would still leave "0 modules" as the headline. Throw instead: the caller
        // gets a refusal that names the fix rather than a result they have to distrust.
        if (modules.Count == 0)
        {
            var message = DescribeTotalFailure(processId, failure);
            throw failure is null
                ? new ModuleQueryException(message)
                : new ModuleQueryException(message, failure);
        }

        // Only now is "partial" the honest word: some modules came back and then enumeration stopped.
        var limitation = failure is null ? null : DescribePartialFailure(failure);

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
            Limitation: limitation,
            CollisionCount: page.Count(m => m.BaseCollision));
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
            .Select(m => !string.IsNullOrWhiteSpace(m.Path) && verdicts.TryGetValue(m.Path, out var signature)
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
        var path = module.FileName ?? string.Empty;
        var loadedAt = (ulong)module.BaseAddress.ToInt64();
        var header = PeImageReader.TryRead(path);

        return new LoadedModule(
            Name: module.ModuleName ?? "(unnamed)",
            Path: path,
            BaseAddress: Hex(loadedAt),
            SizeBytes: module.ModuleMemorySize,
            FileVersion: NullIfEmpty(info?.FileVersion),
            CompanyName: NullIfEmpty(info?.CompanyName),
            SignatureVerdict: null,
            Signer: null,
            PreferredBase: header is { } pe ? Hex(pe.ImageBase) : null,
            Relocated: header is { } relocated ? relocated.ImageBase != loadedAt : null,
            // ASLR moves nearly every system image every boot, so "relocated" alone is noise. An image
            // that never asked to be moved and was moved anyway is the opposite: something was already
            // sitting in its range, and it has just lost its shareable pages.
            BaseCollision: header is { DynamicBase: false } fixedBase && fixedBase.ImageBase != loadedAt);
    }

    private static string Hex(ulong address) =>
        "0x" + address.ToString("X", CultureInfo.InvariantCulture);

    /// <summary>Explains an enumeration that returned nothing at all.</summary>
    private static string DescribeTotalFailure(int processId, Exception? failure)
    {
        if (failure is null)
        {
            return $"PID {processId} reported no loaded modules at all, which should not happen for a " +
                   "live user-mode process. It has most likely just exited.";
        }

        if (failure is InvalidOperationException)
        {
            return $"PID {processId} exited before its modules could be read ({failure.Message}). Call " +
                   "process_list for a current PID.";
        }

        // This is the whole reason the win-x86 and win-x64 builds both exist, so name the fix rather
        // than the symptom -- an operator reading "Only partial data was returned" would go looking for
        // a permissions problem that is not there.
        var mismatch = Environment.Is64BitOperatingSystem && !Environment.Is64BitProcess;

        return mismatch
            ? $"No modules could be read from PID {processId}. This server is the 32-bit build on 64-bit " +
              "Windows, which cannot enumerate a 64-bit process's modules at all. Run the win-x64 build " +
              $"here and try again. Underlying error: {failure.Message}"
            : $"No modules could be read from PID {processId}: {failure.Message}. Either the target is a " +
              "different bitness from this server, or it is protected and even an elevated caller cannot " +
              "read it.";
    }

    /// <summary>Explains an enumeration that stopped after returning some of the list.</summary>
    private static string DescribePartialFailure(Exception failure) =>
        $"Only part of the module list could be read: {failure.Message}. What follows is a prefix of " +
        "what the process has loaded, not all of it.";

    private static Process Open(int processId)
    {
        try
        {
            // No handle probe here on purpose. Process.Handle opens with a far broader access mask than
            // reading modules needs, so probing with it would refuse processes whose modules could
            // actually have been read -- and refuse them with an elevation hint that would send the
            // caller the wrong way. Let the enumeration itself decide, and translate what it throws.
            return Process.GetProcessById(processId);
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
