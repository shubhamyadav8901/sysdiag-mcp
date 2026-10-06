using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;
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
/// <para>Version and signature can only be read from a file, and the file at a module's path need not
/// be the one that was loaded: NTFS lets a loaded DLL be renamed, and something else put in its place.
/// So each module's PE header is also read from the process's own mapping and compared with the file's;
/// a module whose file no longer matches is flagged and its signature is not checked, rather than
/// reported with the verdict of a file it never ran.</para>
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
        using var memory = LoadedImageReader.Open(processId);

        var modules = new List<LoadedModule>();
        Exception? failure = null;

        try
        {
            foreach (ProcessModule module in process.Modules)
            {
                cancellationToken.ThrowIfCancellationRequested();

                using (module)
                {
                    modules.Add(Describe(module, memory));
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
            CollisionCount: page.Count(m => m.BaseCollision),
            ReplacedCount: ordered.Count(m => m.ReplacedOnDisk == true));
    }

    /// <summary>
    /// Verifies the returned page only, not every module in the process.
    /// </summary>
    /// <remarks>
    /// Authenticode verification is not cheap and a process can hold several hundred modules, so this
    /// is opt-in and scoped to what is actually being reported. Catalog lookup is included, which is
    /// what stops most of Windows being reported as unsigned.
    /// </remarks>
    /// <para>A module whose file has been replaced is left unverified. The verdict would be the
    /// replacement's, and reporting it was the hole: rename an unsigned DLL away while it is loaded, put a
    /// signed copy at its path, and it was reported as signed by Microsoft.</para>
    internal List<LoadedModule> Verify(List<LoadedModule> modules, CancellationToken cancellationToken)
    {
        var paths = modules
            .Where(m => m.ReplacedOnDisk != true)
            .Select(m => m.Path)
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .Distinct()
            .ToArray();
        if (paths.Length == 0)
        {
            return modules;
        }

        var verdicts = _signatures.Inspect(paths, cancellationToken).Files
            .ToDictionary(f => f.Path, StringComparer.OrdinalIgnoreCase);

        return modules
            .Select(m => m.ReplacedOnDisk != true
                         && !string.IsNullOrWhiteSpace(m.Path)
                         && verdicts.TryGetValue(m.Path, out var signature)
                ? m with
                {
                    SignatureVerdict = signature.Verdict.ToString(),
                    Signer = signature.Signer ?? (signature.CatalogSigned ? "(catalog)" : null)
                }
                : m)
            .ToList();
    }

    private static LoadedModule Describe(ProcessModule module, LoadedImageReader memory)
    {
        var info = module.FileVersionInfo;
        var path = module.FileName ?? string.Empty;

        return Describe(
            name: module.ModuleName ?? "(unnamed)",
            path: path,
            loadedAt: (ulong)module.BaseAddress.ToInt64(),
            sizeBytes: module.ModuleMemorySize,
            fileVersion: info?.FileVersion,
            companyName: info?.CompanyName,
            loaded: memory.TryReadHeader(module.BaseAddress),
            onDisk: PeImageReader.TryRead(path),
            fileExists: File.Exists(path));
    }

    /// <summary>Describes one module from what was read about it. Separate so it can be tested without a process.</summary>
    internal static LoadedModule Describe(
        string name,
        string path,
        ulong loadedAt,
        long sizeBytes,
        string? fileVersion,
        string? companyName,
        PeImageHeader? loaded,
        PeImageHeader? onDisk,
        bool fileExists)
    {
        var replaced = ReplacedOnDisk(loaded, onDisk, fileExists);

        // The preferred base comes from the file, not the mapping, because the loader writes the base an
        // image actually got into the header it maps. But a header from a different file says nothing
        // about where this image wanted to load, so a replaced module gets no relocation verdict at all.
        var header = replaced == true ? null : onDisk;

        return new LoadedModule(
            Name: name,
            Path: path,
            BaseAddress: Hex(loadedAt),
            SizeBytes: sizeBytes,
            FileVersion: NullIfEmpty(fileVersion),
            CompanyName: NullIfEmpty(companyName),
            SignatureVerdict: null,
            Signer: null,
            PreferredBase: header is { } pe ? Hex(pe.ImageBase) : null,
            Relocated: header is { } relocated ? relocated.ImageBase != loadedAt : null,
            // ASLR moves nearly every system image every boot, so "relocated" alone is noise. An image
            // that never asked to be moved and was moved anyway is the opposite: something was already
            // sitting in its range, and it has just lost its shareable pages.
            BaseCollision: header is { DynamicBase: false } fixedBase && fixedBase.ImageBase != loadedAt,
            ReplacedOnDisk: replaced);
    }

    /// <summary>Whether the file at a module's path is still the image that was loaded from it.</summary>
    /// <remarks>
    /// Unknown, not "no", whenever the mapping could not be read, or the file is there but unreadable --
    /// an access-denied file is not evidence of anything.
    /// </remarks>
    internal static bool? ReplacedOnDisk(PeImageHeader? loaded, PeImageHeader? onDisk, bool fileExists) =>
        (loaded, onDisk) switch
        {
            (null, _) => null,
            ({ } inMemory, { } file) => !inMemory.IsSameBuildAs(file),
            (_, null) => fileExists ? null : true
        };

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

    /// <summary>Reads the PE header each module has mapped in the target process.</summary>
    /// <remarks>
    /// Its own handle with only what the read needs, rather than <c>Process.Handle</c>, for the reason
    /// <see cref="Open"/> gives. Failing to open it costs the replacement check and nothing else: every
    /// module then reports <c>ReplacedOnDisk</c> as unknown.
    /// </remarks>
    private sealed class LoadedImageReader : IDisposable
    {
        private const uint ProcessVmRead = 0x0010;
        private const uint ProcessQueryLimitedInformation = 0x1000;

        private readonly SafeProcessHandle? _handle;

        private LoadedImageReader(SafeProcessHandle? handle) => _handle = handle;

        public static LoadedImageReader Open(int processId)
        {
            var handle = OpenProcess(ProcessVmRead | ProcessQueryLimitedInformation, false, processId);
            if (handle.IsInvalid)
            {
                handle.Dispose();
                return new LoadedImageReader(null);
            }

            return new LoadedImageReader(handle);
        }

        public PeImageHeader? TryReadHeader(IntPtr baseAddress)
        {
            if (_handle is null)
            {
                return null;
            }

            var buffer = new byte[PeImageReader.HeaderBytes];

            // A partial copy still returns what it read; the parser decides whether that is enough.
            ReadProcessMemory(_handle, baseAddress, buffer, buffer.Length, out var read);

            return PeImageReader.TryParse(buffer.AsSpan(0, (int)Math.Min((long)read, buffer.Length)));
        }

        public void Dispose() => _handle?.Dispose();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern SafeProcessHandle OpenProcess(uint access, bool inheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ReadProcessMemory(
            SafeProcessHandle process, IntPtr baseAddress, byte[] buffer, nint size, out nint bytesRead);
    }
}
