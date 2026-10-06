using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
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
/// <para>Version, preferred base and signature can only be read from a file, and the file at a module's
/// listed path need not be the one that was loaded: NTFS lets a loaded DLL be renamed, and something else
/// put in its place. So none of them is read from that path. Each comes from the file the kernel says is
/// behind the module's mapping, held open while it is read, and only where no one but SYSTEM,
/// Administrators and TrustedInstaller could have moved the directories that name runs through
/// (<see cref="WindowsModuleImageSource"/>); a module whose file cannot be identified that way gets none
/// of them, and says why.</para>
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

        var listed = new List<ListedModule>();
        Exception? failure = null;

        try
        {
            foreach (ProcessModule module in process.Modules)
            {
                cancellationToken.ThrowIfCancellationRequested();

                using (module)
                {
                    listed.Add(new ListedModule(
                        module.ModuleName ?? "(unnamed)",
                        module.FileName ?? string.Empty,
                        (ulong)module.BaseAddress.ToInt64(),
                        module.ModuleMemorySize));
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
        if (listed.Count == 0)
        {
            var message = DescribeTotalFailure(processId, failure);
            throw failure is null
                ? new ModuleQueryException(message)
                : new ModuleQueryException(message, failure);
        }

        // Only now is "partial" the honest word: some modules came back and then enumeration stopped.
        var limitation = failure is null ? null : DescribePartialFailure(failure);

        using var images = WindowsModuleImageSource.Open(processId);
        return Assemble(processId, name, listed, limitation, images, nameFilter, verifySignatures, cancellationToken);
    }

    /// <summary>
    /// Filters, pages and describes the listed modules, each from its own held image file. Separate from
    /// <see cref="List"/> so it can be driven without a process.
    /// </summary>
    /// <remarks>
    /// <para>Every match is identified, not just the returned page, so the replaced and unidentified counts
    /// cannot lose a module by sorting it past the cap. Only the page is described in full and, on
    /// request, verified -- Authenticode verification is not cheap and a process can hold several hundred
    /// modules.</para>
    /// <para>A module's signature is checked inside the same hold that identified its file, never by a
    /// second open later. The two used to be minutes apart in the worst case, after the whole list was
    /// enumerated and sorted, and nothing tied the file verified to the file compared.</para>
    /// </remarks>
    internal ModuleListResult Assemble(
        int processId,
        string processName,
        IReadOnlyList<ListedModule> listed,
        string? limitation,
        IModuleImageSource images,
        string? nameFilter,
        bool verifySignatures,
        CancellationToken cancellationToken)
    {
        IEnumerable<ListedModule> matched = listed;
        if (!string.IsNullOrWhiteSpace(nameFilter))
        {
            matched = matched.Where(m =>
                m.Name.Contains(nameFilter, StringComparison.OrdinalIgnoreCase)
                || m.Path.Contains(nameFilter, StringComparison.OrdinalIgnoreCase));
        }

        var ordered = matched.OrderBy(m => m.Name, StringComparer.OrdinalIgnoreCase).ToList();
        var pageSize = Math.Min(ordered.Count, _options.MaxResults);

        var described = new List<LoadedModule>(ordered.Count);
        for (var i = 0; i < ordered.Count; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            using var image = images.Open(ordered[i].Path, ordered[i].BaseAddress);
            var onPage = i < pageSize;

            var module = Describe(ordered[i], image, readFile: onPage);
            if (verifySignatures && onPage)
            {
                module = Verify(module, image, cancellationToken);
            }

            described.Add(module);
        }

        var page = described.Take(pageSize).ToList();

        return new ModuleListResult(
            ProcessId: processId,
            ProcessName: processName,
            Modules: page,
            TotalMatched: ordered.Count,
            Truncated: ordered.Count > pageSize,
            UnsignedCount: page.Count(m => m.SignatureVerdict is "Unsigned" or "Untrusted"),
            Limitation: limitation,
            CollisionCount: page.Count(m => m.BaseCollision),
            ReplacedCount: described.Count(m => m.ReplacedOnDisk == true),
            UnidentifiedCount: described.Count(m => m.ImageFileUnknownReason is not null),
            NotVerifiedCount: page.Count(m => m.SignatureVerdict == LoadedModule.NotVerified));
    }

    /// <summary>The verdict on the loaded image's own file, through the handle that identified it.</summary>
    /// <remarks>
    /// A module whose file was not identified is <c>NotVerified</c>, never verified by its path instead.
    /// That fallback was the hole: an unknown identity -- an image header built not to parse, a file held
    /// open to make the comparison fail -- still got the verdict of whatever signed file sat at the path,
    /// and the module dropped out of the unsigned count with nothing marked.
    /// </remarks>
    private LoadedModule Verify(LoadedModule module, ModuleImageFile image, CancellationToken cancellationToken)
    {
        if (image.Held is null || image.HeldPath is null)
        {
            return module with { SignatureVerdict = LoadedModule.NotVerified, Signer = null };
        }

        FileSignature signature;
        try
        {
            signature = _signatures.InspectHeld(image.HeldPath, image.Held, cancellationToken);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return module with { SignatureVerdict = nameof(SignatureVerdict.Unknown), Signer = null };
        }

        return module with
        {
            SignatureVerdict = signature.Verdict.ToString(),
            Signer = signature.Signer ?? (signature.CatalogSigned ? "(catalog)" : null)
        };
    }

    /// <summary>Describes one module from its held image file, or from nothing when there is none.</summary>
    private static LoadedModule Describe(ListedModule listed, ModuleImageFile image, bool readFile)
    {
        var bare = new LoadedModule(
            Name: listed.Name,
            Path: listed.Path,
            BaseAddress: Hex(listed.BaseAddress),
            SizeBytes: listed.SizeBytes,
            FileVersion: null,
            CompanyName: null,
            SignatureVerdict: null,
            Signer: null,
            ImageFileUnknownReason: image.UnknownReason);

        if (image.Held is null || image.HeldPath is null)
        {
            return bare;
        }

        var identified = bare with
        {
            ReplacedOnDisk = image.ListedPathIsOtherFile,
            ImageFilePath = image.ListedPathIsOtherFile == false ? null : image.HeldPath
        };

        if (!readFile)
        {
            return identified;
        }

        // The preferred base comes from the file, not the mapping, because the loader writes the base an
        // image actually got into the header it maps.
        var header = PeImageReader.TryRead(image.Held);
        var version = ReadVersion(image.HeldPath);

        return identified with
        {
            FileVersion = NullIfEmpty(version?.FileVersion),
            CompanyName = NullIfEmpty(version?.CompanyName),
            PreferredBase = header is { } pe ? Hex(pe.ImageBase) : null,
            Relocated = header is { } relocated ? relocated.ImageBase != listed.BaseAddress : null,
            // ASLR moves nearly every system image every boot, so "relocated" alone is noise. An image
            // that never asked to be moved and was moved anyway is the opposite: something was already
            // sitting in its range, and it has just lost its shareable pages.
            BaseCollision = header is { DynamicBase: false } fixedBase && fixedBase.ImageBase != listed.BaseAddress
        };
    }

    /// <remarks>
    /// By path, because the version resource API takes nothing else -- but the path of the held file,
    /// which while it is held cannot be renamed, replaced or written, so this reads the same bytes.
    /// </remarks>
    private static FileVersionInfo? ReadVersion(string path)
    {
        try
        {
            return FileVersionInfo.GetVersionInfo(path);
        }
        catch (Exception ex) when (ex is FileNotFoundException or IOException or UnauthorizedAccessException)
        {
            return null;
        }
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

/// <summary>A module as the process lists it: the loader's name and path, and where it is mapped.</summary>
internal sealed record ListedModule(string Name, string Path, ulong BaseAddress, long SizeBytes);
