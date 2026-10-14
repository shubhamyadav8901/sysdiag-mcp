using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using WinDiag.Mcp.Configuration;

namespace WinDiag.Mcp.Diagnostics.Pipes;

/// <summary>
/// Enumerates named pipes with their instance counts.
/// </summary>
/// <remarks>
/// <para><c>Directory.GetFiles(@"\\.\pipe\")</c> would list the names in one line, but only the names.
/// How many instances exist against how many the server allowed is only available by querying the pipe
/// device directly, where the file-system structure reuses two fields for it: <c>EndOfFile</c> carries
/// the number of instances <em>created</em> and <c>AllocationSize</c> the maximum.</para>
/// <para>Created is not busy. An instance exists from <c>CreateNamedPipe</c> onwards and is listening
/// until a client takes it, so "all instances created" alone says nothing about whether a client can
/// connect. For those pipes only, <c>WaitNamedPipe</c> is asked with a 1 ms timeout: it returns at once
/// when an instance is listening, and times out when none is -- which is what distinguishes "the
/// service is fine and every instance is taken" from a pipe that would accept a client right now. It
/// connects nothing, so the server never sees it.</para>
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class NamedPipeInspector : INamedPipeInspector
{
    private const string PipeDevicePath = @"\??\Pipe\";

    private const uint FileListDirectory = 0x0001;
    private const uint Synchronize = 0x00100000;
    private const uint FileShareAll = 0x07;
    private const uint FileDirectoryFile = 0x00000001;
    private const uint FileSynchronousIoNonAlert = 0x00000020;
    private const uint FileDirectoryInformation = 1;

    private const int StatusSuccess = 0;
    private const int StatusNoMoreFiles = unchecked((int)0x80000006);

    /// <summary>
    /// The shortest wait <c>WaitNamedPipe</c> accepts that is not one of its special values: 0 means the
    /// pipe's default timeout, often 50 ms, and an answer about listening needs no waiting at all.
    /// </summary>
    private const uint ProbeTimeoutMilliseconds = 1;

    private const int ErrorSemTimeout = 121;

    /// <summary>Buffer for one batch of directory entries. Grown by re-reading, never by guessing.</summary>
    private const int BufferBytes = 64 * 1024;

    private readonly WinDiagOptions _options;

    public NamedPipeInspector(WinDiagOptions options)
    {
        _options = options;
    }

    public NamedPipeListResult List(string? nameFilter, CancellationToken cancellationToken) =>
        Arrange(Enumerate(cancellationToken), nameFilter, _options.MaxResults, ProbeListening, cancellationToken);

    /// <summary>Filters, probes and orders an enumeration. Separate so it can be tested without a pipe.</summary>
    /// <remarks>
    /// Only pipes with every instance created are probed. A pipe below its limit can still create
    /// another instance, and probing hundreds of healthy pipes would cost a timer tick each for nothing;
    /// the probes that do run go in parallel because a single-instance pipe with its client connected --
    /// Chromium creates hundreds -- times out rather than answering at once.
    /// </remarks>
    internal static NamedPipeListResult Arrange(
        IEnumerable<NamedPipe> pipes,
        string? nameFilter,
        int maxResults,
        Func<string, bool?> probe,
        CancellationToken cancellationToken)
    {
        IEnumerable<NamedPipe> matched = pipes;
        if (!string.IsNullOrWhiteSpace(nameFilter))
        {
            matched = matched.Where(p => p.Name.Contains(nameFilter, StringComparison.OrdinalIgnoreCase));
        }

        var probed = matched.ToArray();

        Parallel.For(
            0,
            probed.Length,
            new ParallelOptions { MaxDegreeOfParallelism = 16, CancellationToken = cancellationToken },
            i =>
            {
                if (probed[i].AllInstancesCreated)
                {
                    probed[i] = probed[i] with { Listening = probe(probed[i].Name) };
                }
            });

        // Busy pipes first: one with every instance taken and none listening is almost certainly the
        // answer the caller came for, and it must not be buried alphabetically among hundreds of
        // healthy ones. Merely having created every instance is not that, so it does not jump the queue.
        var ordered = probed
            .OrderByDescending(p => p.Busy)
            .ThenBy(p => p.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var truncated = ordered.Count > maxResults;

        return new NamedPipeListResult(
            Pipes: truncated ? ordered.Take(maxResults).ToArray() : ordered,
            TotalMatched: ordered.Count,
            Truncated: truncated);
    }

    /// <summary>Whether an instance of the pipe is waiting for a client, without connecting to it.</summary>
    /// <returns>Null when the pipe went away or the answer was something other than yes or no.</returns>
    private static bool? ProbeListening(string name)
    {
        if (WaitNamedPipe(@"\\.\pipe\" + name, ProbeTimeoutMilliseconds))
        {
            return true;
        }

        return Marshal.GetLastWin32Error() == ErrorSemTimeout ? false : null;
    }

    private static List<NamedPipe> Enumerate(CancellationToken cancellationToken)
    {
        var pipes = new List<NamedPipe>();
        var handle = OpenPipeDevice();

        try
        {
            var buffer = Marshal.AllocHGlobal(BufferBytes);

            try
            {
                var restart = true;

                while (true)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    var status = NtQueryDirectoryFile(
                        handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                        out _, buffer, BufferBytes,
                        FileDirectoryInformation, false, IntPtr.Zero, restart);

                    restart = false;

                    if (status == StatusNoMoreFiles)
                    {
                        break;
                    }

                    if (status != StatusSuccess)
                    {
                        throw new NamedPipeQueryException(
                            $"Enumerating named pipes failed with NTSTATUS 0x{status:X8}.");
                    }

                    ReadEntries(buffer, pipes);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        finally
        {
            CloseHandle(handle);
        }

        return pipes;
    }

    /// <summary>Walks one buffer of FILE_DIRECTORY_INFORMATION records.</summary>
    /// <remarks>
    /// Field offsets are fixed by the structure's definition. They are read explicitly rather than via
    /// a marshalled struct because the trailing filename is variable-length, which no blittable layout
    /// can express.
    /// </remarks>
    private static void ReadEntries(IntPtr buffer, List<NamedPipe> pipes)
    {
        const int nextEntryOffsetOffset = 0;
        const int endOfFileOffset = 40;      // instances created, connected or not
        const int allocationSizeOffset = 48; // maximum instances
        const int fileNameLengthOffset = 60;
        const int fileNameOffset = 64;

        var entry = buffer;

        while (true)
        {
            var nextEntryOffset = Marshal.ReadInt32(entry, nextEntryOffsetOffset);
            var instancesCreated = Marshal.ReadInt64(entry, endOfFileOffset);
            var maximumInstances = Marshal.ReadInt64(entry, allocationSizeOffset);
            var nameLength = Marshal.ReadInt32(entry, fileNameLengthOffset);

            if (nameLength > 0)
            {
                var name = Marshal.PtrToStringUni(entry + fileNameOffset, nameLength / 2);
                if (!string.IsNullOrEmpty(name))
                {
                    pipes.Add(new NamedPipe(
                        name,
                        Clamp(instancesCreated),
                        maximumInstances >= int.MaxValue ? -1 : Clamp(maximumInstances)));
                }
            }

            if (nextEntryOffset == 0)
            {
                break;
            }

            entry += nextEntryOffset;
        }
    }

    /// <summary>
    /// Narrows a 64-bit field to the instance count it actually represents.
    /// </summary>
    /// <remarks>
    /// PIPE_UNLIMITED_INSTANCES surfaces here as a very large value rather than a flag, so it is mapped
    /// to -1 by the caller. Anything else is a small count; clamping guards against a nonsensical value
    /// becoming a negative instance count through overflow.
    /// </remarks>
    private static int Clamp(long value) => value switch
    {
        < 0 => 0,
        > int.MaxValue => int.MaxValue,
        _ => (int)value
    };

    private static IntPtr OpenPipeDevice()
    {
        var name = new UnicodeString(PipeDevicePath);

        try
        {
            var attributes = new ObjectAttributes
            {
                Length = Marshal.SizeOf<ObjectAttributes>(),
                ObjectName = name.Pointer
            };

            var status = NtOpenFile(
                out var handle,
                FileListDirectory | Synchronize,
                ref attributes,
                out _,
                FileShareAll,
                FileDirectoryFile | FileSynchronousIoNonAlert);

            if (status != StatusSuccess)
            {
                throw new NamedPipeQueryException(
                    $"Could not open the named pipe device (NTSTATUS 0x{status:X8}). No conclusion about " +
                    "named pipes should be drawn from this.");
            }

            return handle;
        }
        finally
        {
            name.Dispose();
        }
    }

    /// <summary>Owns the native UNICODE_STRING and its buffer for the duration of one call.</summary>
    private sealed class UnicodeString : IDisposable
    {
        private readonly IntPtr _buffer;

        public UnicodeString(string value)
        {
            _buffer = Marshal.StringToHGlobalUni(value);

            var native = new UnicodeStringNative
            {
                Length = (ushort)(value.Length * 2),
                MaximumLength = (ushort)((value.Length + 1) * 2),
                Buffer = _buffer
            };

            Pointer = Marshal.AllocHGlobal(Marshal.SizeOf<UnicodeStringNative>());
            Marshal.StructureToPtr(native, Pointer, false);
        }

        public IntPtr Pointer { get; }

        public void Dispose()
        {
            Marshal.FreeHGlobal(Pointer);
            Marshal.FreeHGlobal(_buffer);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UnicodeStringNative
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ObjectAttributes
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoStatusBlock
    {
        public IntPtr Status;
        public IntPtr Information;
    }

    [DllImport("ntdll.dll")]
    private static extern int NtOpenFile(
        out IntPtr fileHandle,
        uint desiredAccess,
        ref ObjectAttributes objectAttributes,
        out IoStatusBlock ioStatusBlock,
        uint shareAccess,
        uint openOptions);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryDirectoryFile(
        IntPtr fileHandle,
        IntPtr @event,
        IntPtr apcRoutine,
        IntPtr apcContext,
        out IoStatusBlock ioStatusBlock,
        IntPtr fileInformation,
        uint length,
        uint fileInformationClass,
        [MarshalAs(UnmanagedType.Bool)] bool returnSingleEntry,
        IntPtr fileName,
        [MarshalAs(UnmanagedType.Bool)] bool restartScan);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "WaitNamedPipeW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WaitNamedPipe(string name, uint timeoutMilliseconds);
}

/// <summary>Raised when named pipes could not be enumerated at all.</summary>
public sealed class NamedPipeQueryException : Exception, IDiagnosticException
{
    public NamedPipeQueryException(string message) : base(message)
    {
    }
}
