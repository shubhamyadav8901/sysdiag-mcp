using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace WinDiag.Mcp.Diagnostics.Handles;

/// <summary>One process as the kernel lists it: when it was created, and its image name.</summary>
/// <param name="CreateTime">
/// The kernel's creation time, which tells a process from a later one given the same PID.
/// </param>
/// <param name="ImageName">The image file name, as handle.exe prints it at the start of each row; null when the kernel has none.</param>
public readonly record struct ProcessImage(long CreateTime, string? ImageName);

/// <summary>Takes a snapshot of every process on the machine.</summary>
public interface IProcessTable
{
    IReadOnlyDictionary<int, ProcessImage> Snapshot();
}

/// <summary>
/// Says whether the image name handle.exe printed for a row is the whole of that process's image name.
/// </summary>
/// <remarks>
/// <para>handle.exe prints a row's image name first and quotes nothing, so an image name holding a line
/// break puts whatever precedes the break on lines of its own -- whole forged rows, which nothing before
/// them gives away. What gives them away comes after: the real row's line then starts with only the text
/// after the last break, and its PID, which the parser anchors on, is the real one. So the line names a
/// real process under a name that is not that process's.</para>
/// <para>That is only conclusive for a process that was the same process for the whole run. Read once,
/// after handle.exe exits, a process that had printed a row and exited could have its PID taken by one
/// whose name is whatever the row said; read once before, a process could start, print and exit unseen.
/// So the table is read on both sides of the run, and a row is confirmed only when its PID names the
/// same process -- same creation time -- in both, under the name printed.</para>
/// <para>"The name printed" is the name as handle.exe could write it. It writes its pipe in the ANSI code
/// page, and a character that page lacks arrives as '?', as a best-fit letter, or not at all -- which of
/// these is not measured, so each run of such characters may be printed as up to as many characters, of
/// any kind but a control character. Compared exactly, a process named in Chinese on a Western install was
/// never confirmed, on any run, and cost every row printed before it. Every character the page has must
/// match exactly. What makes a name whole is that it holds no line break, so a name holding a control
/// character or a line or paragraph separator is never confirmed, whatever was printed for it.</para>
/// <para>The search tool's own rows are the exception: it is in neither reading, since it starts after the
/// first and is gone by the second, but its PID was its own for the whole run that printed the rows, and its
/// name is the file the server started.</para>
/// </remarks>
/// <param name="console">The encoding handle.exe's output was decoded with.</param>
/// <param name="printer">The PID and image name of the handle.exe run that printed the rows, when known.</param>
internal sealed class PrintedImageWitness(
    IReadOnlyDictionary<int, ProcessImage> before,
    IReadOnlyDictionary<int, ProcessImage> after,
    Encoding console,
    (int ProcessId, string ImageName)? printer = null)
{
    private readonly Encoding _strict = Strict(console);
    private readonly Dictionary<(int, string), bool> _answers = [];

    public bool IsWhole(int processId, string printedImage)
    {
        if (printer is { } self && processId == self.ProcessId)
        {
            // A name the server chose, matched as Windows matches file names.
            return string.Equals(printedImage, self.ImageName, StringComparison.OrdinalIgnoreCase);
        }

        if (!before.TryGetValue(processId, out var first) ||
            !after.TryGetValue(processId, out var last) ||
            first != last ||
            first.ImageName is not { } name)
        {
            return false;
        }

        if (!_answers.TryGetValue((processId, printedImage), out var whole))
        {
            whole = CouldPrintAs(name, printedImage);
            _answers[(processId, printedImage)] = whole;
        }

        return whole;
    }

    private bool CouldPrintAs(string name, string printed)
    {
        if (name.Any(BreaksALine))
        {
            return false;
        }

        if (string.Equals(name, printed, StringComparison.Ordinal))
        {
            return true;
        }

        // Each run of characters the page lacks becomes a bounded wildcard; everything else must be as named.
        var pattern = new StringBuilder("^");
        var missing = 0;
        foreach (var rune in name.EnumerateRunes())
        {
            if (InCodePage(rune))
            {
                Flush();
                pattern.Append(Regex.Escape(rune.ToString()));
            }
            else
            {
                missing += rune.Utf16SequenceLength;
            }
        }

        Flush();
        pattern.Append('$');

        // NonBacktracking: the name is chosen by whoever named the image, and adjacent bounded wildcards
        // over the same characters are what makes a backtracking engine take exponential time.
        return Regex.IsMatch(printed, pattern.ToString(), RegexOptions.NonBacktracking | RegexOptions.CultureInvariant);

        void Flush()
        {
            if (missing > 0)
            {
                pattern.Append(CultureInfo.InvariantCulture, $@"[^\p{{Cc}}\p{{Zl}}\p{{Zp}}]{{0,{missing}}}");
                missing = 0;
            }
        }
    }

    private bool InCodePage(Rune rune)
    {
        var text = rune.ToString();
        try
        {
            return string.Equals(_strict.GetString(_strict.GetBytes(text)), text, StringComparison.Ordinal);
        }
        catch (Exception ex) when (ex is EncoderFallbackException or DecoderFallbackException)
        {
            return false;
        }
    }

    private static bool BreaksALine(char c) =>
        char.IsControl(c) ||
        CharUnicodeInfo.GetUnicodeCategory(c) is UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator;

    /// <summary>The same code page, failing on a character it lacks instead of substituting one.</summary>
    private static Encoding Strict(Encoding console)
    {
        var strict = (Encoding)console.Clone();
        strict.EncoderFallback = EncoderFallback.ExceptionFallback;
        strict.DecoderFallback = DecoderFallback.ExceptionFallback;
        return strict;
    }
}

/// <summary>Reads the process table with <c>NtQuerySystemInformation</c>, the source handle.exe names processes from.</summary>
/// <remarks>
/// Not <see cref="System.Diagnostics.Process"/>: its name drops ".exe", which handle.exe prints, and its
/// start time opens each process, which fails for some that hold handles worth finding. This query
/// opens nothing and returns both for every process.
/// </remarks>
internal sealed class NativeProcessTable : IProcessTable
{
    private const int SystemProcessInformationClass = 5;
    private const int StatusInfoLengthMismatch = unchecked((int)0xC0000004);
    private const int SystemProcessId = 4;

    public IReadOnlyDictionary<int, ProcessImage> Snapshot()
    {
        var size = 1 << 20;

        // The table grows between the call that sizes it and the call that fills it; a few retries
        // with headroom always settle, and a bound keeps a broken answer from spinning forever.
        for (var attempt = 0; attempt < 8; attempt++)
        {
            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                var status = NtQuerySystemInformation(SystemProcessInformationClass, buffer, size, out var needed);
                if (status == StatusInfoLengthMismatch)
                {
                    size = Math.Max(size * 2, needed + (64 << 10));
                    continue;
                }

                if (status < 0)
                {
                    throw new ProcessTableException(
                        $"The process table could not be read (NTSTATUS 0x{status:X8}), so no handle.exe row can be " +
                        "confirmed to be the row it looks like.", new Win32Exception(RtlNtStatusToDosError(status)));
                }

                return Read(buffer);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        throw new ProcessTableException(
            "The process table kept growing faster than it could be read, so no handle.exe row can be " +
            "confirmed to be the row it looks like.", null);
    }

    private static Dictionary<int, ProcessImage> Read(IntPtr buffer)
    {
        var table = new Dictionary<int, ProcessImage>();
        var entry = buffer;

        while (true)
        {
            var info = Marshal.PtrToStructure<SystemProcessInformation>(entry);
            var processId = unchecked((int)(long)info.UniqueProcessId);

            // The System process can come back with no name; handle.exe, like every tool, calls it
            // "System". No user can name the kernel's own process, so supplying that name lets nothing
            // through -- and leaving it null would leave every row System holds unconfirmed.
            var name = info.ImageName.Buffer != IntPtr.Zero
                ? Marshal.PtrToStringUni(info.ImageName.Buffer, info.ImageName.Length / sizeof(char))
                : processId == SystemProcessId ? "System" : null;

            table[processId] = new ProcessImage(info.CreateTime, name);

            if (info.NextEntryOffset == 0)
            {
                return table;
            }

            entry += (nint)info.NextEntryOffset;
        }
    }

    /// <summary>The head of SYSTEM_PROCESS_INFORMATION, as far as the PID; sequential layout gives the x86 and x64 offsets alike.</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct SystemProcessInformation
    {
        public uint NextEntryOffset;
        public uint NumberOfThreads;
        public long WorkingSetPrivateSize;
        public uint HardFaultCount;
        public uint NumberOfThreadsHighWatermark;
        public ulong CycleTime;
        public long CreateTime;
        public long UserTime;
        public long KernelTime;
        public UnicodeString ImageName;
        public int BasePriority;
        public IntPtr UniqueProcessId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UnicodeString
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(int informationClass, IntPtr information, int length, out int returnLength);

    [DllImport("ntdll.dll")]
    private static extern int RtlNtStatusToDosError(int status);
}

/// <summary>Raised when the process table could not be read around a handle.exe run.</summary>
public sealed class ProcessTableException(string message, Exception? inner) : Exception(message, inner), IDiagnosticException;
