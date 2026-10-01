using System.Globalization;
using System.Text;

namespace MacDiag.Mcp.Mac.Parsers;

/// <param name="Descriptor">lsof's FD column: a number, or cwd, txt, rtd, mem and so on.</param>
/// <param name="Access">r, w or u; null when lsof left it blank, as it does for cwd and txt.</param>
/// <param name="KernelAddress">The socket's kernel address (field d): the same socket shared by several processes has one.</param>
/// <param name="TcpState">From a T field "ST=…", e.g. LISTEN.</param>
public sealed record LsofFile(
    string Descriptor, string? Access, string? Type, string? KernelAddress, string? Device, long? Size, long? Inode,
    string? Name, string? Protocol, string? TcpState);

public sealed record LsofProcess(int ProcessId, int? ParentProcessId, string Command, long? UserId, IReadOnlyList<LsofFile> Files);

/// <summary>lsof -F0 field output: every field NUL-terminated, each process and file set ending in a newline.</summary>
/// <remarks>
/// Split on NUL, never on newlines: a newline inside a value is data, and splitting on it is how a file name
/// forges a record. The newline that ends a set arrives as the first character of the next field, so exactly
/// one leading newline is stripped from each field.
/// </remarks>
public static class LsofFields
{
    public static IReadOnlyList<LsofProcess> Parse(string raw)
    {
        ArgumentNullException.ThrowIfNull(raw);

        var processes = new List<LsofProcess>();
        var tokens = raw.Split('\0');

        // The last token follows the final NUL: a field cut off mid-value, or the closing newline. Never a field.
        var complete = tokens.Length - 1;

        ProcessBuilder? process = null;
        FileBuilder? file = null;
        for (var i = 0; i < complete; i++)
        {
            var token = tokens[i].StartsWith('\n') ? tokens[i][1..] : tokens[i];
            if (token.Length == 0)
            {
                continue;
            }

            var value = token[1..];
            switch (token[0])
            {
                case 'p':
                    Flush();
                    process = int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var pid) ? new ProcessBuilder(pid) : null;
                    break;
                case 'f' when process is not null:
                    if (file is not null)
                    {
                        process.Files.Add(file.Build());
                    }

                    file = new FileBuilder(value);
                    break;
                case 'c' when process is not null && file is null:
                    process.Command = LsofEscapes.Decode(value);
                    break;
                case 'u' when process is not null && file is null:
                    process.UserId = Number(value);
                    break;
                case 'R' when process is not null && file is null:
                    process.ParentProcessId = (int?)Number(value);
                    break;
                case 'a' when file is not null:
                    file.Access = string.IsNullOrWhiteSpace(value) ? null : value.Trim();
                    break;
                case 't' when file is not null:
                    file.Type = value;
                    break;
                case 'd' when file is not null:
                    file.KernelAddress = value;
                    break;
                case 'D' when file is not null:
                    file.Device = value;
                    break;
                case 's' when file is not null:
                    file.Size = Number(value);
                    break;
                case 'i' when file is not null:
                    file.Inode = Number(value);
                    break;
                case 'n' when file is not null:
                    file.Name = LsofEscapes.Decode(value);
                    break;
                case 'P' when file is not null:
                    file.Protocol = value;
                    break;
                case 'T' when file is not null && value.StartsWith("ST=", StringComparison.Ordinal):
                    file.TcpState = value[3..];
                    break;
            }
        }

        Flush();
        return processes;

        void Flush()
        {
            if (process is null)
            {
                return;
            }

            if (file is not null)
            {
                process.Files.Add(file.Build());
                file = null;
            }

            processes.Add(new LsofProcess(process.ProcessId, process.ParentProcessId, process.Command, process.UserId, process.Files));
            process = null;
        }
    }

    private static long? Number(string value) =>
        long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var number) ? number : null;

    private sealed class ProcessBuilder(int processId)
    {
        public int ProcessId { get; } = processId;

        public int? ParentProcessId { get; set; }

        public string Command { get; set; } = string.Empty;

        public long? UserId { get; set; }

        public List<LsofFile> Files { get; } = [];
    }

    private sealed class FileBuilder(string descriptor)
    {
        public string? Access { get; set; }

        public string? Type { get; set; }

        public string? KernelAddress { get; set; }

        public string? Device { get; set; }

        public long? Size { get; set; }

        public long? Inode { get; set; }

        public string? Name { get; set; }

        public string? Protocol { get; set; }

        public string? TcpState { get; set; }

        public LsofFile Build() => new(descriptor, Access, Type, KernelAddress, Device, Size, Inode, Name, Protocol, TcpState);
    }
}

/// <summary>Undoes lsof's escaping of names in the C locale: \xNN per non-ASCII byte, and \n \r \t \b \f.</summary>
/// <remarks>
/// A run of \xNN bytes is decoded as UTF-8; a run that is not valid UTF-8 is left as lsof printed it rather than
/// turned into replacement characters. A backslash in a real name followed by one of these letters is
/// indistinguishable from an escape -- lsof gives no way to tell -- and is decoded.
/// </remarks>
public static class LsofEscapes
{
    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    public static string Decode(string printed)
    {
        ArgumentNullException.ThrowIfNull(printed);
        if (!printed.Contains('\\', StringComparison.Ordinal))
        {
            return printed;
        }

        var result = new StringBuilder(printed.Length);
        var i = 0;
        while (i < printed.Length)
        {
            if (printed[i] == '\\' && i + 3 < printed.Length && printed[i + 1] == 'x' && IsHexByte(printed, i + 2))
            {
                var start = i;
                var bytes = new List<byte>();
                while (i + 3 < printed.Length && printed[i] == '\\' && printed[i + 1] == 'x' && IsHexByte(printed, i + 2))
                {
                    bytes.Add(byte.Parse(printed.AsSpan(i + 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture));
                    i += 4;
                }

                try
                {
                    result.Append(StrictUtf8.GetString(bytes.ToArray()));
                }
                catch (DecoderFallbackException)
                {
                    result.Append(printed, start, i - start);
                }

                continue;
            }

            if (printed[i] == '\\' && i + 1 < printed.Length && Named(printed[i + 1]) is { } control)
            {
                result.Append(control);
                i += 2;
                continue;
            }

            result.Append(printed[i]);
            i++;
        }

        return result.ToString();
    }

    private static bool IsHexByte(string text, int at) => Uri.IsHexDigit(text[at]) && Uri.IsHexDigit(text[at + 1]);

    private static char? Named(char letter) => letter switch
    {
        'n' => '\n',
        'r' => '\r',
        't' => '\t',
        'b' => '\b',
        'f' => '\f',
        _ => null,
    };
}
