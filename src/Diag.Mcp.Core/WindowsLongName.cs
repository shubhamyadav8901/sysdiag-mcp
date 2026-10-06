using System.Runtime.InteropServices;

namespace Diag.Mcp.Core;

/// <summary>An existing Windows path with its 8.3 short names spelled out as the long names they stand for.</summary>
/// <remarks>
/// <para>
/// NTFS gives a long name a second, 8.3 spelling -- <c>C:\Diag\WinDiag Server</c> is also
/// <c>C:\Diag\WINDIA~1</c> -- and every open accepts it. <see cref="Path.GetFullPath(string)"/> does not
/// expand it, and nothing in .NET does: enumeration stopped matching short names in .NET Core. So a
/// containment check on the spelling was a check on whichever name the caller chose.
/// </para>
/// <para>
/// GetLongPathNameW rather than opening the path and asking GetFinalPathNameByHandleW: it reads names
/// and never follows a reparse point, so it fits into <see cref="PathScope.Walk(string)"/>, which has
/// already resolved every link on the way and only asks about a component that is not one. The final
/// path of a handle would also resolve the link the walk is about to judge on its own terms.
/// </para>
/// <para>
/// Bound by absolute path from System32, never through <c>[DllImport]</c>: the runtime probes the
/// application directory for an imported DLL first, and this assembly has no resolver. That directory is
/// exactly the one this check guards.
/// </para>
/// </remarks>
public static class WindowsLongName
{
    private const int ErrorFileNotFound = 2;
    private const int ErrorPathNotFound = 3;

    [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode, SetLastError = true)]
    private delegate uint GetLongPathNameW(string shortPath, IntPtr longPath, uint bufferLength);

    private static readonly Lazy<GetLongPathNameW> Function = new(() =>
    {
        var kernel32 = NativeLibrary.Load(Path.Combine(Environment.SystemDirectory, "kernel32.dll"));
        return Marshal.GetDelegateForFunctionPointer<GetLongPathNameW>(
            NativeLibrary.GetExport(kernel32, nameof(GetLongPathNameW)));
    });

    /// <summary>
    /// <paramref name="path"/> with its components spelled as stored, or unchanged when it does not exist.
    /// </summary>
    /// <param name="path">An absolute path whose parent the caller has already canonicalised.</param>
    /// <param name="requested">The path the caller asked about, for the refusal.</param>
    /// <exception cref="FileTransferException">
    /// The path exists but its long name could not be read. Refused rather than kept as spelled: a short
    /// name kept as spelled is the second spelling this exists to remove.
    /// </exception>
    public static string Of(string path, string requested)
    {
        // The \\?\ form lifts MAX_PATH, as the function documents; a deep path must not be refused for
        // its depth. Drive-letter paths only: anything else was refused before the walk began.
        var driveRooted = path.Length >= 3 && char.IsAsciiLetter(path[0]) && path[1] == ':' && path[2] == '\\';
        var asked = driveRooted ? @"\\?\" + path : path;

        var capacity = (uint)asked.Length + 1;
        while (true)
        {
            var buffer = Marshal.AllocHGlobal((int)capacity * sizeof(char));
            try
            {
                var length = Function.Value(asked, buffer, capacity);
                if (length == 0)
                {
                    var error = Marshal.GetLastPInvokeError();
                    if (error is ErrorFileNotFound or ErrorPathNotFound)
                    {
                        // Not there yet -- the file about to be written. A name that does not exist has
                        // no short form, so the spelling given is the only one.
                        return path;
                    }

                    throw new FileTransferException(
                        $"'{requested}' could not be resolved: Windows could not give the long name of " +
                        $"'{path}' (error {error}).");
                }

                // Too small: the length returned then counts the terminating null, so it is never below
                // the capacity. On success it does not, so it always is.
                if (length >= capacity)
                {
                    capacity = length;
                    continue;
                }

                var result = Marshal.PtrToStringUni(buffer, (int)length);
                return driveRooted && result.StartsWith(@"\\?\", StringComparison.Ordinal) ? result[4..] : result;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
    }
}
