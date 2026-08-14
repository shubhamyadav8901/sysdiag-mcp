namespace WinDiag.Mcp.Diagnostics.External;

/// <summary>Raised when the only build of a tool present here cannot do the job on this OS.</summary>
/// <remarks>
/// Distinct from <see cref="ToolNotFoundException"/> on purpose: "not installed" and "the wrong one is
/// installed" have different fixes, and the second is the one that would otherwise be mistaken for a
/// clean result. Derives from <see cref="ExternalToolException"/> so the tool-error filter reports its
/// message verbatim -- the message is the whole value here.
/// </remarks>
public sealed class ToolArchitectureException : ExternalToolException
{
    public ToolArchitectureException(string message) : base(message)
    {
    }
}

/// <summary>
/// Picks the build of a Sysinternals console tool that can actually answer on this machine.
/// </summary>
/// <remarks>
/// <para>The downloadable zips ship two or three builds of every tool under names differing by one
/// character -- <c>handle.exe</c> and <c>handle64.exe</c>, <c>Procmon.exe</c> and
/// <c>Procmon64.exe</c>. Running the 32-bit one on 64-bit Windows does not fail; it answers
/// <em>wrongly</em>, which is far worse.</para>
/// <para>Measured on an x64 workstation, both unelevated, same filter:</para>
/// <code>
/// handle.exe   -u -v System32  ->  "No matching handles found."   (1 line)
/// handle64.exe -u -v System32  ->  526 rows
/// </code>
/// <para>An empty result from a handle search reads as "nothing holds this file", which is exactly the
/// conclusion that ends an investigation early. Procmon fails differently but just as quietly: its
/// 32-bit build is a launcher that starts the 64-bit one and exits, so the capture looks like it
/// finished in a second over a trace still being written.</para>
/// <para>Hence resolving by preference <em>and</em> verifying the PE machine type of what was found: a
/// file name cannot distinguish the two, because the Store package ships the x64 image as plain
/// <c>Procmon.exe</c>.</para>
/// </remarks>
public static class SysinternalsArchitecture
{
    /// <summary>Names the build to run, or explains why neither present build will do.</summary>
    /// <param name="locator">Resolver for the executable.</param>
    /// <param name="baseName">Tool name without an extension or bitness suffix, e.g. <c>handle</c>.</param>
    /// <param name="symptom">
    /// What running the 32-bit build on 64-bit Windows actually does, in a sentence. Included in the
    /// refusal because "wrong architecture" alone does not tell the reader why they should care.
    /// </param>
    /// <returns>The executable name to hand the runner, which resolves it again through the same locator.</returns>
    /// <exception cref="ToolNotFoundException">Neither build is present.</exception>
    /// <exception cref="ToolArchitectureException">Only the 32-bit build is present, on 64-bit Windows.</exception>
    public static string ResolveName(IToolLocator locator, string baseName, string symptom)
    {
        var choice = Choose(locator, baseName, symptom);

        return choice.ExecutableName
               ?? throw (choice.WrongArchitecture
                   ? new ToolArchitectureException(choice.Problem!)
                   : new ToolNotFoundException(PreferredFileName(baseName)));
    }

    /// <summary>The same decision, as data, for reporting what this machine can do before it is asked.</summary>
    /// <param name="ExecutableName">Null when no usable build is present.</param>
    /// <param name="Path">Full path of what was found, usable or not. Null when nothing was found.</param>
    /// <param name="Problem">Null when a usable build was found.</param>
    /// <param name="WrongArchitecture">
    /// True when a build was found but is the wrong one. Distinguishes "install it" from "you installed
    /// the wrong half", which are different fixes.
    /// </param>
    public readonly record struct ToolChoice(
        string? ExecutableName,
        string? Path,
        string? Problem,
        bool WrongArchitecture);

    /// <summary>The file name that should be present on this OS, for a "not installed" message.</summary>
    public static string PreferredFileName(string baseName) =>
        Environment.Is64BitOperatingSystem ? $"{baseName}64.exe" : $"{baseName}.exe";

    public static ToolChoice Choose(IToolLocator locator, string baseName, string symptom)
    {
        ArgumentNullException.ThrowIfNull(locator);
        ArgumentException.ThrowIfNullOrWhiteSpace(baseName);

        var wide = $"{baseName}64.exe";
        var narrow = $"{baseName}.exe";

        if (Environment.Is64BitOperatingSystem && locator.TryResolve(wide, out var widePath))
        {
            return new ToolChoice(wide, widePath, null, false);
        }

        if (!locator.TryResolve(narrow, out var path))
        {
            return new ToolChoice(
                null,
                null,
                $"{PreferredFileName(baseName)} is not installed on this machine.",
                false);
        }

        // On 32-bit Windows the narrow build is the only correct answer, and there is nothing to check.
        if (!Environment.Is64BitOperatingSystem)
        {
            return new ToolChoice(narrow, path, null, false);
        }

        // Unreadable is not a refusal: a tool whose header we cannot parse may still be the right one,
        // and the call itself will report a real failure if it is not.
        if (PeImageReader.TryRead(path) is { Is32Bit: true })
        {
            return new ToolChoice(
                null,
                path,
                $"'{path}' is the 32-bit build of {baseName}, which cannot answer correctly on 64-bit " +
                $"Windows: {symptom} Put {wide} beside it -- it ships in the same Sysinternals download " +
                "-- or re-run tools/deploy-target.ps1, which stages both.",
                true);
        }

        return new ToolChoice(narrow, path, null, false);
    }
}
