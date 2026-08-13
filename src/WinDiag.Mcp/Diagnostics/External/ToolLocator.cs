using System.Collections.Concurrent;
using Microsoft.Win32;

namespace WinDiag.Mcp.Diagnostics.External;

/// <summary>
/// Locates Sysinternals executables via the registry's App Paths key, falling back to PATH.
/// </summary>
/// <remarks>
/// Deliberately does <em>not</em> look inside
/// <c>C:\Program Files\WindowsApps\Microsoft.SysinternalsSuite_&lt;version&gt;_x64__8wekyb3d8bbwe\Tools</c>.
/// That directory name embeds the package version and changes on every Store update, so hardcoding it
/// produces a tool that works until the machine patches and then mysteriously stops.
/// <para>
/// The <c>WindowsApps</c> entries on PATH are zero-byte reparse points whose target is not readable,
/// so PATH alone resolves the alias but not the real binary. App Paths holds the real path and is
/// maintained by the installer, which makes it the reliable source.
/// </para>
/// </remarks>
public sealed class ToolLocator : IToolLocator
{
    private const string AppPathsSubKey = @"Software\Microsoft\Windows\CurrentVersion\App Paths";

    /// <summary>
    /// Successful resolutions only.
    /// </summary>
    /// <remarks>
    /// Misses are deliberately not cached. Caching them would mean that installing Sysinternals while
    /// the server is running leaves every call failing with "not found" -- telling the user to do the
    /// thing they just did -- until someone restarts the server. A registry read per miss is cheap.
    /// </remarks>
    private readonly ConcurrentDictionary<string, string> _cache = new(StringComparer.OrdinalIgnoreCase);

    public string Resolve(string executableName)
    {
        if (TryResolve(executableName, out var fullPath))
        {
            return fullPath;
        }

        throw new ToolNotFoundException(executableName);
    }

    public bool TryResolve(string executableName, out string fullPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executableName);

        if (_cache.TryGetValue(executableName, out var cached))
        {
            fullPath = cached;
            return true;
        }

        var resolved = Locate(executableName);
        if (resolved is null)
        {
            fullPath = string.Empty;
            return false;
        }

        _cache[executableName] = resolved;
        fullPath = resolved;
        return true;
    }

    private static string? Locate(string executableName)
    {
        return BesideTheServer(executableName)
               ?? FromAppPaths(Registry.CurrentUser, executableName)
               ?? FromAppPaths(Registry.LocalMachine, executableName)
               ?? FromSearchPath(executableName);
    }

    /// <summary>Looks in the directory the server executable itself lives in.</summary>
    /// <remarks>
    /// <para>Checked first because it matches how this actually gets deployed: copy a folder to a
    /// target machine containing the server and whatever Sysinternals binaries it needs. Nothing gets
    /// installed there, so App Paths is empty and PATH knows nothing about it.</para>
    /// <para>Found the hard way — a freshly deployed lab VM reported <c>capture_activity</c> and
    /// <c>path_handle_search</c> as unavailable with Procmon sitting in a folder on the desktop.</para>
    /// <para><see cref="Environment.ProcessPath"/> rather than <c>AppContext.BaseDirectory</c>: under a
    /// single-file publish the latter points at the extraction directory, not at the exe.</para>
    /// </remarks>
    private static string? BesideTheServer(string executableName)
    {
        var directory = Path.GetDirectoryName(Environment.ProcessPath);
        if (string.IsNullOrEmpty(directory))
        {
            return null;
        }

        var candidate = Path.Combine(directory, executableName);
        return File.Exists(candidate) ? candidate : null;
    }

    private static string? FromAppPaths(RegistryKey root, string executableName)
    {
        try
        {
            using var key = root.OpenSubKey($@"{AppPathsSubKey}\{executableName}");
            var value = key?.GetValue(null) as string;
            if (string.IsNullOrWhiteSpace(value))
            {
                return null;
            }

            // App Paths values are sometimes quoted.
            var candidate = value.Trim().Trim('"');
            return File.Exists(candidate) ? candidate : null;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static string? FromSearchPath(string executableName)
    {
        var pathVariable = Environment.GetEnvironmentVariable("PATH");
        if (string.IsNullOrEmpty(pathVariable))
        {
            return null;
        }

        foreach (var directory in pathVariable.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            string candidate;
            try
            {
                candidate = Path.Combine(directory.Trim(), executableName);
            }
            catch (ArgumentException)
            {
                // A malformed PATH entry should skip that entry, not fail resolution outright.
                continue;
            }

            // A zero-length file here is a WindowsApps alias reparse point: it resolves and executes,
            // but only via the shell's alias handling. Accept it as a last resort -- it still runs.
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return null;
    }
}
