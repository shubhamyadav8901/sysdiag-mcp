using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using MacDiag.Mcp.Diagnostics.SelfUpdate;

namespace MacDiag.Mcp.Tests;

/// <summary>Runs the generated update script under /bin/sh with recording fakes, and checks what it really did.</summary>
/// <remarks>
/// The script is the one thing between update_self and a Mac with no server, and its abort and rollback branches
/// never run in the CI smoke, which only succeeds. String checks cannot catch a wrong condition or a command that
/// never runs; executing it can. launchctl, nc and sleep are fakes; the file tools are the real ones behind a
/// recording wrapper that can be told to fail.
/// </remarks>
[UnsupportedOSPlatform("windows")]
public sealed class RestartScriptRunTests : IDisposable
{
    private const string Label = "com.sysdiag.macdiag";
    private readonly string _root = Directory.CreateTempSubdirectory("helper-run-").FullName;
    private readonly string _bin;
    private readonly string _live;
    private readonly string _staged;
    private readonly int _deadPid;

    public RestartScriptRunTests()
    {
        _bin = Directory.CreateDirectory(Path.Combine(_root, "bin")).FullName;
        _live = Path.Combine(_root, "MacDiag.Mcp");
        _staged = _live + ".new";
        File.WriteAllText(_live, "old build");
        File.WriteAllText(_staged, "new build");

        // A PID that is certainly not running: a child that has already exited.
        using var done = Process.Start("/bin/sh", ["-c", "exit 0"])!;
        done.WaitForExit();
        _deadPid = done.Id;
        File.WriteAllText(Path.Combine(_bin, "old-pid"), _deadPid.ToString(System.Globalization.CultureInfo.InvariantCulture));

        foreach (var tool in new[] { "ln", "mv", "chmod", "sed", "head", "cut", "tr", "date" })
        {
            Wrap(tool, $"exec {Real(tool)} \"$@\"");
        }

        Wrap("shasum", $"if [ -x {Real("sha256sum", required: false)} ]; then exec {Real("sha256sum", required: false)} \"$3\"; else exec {Real("shasum", required: false)} -a 256 \"$3\"; fi");
        Wrap("sleep", "exit 0");
        Wrap("nc", "exit 0");
        Wrap("launchctl", """
            case "$1" in
              print) if [ -f "$d/new-pid" ]; then echo "	pid = $(cat "$d/new-pid")"; else echo "	pid = $(cat "$d/old-pid")"; fi ;;
              kickstart) if [ ! -f "$d/no-new-pid" ]; then echo 9999 > "$d/new-pid"; fi ;;
            esac
            exit 0
            """);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    private static string Real(string tool, bool required = true) =>
        new[] { "/usr/bin/", "/bin/" }.Select(d => d + tool).FirstOrDefault(File.Exists)
        ?? (required ? throw new InvalidOperationException($"{tool} not found") : "/nonexistent/" + tool);

    /// <summary>A fake that records "name args" and fails when a file named fail-&lt;name&gt; exists.</summary>
    private void Wrap(string tool, string body)
    {
        var path = Path.Combine(_bin, tool);
        File.WriteAllText(path,
            "#!/bin/sh\nd=\"$(dirname \"$0\")\"\n" +
            $"echo \"{tool} $*\" >> \"$d/calls\"\n" +
            $"if [ -f \"$d/fail-{tool}\" ]; then exit 1; fi\n" +
            body.ReplaceLineEndings("\n") + "\n");
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }

    private HelperTools Fakes() => new(
        Path.Combine(_bin, "shasum"), Path.Combine(_bin, "launchctl"), Path.Combine(_bin, "nc"), Path.Combine(_bin, "ln"),
        Path.Combine(_bin, "mv"), Path.Combine(_bin, "chmod"), Path.Combine(_bin, "sed"), Path.Combine(_bin, "head"),
        Path.Combine(_bin, "cut"), Path.Combine(_bin, "tr"), Path.Combine(_bin, "sleep"),
        Path.Combine(_bin, "date"));

    private static string Sha(string text) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text)));

    private (int ExitCode, string[] Calls) Run(string expectedSha)
    {
        var script = Path.Combine(_root, "self-update.sh");
        File.WriteAllText(script, LaunchdRestartHelper.Script(
            _deadPid, _live, _staged, expectedSha, Path.Combine(_root, "self-update.log"), Label, ("127.0.0.1", 4025),
            ["--env-file", "/etc/macdiag/x.env"], Fakes(), confirmSeconds: 3));

        using var process = Process.Start("/bin/sh", [script])!;
        Assert.True(process.WaitForExit(30_000), "the script did not finish");
        var calls = Path.Combine(_bin, "calls");
        return (process.ExitCode, File.Exists(calls) ? File.ReadAllLines(calls) : []);
    }

    private static string[] Launchctl(string[] calls) => calls.Where(c => c.StartsWith("launchctl kickstart", StringComparison.Ordinal)).ToArray();

    [UnixFact]
    public void A_good_build_is_swapped_in_kept_and_the_old_one_backed_up()
    {
        var (exit, calls) = Run(Sha("new build"));

        Assert.Equal(0, exit);
        Assert.Equal("new build", File.ReadAllText(_live));
        Assert.Equal("old build", File.ReadAllText(_live + ".old"));
        Assert.Equal([$"launchctl kickstart -k system/{Label}"], Launchctl(calls));
        Assert.Contains(calls, c => c.StartsWith("nc -z -G 2 127.0.0.1 4025", StringComparison.Ordinal));
    }

    [UnixFact]
    public void A_hash_mismatch_changes_nothing_and_starts_the_existing_build()
    {
        var (exit, calls) = Run(Sha("something else"));

        Assert.Equal(2, exit);
        Assert.Equal("old build", File.ReadAllText(_live));
        Assert.Equal([$"launchctl kickstart system/{Label}"], Launchctl(calls));
    }

    [UnixFact]
    public void A_failed_backup_changes_nothing_and_starts_the_existing_build()
    {
        File.WriteAllText(Path.Combine(_bin, "fail-ln"), "");

        var (exit, calls) = Run(Sha("new build"));

        Assert.Equal(3, exit);
        Assert.Equal("old build", File.ReadAllText(_live));
        Assert.Equal([$"launchctl kickstart system/{Label}"], Launchctl(calls));
    }

    [UnixFact]
    public void A_failed_move_leaves_the_old_build_and_starts_it()
    {
        File.WriteAllText(Path.Combine(_bin, "fail-mv"), "");

        var (exit, calls) = Run(Sha("new build"));

        Assert.Equal(4, exit);
        Assert.Equal("old build", File.ReadAllText(_live));
        Assert.Equal([$"launchctl kickstart system/{Label}"], Launchctl(calls));
    }

    [UnixFact]
    public void A_build_that_never_comes_up_is_rolled_back_and_the_old_one_started_again()
    {
        File.WriteAllText(Path.Combine(_bin, "no-new-pid"), "");

        var (exit, calls) = Run(Sha("new build"));

        Assert.Equal(5, exit);
        Assert.Equal("old build", File.ReadAllText(_live));
        Assert.Equal([$"launchctl kickstart -k system/{Label}", $"launchctl kickstart -k system/{Label}"], Launchctl(calls));
    }
}
