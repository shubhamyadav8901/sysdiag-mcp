using Diag.Mcp.Core;
using Diag.Mcp.Server.Files;
using WinDiag.Mcp.Configuration;
using WinDiag.Mcp.Diagnostics.Access;
using WinDiag.Mcp.Diagnostics.Activity;
using WinDiag.Mcp.Diagnostics.Handles;
using WinDiag.Mcp.Diagnostics.Locks;
using WinDiag.Mcp.Diagnostics.Network;
using WinDiag.Mcp.Diagnostics.Signatures;
using WinDiag.Mcp.Tools;

namespace WinDiag.Mcp.Tests;

/// <summary>Every tool that opens a path it was given refuses a share or a device before touching it.</summary>
/// <remarks>
/// <c>\\host\share\x</c> made the LocalSystem service open SMB to that host and sign in as the machine
/// account, which an attacker relays. who_locks_path, file_signatures, effective_access and query_activity
/// are all registered on a read-only server, so a token with no grants could trigger it. Each fake records
/// whether it was reached: the inspector is the first thing that would open the path.
/// </remarks>
public sealed class NetworkPathToolTests
{
    private static FileTransferOptions Files(bool arbitraryRead = false) =>
        new(Path.GetTempPath(), false, arbitraryRead, "WINDIAG_ALLOW_ARBITRARY_WRITE=1", "WINDIAG_ALLOW_ARBITRARY_READ=1");

    public static TheoryData<string> RemotePaths => new()
    {
        @"\\192.0.2.1\share\secret.txt",
        "//192.0.2.1/share/secret.txt",
        @"\\?\UNC\192.0.2.1\share\secret.txt",
        @"\\?\GLOBALROOT\Device\Mup\192.0.2.1\share\secret.txt",
        @"\\.\pipe\spoolss",
    };

    private sealed class RecordingLocks : ILockInspector
    {
        public List<string> Asked { get; } = [];

        public LockQueryResult WhoLocks(string path, CancellationToken cancellationToken)
        {
            Asked.Add(path);
            return new LockQueryResult(path, [], Exhaustive: false);
        }
    }

    private sealed class RecordingAccess : IAccessInspector
    {
        public List<string> Asked { get; } = [];

        public AccessReport Inspect(string path, string? account, bool probeWrite, CancellationToken cancellationToken)
        {
            Asked.Add(path);
            return new AccessReport(path, SecurableKind.File, "owner", [], account, [],
                new AccessProbe(true, null, null, null), "probe");
        }
    }

    private sealed class RecordingSignatures : ISignatureInspector
    {
        public List<string> Asked { get; } = [];

        public SignatureQueryResult Inspect(IReadOnlyList<string> paths, CancellationToken cancellationToken)
        {
            Asked.AddRange(paths);
            return new SignatureQueryResult([], paths);
        }

        public FileSignature InspectHeld(string path, CancellationToken cancellationToken) =>
            throw new NotSupportedException("path refusal never reaches a held-file signature check");

        public FileSignature InspectHeld(string path, FileStream held, CancellationToken cancellationToken) =>
            throw new NotSupportedException("path refusal never reaches a held-file signature check");
    }

    private sealed class RecordingActivity : IActivityInspector
    {
        public List<string> Asked { get; } = [];

        public Task<ActivityCapture> CaptureAsync(int durationSeconds, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Not used.");

        public ActivityQueryResult Query(string capturePath, ActivityFilter filter, CancellationToken cancellationToken)
        {
            Asked.Add(capturePath);
            return new ActivityQueryResult(capturePath, 0, 0, false, [], [], [], []);
        }
    }

    private sealed class NoNetwork : INetworkInspector
    {
        public NetworkEndpointsResult List(int? port, int? processId, bool listeningOnly, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Not used.");
    }

    private static void AssertRefused(Action call)
    {
        var ex = Assert.ThrowsAny<ArgumentException>(call);
        Assert.Contains("network share or a device", ex.Message, StringComparison.Ordinal);
        Assert.Contains("WINDIAG_ALLOW_ARBITRARY_READ=1", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [MemberData(nameof(RemotePaths))]
    public void Who_locks_path_refuses_a_remote_path_before_looking_at_it(string path)
    {
        var locks = new RecordingLocks();
        var tools = new FileLockTools(
            locks,
            new FakeHandleInspector(new HandleSearchResult("x", [], true, false, 0, false)),
            new FakePrivilegeProbe(true),
            Files());

        AssertRefused(() => tools.WhoLocksPath(path, CancellationToken.None));
        Assert.Empty(locks.Asked);
    }

    [Theory]
    [MemberData(nameof(RemotePaths))]
    public void Effective_access_refuses_a_remote_path_before_looking_at_it(string path)
    {
        var access = new RecordingAccess();

        AssertRefused(() => new AccessTools(access, Files()).EffectiveAccess(path));
        Assert.Empty(access.Asked);
    }

    [Theory]
    [MemberData(nameof(RemotePaths))]
    public void File_signatures_refuses_a_remote_path_among_local_ones_before_looking_at_any(string path)
    {
        var signatures = new RecordingSignatures();

        AssertRefused(() => new InventoryTools(new NoNetwork(), signatures, Files())
            .FileSignatures([@"C:\Windows\System32\cmd.exe", path]));
        Assert.Empty(signatures.Asked);
    }

    [Theory]
    [MemberData(nameof(RemotePaths))]
    public void Query_activity_refuses_a_remote_path_before_looking_at_it(string path)
    {
        var activity = new RecordingActivity();
        var tools = new ActivityQueryTools(activity, new WinDiagOptions(), Files());

        AssertRefused(() => tools.QueryActivity(path));
        Assert.Empty(activity.Asked);
    }

    [Fact]
    public void Arbitrary_read_lets_a_tool_reach_a_share_because_that_grant_already_means_anything_it_can_open()
    {
        var access = new RecordingAccess();

        new AccessTools(access, Files(arbitraryRead: true)).EffectiveAccess(@"\\fileserver\share\app.config");

        Assert.Equal([@"\\fileserver\share\app.config"], access.Asked);
    }

    [Fact]
    public void Effective_access_on_a_registry_key_is_not_judged_as_a_file_path()
    {
        var access = new RecordingAccess();

        new AccessTools(access, Files()).EffectiveAccess(@"HKLM\SOFTWARE\Vendor");

        Assert.Equal([@"HKLM\SOFTWARE\Vendor"], access.Asked);
    }
}
