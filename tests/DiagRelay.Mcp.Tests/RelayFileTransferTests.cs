using System.Collections;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text.Json;
using ModelContextProtocol.Protocol;

namespace DiagRelay.Mcp.Tests;

/// <summary>
/// The relay's own file transfer: chunk boundaries, the per-chunk retry, and every hash check.
/// </summary>
/// <remarks>
/// <para>These loops exist so a transfer costs a tool call rather than a payload, which means nothing
/// about them is observable from the conversation -- the caller sees one summary line whether the bytes
/// arrived intact or not. The verification therefore has to live here.</para>
/// <para>Driven through a fake <see cref="ForwardTool"/> rather than a live target: the interesting
/// cases are a corrupted slice, a truncated file and a refused chunk, none of which a healthy VM will
/// produce on demand.</para>
/// </remarks>
public sealed class RelayFileTransferTests : IDisposable
{
    private readonly string _directory =
        Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "sysdiag-relay-tests", Guid.NewGuid().ToString("N")))
            .FullName;

    public void Dispose()
    {
        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (IOException)
        {
            // A leftover temp directory is not worth failing a green run over.
        }
    }

    private string Local(string name) => Path.Combine(_directory, name);

    private static string Hex(byte[] data) => Convert.ToHexString(SHA256.HashData(data));

    /// <summary>Records what a push sent, and answers as a healthy target would.</summary>
    private sealed class FakeTarget
    {
        public List<(bool Append, byte[] Bytes, string? ExpectedSha, bool? Overwrite)> Writes { get; } = [];

        public int Refusals { get; set; }

        public ForwardTool Forward => (tool, args, _) =>
        {
            Assert.Equal("put_file", tool);

            if (Refusals > 0)
            {
                Refusals--;
                return Task.FromResult(new CallToolResult
                {
                    IsError = true,
                    Content = [new TextContentBlock { Text = "chunk hash mismatch" }]
                });
            }

            var bytes = Convert.FromBase64String((string)args["contentBase64"]!);

            // The target checks this before writing; a loop that computed it over the wrong buffer would
            // otherwise go unnoticed until a real transfer corrupted a file.
            Assert.Equal(Hex(bytes), (string)args["chunkSha256"]!);

            Writes.Add((
                (bool)args["append"]!,
                bytes,
                args.TryGetValue("expectedSha256", out var sha) ? (string?)sha : null,
                args.TryGetValue("overwrite", out var o) ? (bool?)o : null));

            return Task.FromResult(new CallToolResult());
        };
    }

    [Theory]
    [InlineData(0)]                        // empty file: still needs one call, or nothing is created
    [InlineData(64)]                       // well under one chunk
    [InlineData(RelayFileTransfer.ChunkBytes)]      // exactly one chunk
    [InlineData(RelayFileTransfer.ChunkBytes + 1)]  // the off-by-one that splits a file in two
    public async Task Push_sends_the_whole_file_and_reassembles_byte_for_byte(int size)
    {
        var content = new byte[size];
        Random.Shared.NextBytes(content);

        var path = Local("push.bin");
        await File.WriteAllBytesAsync(path, content);

        var target = new FakeTarget();
        var outcome = await RelayFileTransfer.PushAsync(
            target.Forward, path, @"C:\WinDiag\push.bin", overwrite: true, CancellationToken.None);

        Assert.Equal(content, target.Writes.SelectMany(w => w.Bytes).ToArray());
        Assert.Equal(size, outcome.Bytes);
        Assert.Equal(Hex(content), outcome.Sha256);
        Assert.Equal(target.Writes.Count, outcome.Chunks);

        // Only the first call may create; every later one must append, or each chunk overwrites the last
        // and a multi-chunk file silently becomes just its final chunk.
        Assert.False(target.Writes[0].Append);
        Assert.All(target.Writes.Skip(1), w => Assert.True(w.Append));

        // The whole-file hash rides on the last call only, which is where the target can act on it.
        Assert.All(target.Writes.SkipLast(1), w => Assert.Null(w.ExpectedSha));
        Assert.Equal(Hex(content), target.Writes[^1].ExpectedSha);
    }

    [Fact]
    public async Task Push_retries_only_the_refused_chunk()
    {
        var content = new byte[1024];
        Random.Shared.NextBytes(content);

        var path = Local("retry.bin");
        await File.WriteAllBytesAsync(path, content);

        var target = new FakeTarget { Refusals = 2 };
        var outcome = await RelayFileTransfer.PushAsync(
            target.Forward, path, @"C:\WinDiag\retry.bin", overwrite: true, CancellationToken.None);

        // Two refusals then success: the chunk is re-sent, and the file still arrives exactly once.
        Assert.Equal(2, outcome.Retries);
        Assert.Single(target.Writes);
        Assert.Equal(content, target.Writes[0].Bytes);
    }

    [Fact]
    public async Task Push_gives_up_after_the_attempt_limit_and_says_the_target_was_left_dirty()
    {
        var path = Local("doomed.bin");
        await File.WriteAllBytesAsync(path, new byte[16]);

        var target = new FakeTarget { Refusals = RelayFileTransfer.ChunkAttempts };

        var ex = await Assert.ThrowsAsync<RelayException>(() => RelayFileTransfer.PushAsync(
            target.Forward, path, @"C:\WinDiag\doomed.bin", overwrite: true, CancellationToken.None));

        Assert.Contains("chunk hash mismatch", ex.Message, StringComparison.Ordinal);

        // A partial file left under the destination name is the caller's problem to know about.
        Assert.Contains("Nothing was rolled back", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Push_refuses_a_file_that_is_not_there()
    {
        var ex = await Assert.ThrowsAsync<RelayException>(() => RelayFileTransfer.PushAsync(
            new FakeTarget().Forward, Local("absent.bin"), @"C:\WinDiag\a.bin", true, CancellationToken.None));

        Assert.Contains("no file at", ex.Message, StringComparison.Ordinal);
    }

    /// <summary>Serves a file back in slices, the way get_file does.</summary>
    private static ForwardTool Server(
        byte[] content, bool corruptFirstSlice = false, bool lieAboutTotal = false, bool omitWholeHash = false)
    {
        return (tool, args, _) =>
        {
            Assert.Equal("get_file", tool);

            var offset = Convert.ToInt32(args["offset"]);
            var length = Math.Min(Convert.ToInt32(args["length"]), content.Length - offset);
            var slice = content.Skip(offset).Take(length).ToArray();
            var endOfFile = offset + length >= content.Length;

            // The hash the target reports is over what it read; corrupting the bytes after hashing is
            // exactly what a lossy link does.
            var chunkSha = Hex(slice);
            if (corruptFirstSlice && offset == 0 && slice.Length > 0)
            {
                slice = (byte[])slice.Clone();
                slice[0] ^= 0xFF;
            }

            var file = new Dictionary<string, object?>
            {
                ["content"] = Convert.ToBase64String(slice),
                ["chunkSha256"] = chunkSha,
                ["totalBytes"] = lieAboutTotal ? content.Length + 10 : content.Length,
                ["endOfFile"] = endOfFile
            };

            if ((bool)args["includeWholeFileHash"]! && !omitWholeHash)
            {
                file["sha256"] = Hex(content);
            }

            var payload = JsonSerializer.SerializeToElement(new Dictionary<string, object?> { ["file"] = file });
            return Task.FromResult(new CallToolResult { StructuredContent = payload });
        };
    }

    [Theory]
    [InlineData(0)]
    [InlineData(2048)]
    [InlineData(RelayFileTransfer.ChunkBytes + 7)]
    public async Task Pull_reassembles_the_file_and_verifies_it(int size)
    {
        var content = new byte[size];
        Random.Shared.NextBytes(content);

        var path = Local("pulled.bin");
        var outcome = await RelayFileTransfer.PullAsync(
            Server(content), @"C:\WinDiag\x.bin", path, overwrite: false, CancellationToken.None);

        Assert.Equal(content, await File.ReadAllBytesAsync(path));
        Assert.Equal(Hex(content), outcome.Sha256);
        Assert.Equal(size, outcome.Bytes);
        Assert.True(outcome.VerifiedAgainstTarget);
    }

    [Fact]
    public async Task Pull_refuses_a_corrupted_slice_and_keeps_nothing()
    {
        var content = new byte[4096];
        Random.Shared.NextBytes(content);
        var path = Local("corrupt.bin");

        var ex = await Assert.ThrowsAsync<RelayException>(() => RelayFileTransfer.PullAsync(
            Server(content, corruptFirstSlice: true), @"C:\x.bin", path, false, CancellationToken.None));

        Assert.Contains("corrupted", ex.Message, StringComparison.Ordinal);

        // The point of the check: a bad copy must not be left where a caller would go on to use it.
        Assert.False(File.Exists(path));
        Assert.False(File.Exists(path + ".partial"));
    }

    [Fact]
    public async Task Pull_refuses_a_file_whose_length_does_not_match_what_the_target_reported()
    {
        var content = new byte[2048];
        Random.Shared.NextBytes(content);
        var path = Local("short.bin");

        var ex = await Assert.ThrowsAsync<RelayException>(() => RelayFileTransfer.PullAsync(
            Server(content, lieAboutTotal: true), @"C:\x.bin", path, false, CancellationToken.None));

        Assert.Contains("Reassembled", ex.Message, StringComparison.Ordinal);
        Assert.False(File.Exists(path));
    }

    [Fact]
    public async Task Pull_says_so_when_the_target_reported_no_whole_file_hash()
    {
        var content = new byte[512];
        Random.Shared.NextBytes(content);
        var path = Local("unverified.bin");

        var outcome = await RelayFileTransfer.PullAsync(
            Server(content, omitWholeHash: true), @"C:\x.bin", path, false, CancellationToken.None);

        // Still written, and every slice was checked -- but not verified end to end, and the caller is
        // told which of the two they have rather than left to infer it.
        Assert.Equal(content, await File.ReadAllBytesAsync(path));
        Assert.False(outcome.VerifiedAgainstTarget);
    }

    [Fact]
    public async Task Pull_will_not_silently_replace_an_existing_local_file()
    {
        var path = Local("existing.bin");
        await File.WriteAllTextAsync(path, "collected earlier");

        var ex = await Assert.ThrowsAsync<RelayException>(() => RelayFileTransfer.PullAsync(
            Server([1, 2, 3]), @"C:\x.bin", path, overwrite: false, CancellationToken.None));

        Assert.Contains("already exists", ex.Message, StringComparison.Ordinal);
        Assert.Equal("collected earlier", await File.ReadAllTextAsync(path));
    }

    [UnixFact]
    [UnsupportedOSPlatform("windows")]
    public async Task A_pulled_file_and_the_directory_made_for_it_are_owner_only_on_unix()
    {
        // Pulls are process dumps and traces -- memory, and often credentials. Under the default umask
        // they would land 0644 in a 0755 directory, readable by every local user.
        var content = new byte[] { 1, 2, 3, 4 };
        var path = Path.Combine(_directory, "made-for-it", "dump.bin");

        await RelayFileTransfer.PullAsync(
            Server(content), @"C:\WinDiag\x.bin", path, overwrite: false, CancellationToken.None);

        Assert.Equal(content, await File.ReadAllBytesAsync(path));
        Assert.Equal(RelayTargetsFile.OwnerOnly, File.GetUnixFileMode(path));
        Assert.Equal(
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute,
            File.GetUnixFileMode(Path.GetDirectoryName(path)!));
    }

    [UnixFact]
    [UnsupportedOSPlatform("windows")]
    public async Task A_symlink_planted_at_the_partial_name_is_replaced_not_followed_on_unix()
    {
        // Anyone who can write the destination directory can put a link at <name>.partial. Followed, it
        // makes the relay overwrite a file of their choosing with the operator's own rights.
        var victim = Local("victim.txt");
        await File.WriteAllTextAsync(victim, "not yours");
        var path = Local("pulled.bin");
        File.CreateSymbolicLink(path + ".partial", victim);

        await RelayFileTransfer.PullAsync(
            Server([9, 9, 9]), @"C:\WinDiag\x.bin", path, overwrite: false, CancellationToken.None);

        Assert.Equal("not yours", await File.ReadAllTextAsync(victim));
        Assert.Equal(new byte[] { 9, 9, 9 }, await File.ReadAllBytesAsync(path));
        Assert.Null(new FileInfo(path).LinkTarget);
    }
}

/// <summary>
/// Which local directories the relay will touch.
/// </summary>
/// <remarks>
/// push_file and pull_file are the first thing the relay does that reads local disk, so this boundary is
/// the difference between a deployment tool and an arbitrary-file exfiltration primitive.
/// </remarks>
public sealed class RelayFileScopeTests
{
    private static Hashtable Environment(string? roots) =>
        roots is null ? [] : new Hashtable { [RelayFileScope.RootsVariable] = roots };

    // A home directory and the places a relay is ordinarily put, none of which need to exist: the layout
    // decision is made on names alone, so these are pure and portable.
    private static readonly string Home = Path.Combine(Path.GetTempPath(), "relay-home", "someone");

    [Fact]
    public void Defaults_to_the_build_and_artifact_directories()
    {
        var roots = RelayFileScope.Roots(Environment(null));

        Assert.Equal(RelayFileScope.DefaultRoots, roots);
        Assert.Contains(RelayFileScope.DefaultArtifactRoot, roots);
    }

    [Fact]
    public void The_published_layout_gives_the_artifacts_tree_the_builds_sit_in()
    {
        // The relay ships at artifacts/diagrelay/ and sends builds from artifacts/win-x64/, so the root has
        // to be the level above the executable. A first version appended "artifacts" to the executable's
        // own directory, yielding artifacts/relay/artifacts -- a default that existed nowhere, so every
        // push of a build was refused until the environment variable was set.
        var artifacts = Path.Combine(Home, "src", "sysdiag", "artifacts");

        Assert.Equal(artifacts, RelayFileScope.BuildRootFor(Path.Combine(artifacts, "diagrelay"), Home));
        Assert.Equal(artifacts, RelayFileScope.BuildRootFor(Path.Combine(artifacts, "diagrelay-osx-arm64"), Home));
    }

    [Fact]
    public void A_relay_directly_in_the_home_directory_gets_no_build_root()
    {
        // Climbing one level from ~/DiagRelay.Mcp handed out /home or /Users -- every user's files.
        Assert.Null(RelayFileScope.BuildRootFor(Home, Home));
    }

    [Fact]
    public void A_relay_in_home_bin_gets_no_build_root()
    {
        // ~/bin/DiagRelay.Mcp climbed to $HOME: ~/.ssh, cloud credentials, and ~/.sysdiag-targets.json with
        // every target's bearer token, one push_file away from a target over plaintext HTTP.
        Assert.Null(RelayFileScope.BuildRootFor(Path.Combine(Home, "bin"), Home));
    }

    [Fact]
    public void A_flat_unpacked_release_folder_gets_no_build_root()
    {
        // A release zip unpacks to a folder of its own; its parent is wherever the operator happened to
        // unpack it -- Downloads, the desktop -- not a build tree.
        Assert.Null(RelayFileScope.BuildRootFor(Path.Combine(Home, "Downloads", "diagrelay-linux-x64"), Home));
    }

    [Fact]
    public void Another_folder_under_some_artifacts_directory_gets_no_build_root()
    {
        // "artifacts" is a common name -- a CI job's output, another project's build -- so the parent's
        // name alone does not say this is sysdiag's tree. The relay's own publish folder has to be there too.
        Assert.Null(RelayFileScope.BuildRootFor(Path.Combine(Home, "ci", "artifacts", "bin"), Home));
    }

    [Fact]
    public void An_artifacts_tree_that_holds_the_home_directory_is_refused()
    {
        // The layout matches by name, so a home that is itself called artifacts -- or sits under one --
        // must still not be handed out whole.
        var artifactsHome = Path.Combine(Path.GetTempPath(), "relay-home", "artifacts");

        Assert.Null(RelayFileScope.BuildRootFor(Path.Combine(artifactsHome, "diagrelay"), artifactsHome));
        Assert.Null(RelayFileScope.BuildRootFor(
            Path.Combine(artifactsHome, "diagrelay"), Path.Combine(artifactsHome, "diagrelay", "me")));
    }

    [Fact]
    public void The_real_default_roots_never_include_the_home_directory_or_anything_above_it()
    {
        // Asserted against the real value as well as the contrived ones. Under the test host the executable
        // is dotnet itself, which a per-user SDK install puts at ~/.dotnet/dotnet -- exactly the shape that
        // used to climb to $HOME.
        var home = System.Environment.GetFolderPath(System.Environment.SpecialFolder.UserProfile);

        foreach (var root in RelayFileScope.DefaultRoots)
        {
            Assert.False(PathScope.IsUnder(home, root), $"the default root '{root}' contains the home directory '{home}'.");
            Assert.NotNull(Directory.GetParent(root));
        }
    }

    [WindowsFact]
    public void The_variable_replaces_the_defaults_rather_than_adding_to_them()
    {
        var roots = RelayFileScope.Roots(Environment(@"C:\builds;C:\dumps"));

        Assert.Equal([@"C:\builds", @"C:\dumps"], roots);
        Assert.DoesNotContain(RelayFileScope.DefaultArtifactRoot, roots);
    }

    [WindowsFact]
    public void A_path_inside_a_root_is_allowed()
    {
        var full = RelayFileScope.Require(@"C:\builds\win-x64\WinDiag.Mcp.exe", "localPath", [@"C:\builds"]);

        Assert.Equal(@"C:\builds\win-x64\WinDiag.Mcp.exe", full);
    }

    [WindowsFact]
    public void A_path_outside_every_root_is_refused_and_the_roots_are_named()
    {
        var ex = Assert.Throws<RelayException>(
            () => RelayFileScope.Require(@"C:\Users\someone\.ssh\id_rsa", "localPath", [@"C:\builds"]));

        Assert.Contains(@"C:\builds", ex.Message, StringComparison.Ordinal);
        Assert.Contains(RelayFileScope.RootsVariable, ex.Message, StringComparison.Ordinal);
    }

    [WindowsFact]
    public void A_traversal_out_of_a_root_is_judged_by_where_it_lands()
    {
        // The classic escape: spelled as if it were inside, resolving to somewhere else entirely.
        Assert.Throws<RelayException>(
            () => RelayFileScope.Require(@"C:\builds\..\Windows\System32\config\SAM", "localPath", [@"C:\builds"]));
    }

    [WindowsFact]
    public void A_sibling_directory_sharing_a_prefix_is_not_inside_the_root()
    {
        // C:\buildsX must not count as being under C:\builds -- a prefix match without the separator
        // boundary is how this check is usually escaped.
        Assert.Throws<RelayException>(
            () => RelayFileScope.Require(@"C:\buildsX\secret.txt", "localPath", [@"C:\builds"]));
    }
}
