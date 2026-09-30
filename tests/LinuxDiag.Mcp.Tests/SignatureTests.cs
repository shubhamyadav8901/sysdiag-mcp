using LinuxDiag.Mcp.Diagnostics.Signatures;
using LinuxDiag.Mcp.Linux.Packages;
using LinuxDiag.Mcp.Tools;

namespace LinuxDiag.Mcp.Tests;

public sealed class SignatureTests : IDisposable
{
    private readonly string _root = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"ld-dpkg-{Guid.NewGuid():N}")).FullName;

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch (IOException) { }
    }

    /// <summary>A small dpkg database in the shape dpkg writes it: lists, md5sums, status, diversions.</summary>
    private DpkgDatabase Database()
    {
        var info = Directory.CreateDirectory(Path.Combine(_root, "info")).FullName;
        File.WriteAllText(Path.Combine(info, "coreutils.list"), "/.\n/usr\n/usr/bin\n/usr/bin/sleep\n");
        File.WriteAllText(Path.Combine(info, "coreutils.md5sums"), "870b1913d5f9a10bce0c6745be1eaf64  usr/bin/sleep\n");
        File.WriteAllText(Path.Combine(info, "libc6:amd64.list"), "/usr/lib/x86_64-linux-gnu/libc.so.6\n");
        File.WriteAllText(Path.Combine(info, "libc6:amd64.md5sums"), "aaaa1111aaaa1111aaaa1111aaaa1111  usr/lib/x86_64-linux-gnu/libc.so.6\n");
        File.WriteAllText(Path.Combine(info, "nomd5.list"), "/usr/bin/nomd5\n");
        File.WriteAllText(Path.Combine(info, "cron.list"), "/etc/default/cron\n/usr/sbin/cron\n");
        File.WriteAllText(Path.Combine(info, "oldpkg.list"), "/bin/oldtool\n");
        File.WriteAllText(Path.Combine(info, "oldpkg.md5sums"), "bbbb2222bbbb2222bbbb2222bbbb2222  bin/oldtool\n");
        File.WriteAllText(Path.Combine(info, "bash.list"), "/bin/sh\n");
        File.WriteAllText(Path.Combine(info, "dash.list"), "/usr/bin/sh\n");
        File.WriteAllText(Path.Combine(_root, "status"),
            "Package: coreutils\nStatus: install ok installed\nVersion: 9.4-3ubuntu6\n\n" +
            "Package: libc6\nArchitecture: amd64\nMulti-Arch: same\nVersion: 2.39-0ubuntu8\n\n" +
            "Package: cron\nVersion: 3.0pl1-184ubuntu2\nConffiles:\n /etc/default/cron bc9ab63f9e143d7338909d50494d552f\n /etc/init.d/cron 36fb1d99878caaafe31e6397b4519323\nDescription: process scheduling daemon\n");
        File.WriteAllText(Path.Combine(_root, "diversions"), "/usr/bin/sh\n/usr/bin/sh.distrib\ndash\n");
        return new DpkgDatabase(_root);
    }

    [Fact]
    public void A_file_is_owned_with_its_version_and_expected_checksum()
    {
        var owner = Database().Owner("/usr/bin/sleep");

        Assert.Equal(new PackageFile("coreutils", "9.4-3ubuntu6", "870b1913d5f9a10bce0c6745be1eaf64", false, null), owner);
    }

    [LinuxFact]
    public void A_multiarch_package_is_named_with_its_architecture_and_versioned_from_its_status()
    {
        // Linux only: on Windows "libc6:amd64.list" is an alternate data stream of a file named libc6, and no
        // listing ever shows it.
        var database = Database();

        Assert.Equal("libc6:amd64", database.Owner("/usr/lib/x86_64-linux-gnu/libc.so.6")?.Package);
        Assert.Equal("2.39-0ubuntu8", database.Owner("/usr/lib/x86_64-linux-gnu/libc.so.6")?.Version);
        Assert.Equal("aaaa1111aaaa1111aaaa1111aaaa1111", database.Owner("/usr/lib/x86_64-linux-gnu/libc.so.6")?.ExpectedMd5);
    }

    [Fact]
    public void Usr_merge_conffiles_and_a_package_without_checksums_are_each_read_right()
    {
        // Review Focus 3.
        var database = Database();

        Assert.Equal("bbbb2222bbbb2222bbbb2222bbbb2222", database.Owner("/usr/bin/oldtool")?.ExpectedMd5); // listed as /bin/oldtool
        var conffile = database.Owner("/etc/default/cron");
        Assert.True(conffile!.Conffile);
        Assert.Equal("bc9ab63f9e143d7338909d50494d552f", conffile.ExpectedMd5);
        Assert.Null(database.Owner("/usr/bin/nomd5")!.ExpectedMd5);
        Assert.Null(database.Owner("/usr/local/bin/mine"));
    }

    [Fact]
    public void A_diversion_gives_the_moved_file_to_its_original_package_and_the_path_to_the_diverter()
    {
        var database = Database();

        var moved = database.Owner("/usr/bin/sh.distrib");
        var diverted = database.Owner("/usr/bin/sh");

        Assert.Equal("bash", moved?.Package);
        Assert.Equal("dash", moved?.DivertedBy);
        Assert.Equal("dash", diverted?.Package);

        // Diversions are recorded under one spelling of a usr-merged path; asked by the other, the answer is the same.
        Assert.Equal("bash", database.Owner("/bin/sh.distrib")?.Package);
        Assert.Equal("dash", database.Owner("/bin/sh")?.Package);
    }

    [Fact]
    public void The_verdict_names_integrity_against_the_database_and_never_calls_a_conffile_modified()
    {
        var owned = new PackageFile("coreutils", "9.4", "abc", false, null);
        var conffile = new PackageFile("cron", "3.0", "abc", true, null);

        Assert.Equal(PackageVerdict.Valid, DpkgDatabase.Judge(owned, "ABC").Verdict);
        Assert.Contains("matches the dpkg database", DpkgDatabase.Judge(owned, "abc").Detail, StringComparison.Ordinal);
        Assert.Equal(PackageVerdict.Modified, DpkgDatabase.Judge(owned, "def").Verdict);
        Assert.Equal(PackageVerdict.ConfigurationChanged, DpkgDatabase.Judge(conffile, "def").Verdict);
        Assert.Equal(PackageVerdict.Unknown, DpkgDatabase.Judge(owned with { ExpectedMd5 = null }, "def").Verdict);
        Assert.Equal(PackageVerdict.Unpackaged, DpkgDatabase.Judge(null, "def").Verdict);
    }

    [Fact]
    public void A_half_written_line_is_skipped_rather_than_failing_the_database()
    {
        var md5 = DpkgDatabase.ParseMd5Sums("870b1913d5f9a10bce0c6745be1eaf64  usr/bin/sleep\ntruncated\n\n");
        var diversions = DpkgDatabase.ParseDiversions("/a\n/b\npkg\n/c\n");

        Assert.Single(md5);
        Assert.Equal("870b1913d5f9a10bce0c6745be1eaf64", md5["/usr/bin/sleep"]);
        Assert.Single(diversions);
    }

    [Fact]
    public void Every_captured_distro_parses()
    {
        foreach (var distro in ProcParserTests.Distros())
        {
            Assert.Contains("/usr/bin/sleep", ProcParserTests.Fixture(distro, "dpkg-coreutils.list")!.Split('\n'));
            Assert.True(DpkgDatabase.ParseMd5Sums(ProcParserTests.Fixture(distro, "dpkg-coreutils.md5sums")!).ContainsKey("/usr/bin/sleep"));
            var status = DpkgDatabase.ParseStatus(ProcParserTests.Fixture(distro, "dpkg-status-cron")!);
            Assert.True(status["cron"].Conffiles.ContainsKey("/etc/default/cron"));
            Assert.Equal(0, ProcParserTests.Fixture(distro, "dpkg-diversions")!.Split('\n', StringSplitOptions.RemoveEmptyEntries).Length % 3);
        }
    }

    [Fact]
    public void More_paths_than_one_call_takes_are_refused_and_a_long_summary_is_elided()
    {
        var paths = Enumerable.Range(0, LinuxSignatureInspector.MaxPaths + 1).Select(i => $"/tmp/f{i}").ToArray();
        var files = Enumerable.Range(0, RenderLimits.MaxRenderedRows + 5)
            .Select(i => new FileSignature($"/f{i}", PackageVerdict.Unpackaged, "No installed package owns this file.", null,
                null, null, false, null, 1, DateTimeOffset.UnixEpoch, "AB"))
            .ToList();

        var ex = Assert.Throws<ArgumentException>(() => new LinuxSignatureInspector(new DpkgDatabaseSource()).Inspect(paths));
        var summary = SignatureTools.Render(new SignatureQueryResult(files, [], null));

        Assert.Contains($"at most {LinuxSignatureInspector.MaxPaths}", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain($"/f{RenderLimits.MaxRenderedRows + 1}", summary, StringComparison.Ordinal);
        Assert.Contains("structured content", summary, StringComparison.Ordinal);
    }

    [Fact]
    public void A_local_diversion_is_named_as_one()
    {
        // dpkg records an administrator's own diversion with ":" where a package name would be.
        var summary = SignatureTools.Render(new SignatureQueryResult(
            [new FileSignature("/usr/bin/x", PackageVerdict.Valid, "ok", null, "pkg", "1", false, ":", 1, DateTimeOffset.UnixEpoch, "AB")],
            [], null));

        Assert.Contains("(a local diversion)", summary, StringComparison.Ordinal);
        Assert.DoesNotContain("diverted by :", summary, StringComparison.Ordinal);
    }

    [Fact]
    public void The_summary_names_the_verdict_package_and_hash_and_says_when_there_is_no_dpkg()
    {
        var summary = SignatureTools.Render(new SignatureQueryResult(
            [new FileSignature("/usr/bin/sleep", PackageVerdict.Modified, "Does NOT match the dpkg database for coreutils 9.4.", null,
                "coreutils", "9.4", false, null, 35336, DateTimeOffset.UnixEpoch, "ABC123")],
            ["/nope"], "This machine has no dpkg database."));

        Assert.Contains("WARNING: This machine has no dpkg database.", summary, StringComparison.Ordinal);
        Assert.Contains("NOT FOUND: /nope", summary, StringComparison.Ordinal);
        Assert.Contains("MODIFIED - Does NOT match", summary, StringComparison.Ordinal);
        Assert.Contains("SHA-256: ABC123", summary, StringComparison.Ordinal);
    }

    [LinuxFact]
    public void A_system_binary_matches_its_package_an_own_file_is_unpackaged_and_a_symlink_is_followed()
    {
        var mine = Path.Combine(_root, "mine.bin");
        File.WriteAllBytes(mine, [1, 2, 3]);
        var link = Path.Combine(_root, "sleep-link");
        File.CreateSymbolicLink(link, "/usr/bin/sleep");
        var fifo = Path.Combine(_root, "pipe");
        LockParserTests.Run("mkfifo", fifo);

        var result = new LinuxSignatureInspector(new DpkgDatabaseSource()).Inspect([ "/usr/bin/sleep", mine, link, fifo, "/no/such" ]);

        var sleep = result.Files.Single(f => f.Path == "/usr/bin/sleep");
        Assert.Equal(PackageVerdict.Valid, sleep.Verdict);
        Assert.Equal("coreutils", sleep.Package);
        Assert.Equal(PackageVerdict.Unpackaged, result.Files.Single(f => f.Path == mine).Verdict);
        Assert.Equal(64, result.Files.Single(f => f.Path == mine).Sha256.Length);
        var followed = result.Files.Single(f => f.Path == link);
        Assert.Equal("/usr/bin/sleep", followed.ResolvedPath);
        Assert.Equal("coreutils", followed.Package);
        Assert.Contains(result.NotFound, n => n.StartsWith(fifo, StringComparison.Ordinal) && n.Contains("not a regular file", StringComparison.Ordinal));
        Assert.Contains("/no/such", result.NotFound);
    }
}
