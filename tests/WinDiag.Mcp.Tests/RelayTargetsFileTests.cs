using System.Security.AccessControl;
using System.Security.Principal;
using WinDiag.Mcp.Relay;

namespace WinDiag.Mcp.Tests;

/// <summary>
/// The targets-file parser the relay pre-connects from at launch. One shape only -- an object with a
/// <c>targets</c> array -- so these pin what a valid file yields and which malformed ones are refused
/// loudly rather than half-accepted.
/// </summary>
public sealed class RelayTargetsFileTests
{
    [Fact]
    public void Parses_each_target_with_its_alias_address_and_token()
    {
        var entries = RelayTargetsFile.Parse("""
            {"targets":[
              {"as":"w11","target":"192.168.32.93","token":"secret-a"},
              {"as":"w10","target":"192.168.32.76","token":"secret-b"}
            ]}
            """);

        Assert.Equal(2, entries.Count);
        Assert.Equal("w11", entries[0].As);
        Assert.Equal("192.168.32.93", entries[0].Target);
        Assert.Equal("secret-a", entries[0].Token);
        Assert.Null(entries[0].Port);
        Assert.Equal("w10", entries[1].As);
        Assert.Equal("192.168.32.76", entries[1].Target);
    }

    [Fact]
    public void Alias_and_port_are_optional()
    {
        var entries = RelayTargetsFile.Parse("""
            {"targets":[{"target":"host.example","token":"t","port":9000}]}
            """);

        var only = Assert.Single(entries);
        Assert.Null(only.As);
        Assert.Equal(9000, only.Port);
    }

    [Fact]
    public void Trims_whitespace_from_alias_and_target()
    {
        var entries = RelayTargetsFile.Parse("""
            {"targets":[{"as":"  w11  ","target":"  192.168.32.93  ","token":"t"}]}
            """);

        Assert.Equal("w11", entries[0].As);
        Assert.Equal("192.168.32.93", entries[0].Target);
    }

    [Fact]
    public void A_blank_alias_becomes_null_so_the_default_is_derived()
    {
        var entries = RelayTargetsFile.Parse("""
            {"targets":[{"as":"   ","target":"192.168.32.93","token":"t"}]}
            """);

        Assert.Null(entries[0].As);
    }

    [Fact]
    public void An_empty_targets_array_is_valid_and_yields_nothing()
    {
        Assert.Empty(RelayTargetsFile.Parse("""{"targets":[]}"""));
    }

    [Fact]
    public void Tolerates_comments_and_trailing_commas()
    {
        var entries = RelayTargetsFile.Parse("""
            {
              // the fleet
              "targets":[
                {"as":"w11","target":"192.168.32.93","token":"t"},
              ]
            }
            """);

        Assert.Single(entries);
    }

    [Theory]
    [InlineData("not json at all")]
    [InlineData("{\"targets\":[{\"as\":\"w11\"}]}")]              // no target, no token
    [InlineData("{\"targets\":[{\"target\":\"h\"}]}")]            // token missing
    [InlineData("{\"targets\":[{\"token\":\"t\"}]}")]             // target missing
    [InlineData("{\"targets\":[{\"target\":\"\",\"token\":\"t\"}]}")] // target blank
    [InlineData("{}")]                                            // no targets key
    public void Refuses_a_malformed_file_with_a_relay_error(string json)
    {
        Assert.Throws<RelayException>(() => RelayTargetsFile.Parse(json));
    }

    [Fact]
    public void Load_returns_null_when_the_file_is_absent()
    {
        var missing = Path.Combine(Path.GetTempPath(), $"windiag-targets-{Guid.NewGuid():N}.json");

        Assert.Null(RelayTargetsFile.Load(missing));
    }

    [Fact]
    public void Load_reads_and_parses_an_existing_file()
    {
        var path = Path.Combine(Path.GetTempPath(), $"windiag-targets-{Guid.NewGuid():N}.json");
        File.WriteAllText(path, """{"targets":[{"as":"w11","target":"192.168.32.93","token":"t"}]}""");
        try
        {
            var entries = RelayTargetsFile.Load(path);

            Assert.NotNull(entries);
            Assert.Equal("w11", entries![0].As);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Upsert_creates_the_file_when_it_does_not_exist()
    {
        var path = Path.Combine(Path.GetTempPath(), $"windiag-targets-{Guid.NewGuid():N}.json");
        try
        {
            RelayTargetsFile.Upsert(path, new RelayTargetEntry("srv1", "http://192.168.36.46:4024", "secret", null));

            var entries = RelayTargetsFile.Load(path);
            var only = Assert.Single(entries!);
            Assert.Equal("srv1", only.As);
            Assert.Equal("http://192.168.36.46:4024", only.Target);
            Assert.Equal("secret", only.Token);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Upsert_appends_a_new_target_and_keeps_the_others()
    {
        var path = Path.Combine(Path.GetTempPath(), $"windiag-targets-{Guid.NewGuid():N}.json");
        File.WriteAllText(path, """{"targets":[{"as":"w11","target":"192.168.32.93","token":"t"}]}""");
        try
        {
            RelayTargetsFile.Upsert(path, new RelayTargetEntry("srv1", "192.168.36.46", "secret", null));

            var entries = RelayTargetsFile.Load(path)!;
            Assert.Equal(2, entries.Count);
            Assert.Contains(entries, e => e.As == "w11");
            Assert.Contains(entries, e => e.As == "srv1" && e.Token == "secret");
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Upsert_replaces_an_existing_alias_case_insensitively_a_repoint()
    {
        var path = Path.Combine(Path.GetTempPath(), $"windiag-targets-{Guid.NewGuid():N}.json");
        File.WriteAllText(path, """{"targets":[{"as":"w11","target":"10.0.0.1","token":"old"}]}""");
        try
        {
            RelayTargetsFile.Upsert(path, new RelayTargetEntry("W11", "10.0.0.2", "new", null));

            var only = Assert.Single(RelayTargetsFile.Load(path)!);
            Assert.Equal("10.0.0.2", only.Target);
            Assert.Equal("new", only.Token);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Upsert_refuses_to_overwrite_a_malformed_file()
    {
        var path = Path.Combine(Path.GetTempPath(), $"windiag-targets-{Guid.NewGuid():N}.json");
        File.WriteAllText(path, "{ this is not json");
        try
        {
            Assert.Throws<RelayException>(() =>
                RelayTargetsFile.Upsert(path, new RelayTargetEntry("srv1", "192.168.36.46", "secret", null)));

            // the broken file is left untouched, not replaced with a half-file
            Assert.Equal("{ this is not json", File.ReadAllText(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Upsert_requires_an_alias()
    {
        var path = Path.Combine(Path.GetTempPath(), $"windiag-targets-{Guid.NewGuid():N}.json");

        Assert.ThrowsAny<ArgumentException>(() =>
            RelayTargetsFile.Upsert(path, new RelayTargetEntry(null, "192.168.36.46", "secret", null)));
    }

    /// <summary>
    /// A relay killed mid-write (they die with their session) leaves a truncated file. Before the atomic
    /// write this destroyed every target's token AND wedged persistence permanently: the empty file
    /// failed to parse, so every later connect refused to touch a "malformed" file with nothing left in
    /// it to fix.
    /// </summary>
    [Fact]
    public void An_empty_file_is_healed_rather_than_treated_as_malformed()
    {
        var path = Path.Combine(Path.GetTempPath(), $"windiag-targets-{Guid.NewGuid():N}.json");
        File.WriteAllText(path, string.Empty);
        try
        {
            Assert.Null(RelayTargetsFile.Load(path));   // not an exception

            // and persistence still works, rather than being wedged forever
            RelayTargetsFile.Upsert(path, new RelayTargetEntry("w11", "192.168.32.93", "t", null));

            Assert.Equal("w11", Assert.Single(RelayTargetsFile.Load(path)!).As);
        }
        finally
        {
            Delete(path);
        }
    }

    [Fact]
    public void A_write_leaves_a_backup_that_a_later_corruption_is_recovered_from()
    {
        var path = Path.Combine(Path.GetTempPath(), $"windiag-targets-{Guid.NewGuid():N}.json");
        try
        {
            RelayTargetsFile.Upsert(path, new RelayTargetEntry("w11", "192.168.32.93", "first", null));
            RelayTargetsFile.Upsert(path, new RelayTargetEntry("w10", "192.168.32.76", "second", null));

            Assert.True(File.Exists(path + ".bak"), "an atomic write should keep the previous contents");

            // Something corrupts the live file; the last good copy still answers.
            File.WriteAllText(path, "{ not json at all");

            var recovered = RelayTargetsFile.Load(path);

            Assert.NotNull(recovered);
            Assert.Contains(recovered!, e => e.As == "w11");
        }
        finally
        {
            Delete(path);
        }
    }

    [Fact]
    public void Concurrent_upserts_from_many_writers_lose_no_target()
    {
        // Every Claude Code session runs its own relay against this one file, so connect races connect.
        // Unlocked, the read-modify-write silently dropped whichever entry lost the race.
        var path = Path.Combine(Path.GetTempPath(), $"windiag-targets-{Guid.NewGuid():N}.json");
        const int writers = 12;
        try
        {
            Parallel.For(0, writers, i =>
                RelayTargetsFile.Upsert(path, new RelayTargetEntry($"vm{i}", $"10.0.0.{i}", $"token{i}", null)));

            var entries = RelayTargetsFile.Load(path);

            Assert.NotNull(entries);
            Assert.Equal(writers, entries!.Count);
            for (var i = 0; i < writers; i++)
            {
                Assert.Contains(entries, e => e.As == $"vm{i}" && e.Token == $"token{i}");
            }
        }
        finally
        {
            Delete(path);
        }
    }

    [Fact]
    public void An_entry_written_without_an_alias_is_repointed_not_duplicated()
    {
        // It still occupies the alias derived from its address, so matching the raw field would append a
        // twin that races the original on every launch.
        var path = Path.Combine(Path.GetTempPath(), $"windiag-targets-{Guid.NewGuid():N}.json");
        File.WriteAllText(path, """{"targets":[{"target":"192.168.32.93","token":"old"}]}""");
        try
        {
            RelayTargetsFile.Upsert(path, new RelayTargetEntry("192-168-32-93", "192.168.32.93", "new", null));

            var only = Assert.Single(RelayTargetsFile.Load(path)!);
            Assert.Equal("new", only.Token);
        }
        finally
        {
            Delete(path);
        }
    }

    [Theory]
    [InlineData(null, "192.168.32.93", null, "192-168-32-93")]
    [InlineData("w11", "192.168.32.93", null, "w11")]
    [InlineData(null, "192.168.32.93", 4025, "192-168-32-93-4025")]   // a second server on the same host
    public void Effective_alias_is_the_declared_one_or_the_one_derived_from_the_address(
        string? declared, string target, int? port, string expected)
    {
        Assert.Equal(expected, RelayTargetsFile.EffectiveAlias(new RelayTargetEntry(declared, target, "t", port)));
    }

    [Fact]
    public void The_file_is_restricted_to_the_current_user_because_it_stores_tokens_in_clear()
    {
        // Left inherited, a file under the profile is readable by SYSTEM and every local administrator --
        // and on these targets a bearer token is command execution at the server's privilege level.
        // Asserted after a SECOND write on purpose: File.Replace keeps the destination's ACL, so hardening
        // only the temporary file passes on the first write and silently does nothing thereafter.
        var path = Path.Combine(Path.GetTempPath(), $"windiag-targets-{Guid.NewGuid():N}.json");
        try
        {
            RelayTargetsFile.Upsert(path, new RelayTargetEntry("w11", "192.168.32.93", "t", null));
            RelayTargetsFile.Upsert(path, new RelayTargetEntry("w10", "192.168.32.76", "t", null));

            foreach (var file in new[] { path, path + ".bak" })
            {
                var security = new FileInfo(file).GetAccessControl();

                Assert.True(
                    security.AreAccessRulesProtected,
                    $"{file} still inherits permissions from its directory");

                var identities = security.GetAccessRules(true, true, typeof(NTAccount))
                    .Cast<FileSystemAccessRule>()
                    .Select(r => r.IdentityReference.Value)
                    .ToList();

                Assert.Equal(WindowsIdentity.GetCurrent().Name, Assert.Single(identities));
            }
        }
        finally
        {
            Delete(path);
        }
    }

    private static void Delete(string path)
    {
        foreach (var candidate in new[] { path, path + ".bak", path + ".tmp" })
        {
            try { File.Delete(candidate); } catch (IOException) { /* best effort */ }
        }
    }
}
