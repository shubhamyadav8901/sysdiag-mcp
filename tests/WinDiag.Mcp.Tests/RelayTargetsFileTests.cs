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
}
