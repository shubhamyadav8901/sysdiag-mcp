using MacDiag.Mcp.Hosting;

namespace MacDiag.Mcp.Tests;

public sealed class CommandLineTests
{
    private static string Refusal(params string[] args) => Assert.Throws<ConfigurationException>(() => MacCommandLine.Check(args)).Message;

    [Theory]
    [InlineData]
    [InlineData("--http", "http://0.0.0.0:4025")]
    [InlineData("--http")]
    [InlineData("--HTTP", "http://0.0.0.0:4025")]                                // HttpBind reads it in any case
    [InlineData("--env-file", "/etc/macdiag/com.sysdiag.macdiag.env")]            // what the launchd job runs
    [InlineData("--install-service", "--http", "http://0.0.0.0:4025", "--token-stdin", "--allow-self-update", "--allow-command-execution")]
    [InlineData("--install-service", "--http", "http://0.0.0.0:4025", "--read-only", "--label", "com.x", "--artifacts", "/var/db/x")]
    [InlineData("--install-service", "--http", "http://0.0.0.0:4025", "--token", "t0k", "--allow-arbitrary-write", "--allow-arbitrary-read")]
    [InlineData("--uninstall-service", "--purge", "--label", "com.x")]
    [InlineData("--service-status", "--label", "com.x")]
    public void Every_documented_command_line_is_accepted(params string[] args)
    {
        MacCommandLine.Check(args);
    }

    [Theory]
    [InlineData("--readonly")]
    [InlineData("--read_only")]
    [InlineData("--allow-arbitary-read")]
    public void A_misspelled_grant_at_install_is_refused_rather_than_installing_a_server_without_it(string typo)
    {
        // Before: dropped without a word, so "--readonly" installed a writable root daemon whose token could kill
        // processes and stop services.
        var message = Refusal("--install-service", "--http", "http://0.0.0.0:4025", typo);

        Assert.Contains($"'{typo}'", message, StringComparison.Ordinal);
        Assert.Contains("Nothing was installed", message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_grant_spelled_with_the_wrong_punctuation_is_answered_with_the_right_spelling()
    {
        Assert.Contains("--read-only", Refusal("--install-service", "--http", "http://0.0.0.0:4025", "--readonly"), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("--read-only", "MACDIAG_READ_ONLY=1")]
    [InlineData("--allow-command-execution", "MACDIAG_ALLOW_COMMAND_EXECUTION=1")]
    [InlineData("--token", "MACDIAG_TOKEN")]
    public void An_install_option_on_a_server_started_by_hand_is_refused_and_pointed_at_its_variable(string option, string variable)
    {
        // Before: "MacDiag.Mcp --http ... --read-only", by analogy with the install flags, served a writable server.
        var message = Refusal("--http", "http://127.0.0.1:4025", option, "x");

        Assert.Contains($"'{option}'", message, StringComparison.Ordinal);
        Assert.Contains(variable, message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("--install-service", "--http", "http://0.0.0.0:4025", "--purge")]
    [InlineData("--uninstall-service", "--read-only")]
    [InlineData("--service-status", "--http", "http://0.0.0.0:4025")]
    [InlineData("--install-service", "--http", "http://0.0.0.0:4025", "--env-file", "/x")]
    [InlineData("--http", "http://0.0.0.0:4025", "stray")]
    public void An_option_another_mode_reads_or_a_stray_word_is_refused(params string[] args)
    {
        Refusal(args);
    }

    [Theory]
    [InlineData("--install-service", "--uninstall-service")]
    [InlineData("--service-status", "--install-service", "--http", "http://0.0.0.0:4025")]
    public void Two_service_actions_at_once_are_refused(params string[] args)
    {
        // Program picks one by its own order; the other would be dropped as silently as a typo.
        Assert.Contains("only one of", Refusal(args), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("--env-file")]
    [InlineData("--install-service", "--http", "http://0.0.0.0:4025", "--token")]
    [InlineData("--install-service", "--http", "http://0.0.0.0:4025", "--token", "--read-only")]
    [InlineData("--install-service", "--http", "http://0.0.0.0:4025", "--label", "a", "--label", "b")]
    public void An_option_without_its_value_or_given_twice_is_refused(params string[] args)
    {
        // "--token --read-only" made "--read-only" the token and installed a writable server; "--env-file" alone served
        // without the settings file; and two --labels were read as the first by one parser and the last by another.
        Refusal(args);
    }
}
