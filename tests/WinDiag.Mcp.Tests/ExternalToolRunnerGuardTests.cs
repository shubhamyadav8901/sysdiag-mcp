using WinDiag.Mcp.Diagnostics.External;

namespace WinDiag.Mcp.Tests;

/// <summary>
/// The flag-injection guard. This is the security-critical test in the suite.
/// </summary>
/// <remarks>
/// Passing arguments as a vector stops shell injection but not flag injection: the target binary's
/// own parser reads a leading '-' or '/' as a switch. handle.exe's <c>-c</c> closes a handle and its
/// documentation warns this can destabilise the machine, so a caller-supplied "-c" reaching the
/// command line is a real defect, not a theoretical one.
/// </remarks>
public sealed class ExternalToolRunnerGuardTests
{
    [Theory]
    [InlineData("-c")]                  // handle.exe: close handle. Destructive.
    [InlineData("/c")]                  // Windows accepts '/' switches too.
    [InlineData("-accepteula")]
    [InlineData("--anything")]
    [InlineData("")]
    [InlineData("   ")]
    public void Refuses_caller_values_that_would_be_read_as_switches(string value)
    {
        var arguments = new[] { ToolArgument.Flag("-v"), ToolArgument.Caller(value) };

        var ex = Assert.Throws<UnsafeArgumentException>(
            () => ExternalToolRunner.BuildArgumentVector(arguments));

        Assert.Equal(value, ex.Value);
    }

    [Fact]
    public void Refuses_caller_values_containing_control_characters()
    {
        var arguments = new[] { ToolArgument.Caller("C:\\temp\\file\r\n.txt") };

        Assert.Throws<UnsafeArgumentException>(() => ExternalToolRunner.BuildArgumentVector(arguments));
    }

    [Fact]
    public void Allows_server_authored_flags_because_the_server_chose_them()
    {
        var arguments = new[] { ToolArgument.Flag("-u"), ToolArgument.Flag("-v") };

        var argv = ExternalToolRunner.BuildArgumentVector(arguments);

        Assert.Contains("-u", argv);
        Assert.Contains("-v", argv);
    }

    [Fact]
    public void Allows_ordinary_caller_values()
    {
        var arguments = new[] { ToolArgument.Caller(@"C:\Windows\Fonts\arial.ttf") };

        var argv = ExternalToolRunner.BuildArgumentVector(arguments);

        Assert.Contains(@"C:\Windows\Fonts\arial.ttf", argv);
    }

    [Fact]
    public void Always_prepends_accepteula_and_nobanner()
    {
        // -nobanner is not cosmetic: without it the banner becomes the first CSV row and the parser
        // sees garbage. -accepteula prevents a first-run dialog that would hang the call forever.
        var argv = ExternalToolRunner.BuildArgumentVector([ToolArgument.Flag("-v")]);

        Assert.Equal("-accepteula", argv[0]);
        Assert.Equal("-nobanner", argv[1]);
    }

    [Fact]
    public void Preserves_caller_argument_order_after_the_fixed_prefix()
    {
        var argv = ExternalToolRunner.BuildArgumentVector(
        [
            ToolArgument.Flag("-u"),
            ToolArgument.Flag("-v"),
            ToolArgument.Caller("Fonts")
        ]);

        Assert.Equal(["-accepteula", "-nobanner", "-u", "-v", "Fonts"], argv);
    }
}
