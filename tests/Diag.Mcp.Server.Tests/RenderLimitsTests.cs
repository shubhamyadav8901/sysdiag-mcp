namespace Diag.Mcp.Server.Tests;

public sealed class RenderLimitsTests
{
    [Fact]
    public void Printable_escapes_line_breaks_terminal_controls_and_direction_overrides_and_keeps_everything_else()
    {
        Assert.Equal("a\\nFORGED\\r\\t\\u001b[31m\\u202eé b", RenderLimits.Printable("a\nFORGED\r\t\u001b[31m‮é b"));
        Assert.Equal("/usr/bin/sleep 30", RenderLimits.Printable("/usr/bin/sleep 30"));
        Assert.Null(RenderLimits.Printable(null));
    }
}
