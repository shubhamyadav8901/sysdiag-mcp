using Diag.Mcp.Server.Tests;
using MacDiag.Mcp.Tools;

namespace MacDiag.Mcp.Tests;

/// <summary>Every MacDiag summary escapes text another account controls; see <see cref="RenderSafetyGuard"/>.</summary>
/// <remarks>run_command is exempt: its output is the caller's own command's, returned as it was written.</remarks>
public sealed class RenderSafetyTests
{
    private const string ToolsNamespace = "MacDiag.Mcp.Tools";

    public static TheoryData<string> Renderers() =>
        RenderSafetyGuard.Renderers(typeof(ServerBuilder).Assembly, ToolsNamespace, typeof(CommandTools));

    [Theory]
    [MemberData(nameof(Renderers))]
    public void A_summary_never_carries_a_forged_line_or_a_terminal_control(string renderer) =>
        RenderSafetyGuard.AssertSafe(typeof(ServerBuilder).Assembly, ToolsNamespace, renderer, typeof(CommandTools));
}
