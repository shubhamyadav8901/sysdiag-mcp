using Diag.Mcp.Server.Tests;
using WinDiag.Mcp.Tools;

namespace WinDiag.Mcp.Tests;

/// <summary>Every WinDiag summary escapes text another account controls; see <see cref="RenderSafetyGuard"/>.</summary>
/// <remarks>
/// Before this, nothing in WinDiag escaped anything: a process started with a newline in its command line, or
/// an HKCU REG_SZ holding one, wrote a line into process_list's or registry_read's summary that an agent read
/// as the server's own words. run_command is exempt -- its output is the caller's own command's.
/// </remarks>
public sealed class RenderSafetyTests
{
    private const string ToolsNamespace = "WinDiag.Mcp.Tools";

    public static TheoryData<string> Renderers() =>
        RenderSafetyGuard.Renderers(typeof(ServerBuilder).Assembly, ToolsNamespace, typeof(CommandTools));

    [Theory]
    [MemberData(nameof(Renderers))]
    public void A_summary_never_carries_a_forged_line_or_a_terminal_control(string renderer) =>
        RenderSafetyGuard.AssertSafe(typeof(ServerBuilder).Assembly, ToolsNamespace, renderer, typeof(CommandTools));
}
