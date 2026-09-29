using LinuxDiag.Mcp.Diagnostics.Capabilities;

namespace LinuxDiag.Mcp.Tests;

public sealed class GuardTests
{
    private static readonly System.Reflection.Assembly Server = typeof(ServerBuilder).Assembly;
    private static readonly System.Reflection.Assembly Kit = typeof(DiagServerKit).Assembly;

    [Fact]
    public void Every_exception_this_server_defines_is_marked_for_the_caller() =>
        DiagnosticExceptionGuard.AssertMarked(Server);

    [Fact]
    public void The_capability_table_covers_every_declared_tool_and_invents_none() =>
        CapabilityTableGuard.AssertTableMatchesDeclaredTools(new LinuxCapabilityRequirements().Requirements, Server, Kit);

    [Fact]
    public void Every_result_model_writes_every_property()
    {
        var models = OutputSerializationGuard.ResultModels([Server, Kit], "LinuxDiag.Mcp.Tools", "Diag.Mcp.Server");

        // A sweep that finds nothing passes forever; the kit alone contributes several result records.
        Assert.True(models.Count >= 5, $"Expected result models to be found; got {models.Count}.");
        foreach (var model in models)
        {
            OutputSerializationGuard.AssertAllPropertiesWritten(model);
        }
    }
}
