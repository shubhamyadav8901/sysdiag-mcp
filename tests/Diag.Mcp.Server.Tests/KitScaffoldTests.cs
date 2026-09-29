namespace Diag.Mcp.Server.Tests;

public sealed class KitScaffoldTests
{
    [Fact]
    public void The_relay_does_not_reference_the_server_kit()
    {
        // K1: the kit carries a web server; the relay is a stdio client and must stay free of it.
        var references = typeof(DiagRelay.Mcp.RelayServer).Assembly.GetReferencedAssemblies().Select(a => a.Name);

        Assert.DoesNotContain(typeof(DiagServerKit).Assembly.GetName().Name, references);
        Assert.DoesNotContain(references, name => name!.StartsWith("Microsoft.AspNetCore", StringComparison.Ordinal));
    }
}
