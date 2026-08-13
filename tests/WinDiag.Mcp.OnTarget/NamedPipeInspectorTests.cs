using System.IO.Pipes;
using WinDiag.Mcp.Configuration;
using WinDiag.Mcp.Diagnostics.Pipes;
using Xunit.Abstractions;

namespace WinDiag.Mcp.OnTarget;

/// <summary>
/// Validates the named-pipe interop against pipes this test creates itself.
/// </summary>
/// <remarks>
/// <para>The inspector reads <c>FILE_DIRECTORY_INFORMATION</c> at hard-coded field offsets and relies on
/// the pipe device reusing <c>EndOfFile</c> as the active instance count and <c>AllocationSize</c> as
/// the maximum. Nothing about that is checkable by the compiler: wrong offsets produce plausible
/// numbers rather than a crash.</para>
/// <para>Creating a pipe with a known instance limit and reading it back is therefore the only way to
/// know the offsets are right, and it is self-verifying -- the expected values come from the test's
/// own arguments.</para>
/// </remarks>
[Trait("Category", "OnTarget")]
public sealed class NamedPipeInspectorTests(ITestOutputHelper output)
{
    private static INamedPipeInspector Inspector() => new NamedPipeInspector(new WinDiagOptions());

    [Fact]
    public void Reads_back_the_instance_limit_a_pipe_was_created_with()
    {
        var name = $"windiag-pipe-{Guid.NewGuid():N}";
        using var server = new NamedPipeServerStream(name, PipeDirection.InOut, maxNumberOfServerInstances: 3);

        var pipe = Assert.Single(Inspector().List(name, CancellationToken.None).Pipes);

        output.WriteLine($"{pipe.Name}: {pipe.ActiveInstances} of {pipe.MaximumInstances}");

        Assert.Equal(name, pipe.Name);
        Assert.Equal(1, pipe.ActiveInstances);
        Assert.Equal(3, pipe.MaximumInstances);
        Assert.False(pipe.Exhausted);
        Assert.False(pipe.Unlimited);
    }

    [Fact]
    public void Counts_every_instance_of_the_same_pipe()
    {
        var name = $"windiag-pipe-{Guid.NewGuid():N}";
        using var first = new NamedPipeServerStream(name, PipeDirection.InOut, maxNumberOfServerInstances: 4);
        using var second = new NamedPipeServerStream(name, PipeDirection.InOut, maxNumberOfServerInstances: 4);

        var pipe = Assert.Single(Inspector().List(name, CancellationToken.None).Pipes);

        Assert.Equal(2, pipe.ActiveInstances);
        Assert.Equal(4, pipe.MaximumInstances);
    }

    [Fact]
    public void Detects_a_pipe_that_has_used_its_whole_instance_budget()
    {
        // The condition the tool exists to find: the server is healthy, but no client can connect.
        var name = $"windiag-pipe-{Guid.NewGuid():N}";
        using var only = new NamedPipeServerStream(name, PipeDirection.InOut, maxNumberOfServerInstances: 1);

        var pipe = Assert.Single(Inspector().List(name, CancellationToken.None).Pipes);

        Assert.True(pipe.Exhausted);
        Assert.Equal(1, pipe.ActiveInstances);
        Assert.Equal(1, pipe.MaximumInstances);
    }

    [Fact]
    public void Reports_an_unlimited_pipe_as_unlimited_rather_than_as_a_huge_number()
    {
        var name = $"windiag-pipe-{Guid.NewGuid():N}";
        using var server = new NamedPipeServerStream(
            name, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances);

        var pipe = Assert.Single(Inspector().List(name, CancellationToken.None).Pipes);

        output.WriteLine($"unlimited pipe reported max = {pipe.MaximumInstances}");

        Assert.True(pipe.Unlimited);
        Assert.False(pipe.Exhausted);
    }

    [Fact]
    public void Finds_the_well_known_system_pipes()
    {
        // Sanity check that enumeration reaches beyond the test's own pipes: every Windows machine has
        // these, so an empty result here means the walk is broken rather than the machine being quiet.
        var pipes = Inspector().List(null, CancellationToken.None);

        output.WriteLine($"enumerated {pipes.TotalMatched} pipes");

        Assert.True(pipes.TotalMatched > 10, $"only {pipes.TotalMatched} pipes enumerated");
    }
}
