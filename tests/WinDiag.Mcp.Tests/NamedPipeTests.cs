using WinDiag.Mcp.Diagnostics.Pipes;
using WinDiag.Mcp.Tools;

namespace WinDiag.Mcp.Tests;

/// <summary>
/// What <c>named_pipes</c> concludes from instance counts and the listening probe, with a fake probe.
/// </summary>
/// <remarks>
/// The interop -- the counts themselves and a real WaitNamedPipe -- is checked against pipes the test
/// creates in <c>WinDiag.Mcp.OnTarget</c>. What is checked here is the conclusion drawn from them, which
/// is where the false positive lived: a pipe whose every instance was created was called "AT LIMIT" and
/// said to block clients, though an instance listens from the moment it is created.
/// </remarks>
public sealed class NamedPipeConclusionTests
{
    private static readonly NamedPipe Waiting = new("waiting-for-first-client", 1, 1);
    private static readonly NamedPipe Taken = new("every-instance-taken", 2, 2);
    private static readonly NamedPipe Roomy = new("room-to-grow", 1, 4);
    private static readonly NamedPipe Unlimited = new("no-limit", 3, -1);

    private static NamedPipeListResult Arrange(Func<string, bool?> probe, params NamedPipe[] pipes) =>
        NamedPipeInspector.Arrange(pipes, nameFilter: null, maxResults: 100, probe, CancellationToken.None);

    [Fact]
    public void A_pipe_with_every_instance_created_and_one_listening_is_not_busy()
    {
        // The false positive: a single-instance pipe waiting for its first client reads 1 of 1, and was
        // reported as one a client would block on. A client would have connected.
        var result = Arrange(_ => true, Waiting);

        var pipe = Assert.Single(result.Pipes);
        Assert.True(pipe.AllInstancesCreated);
        Assert.True(pipe.Listening);
        Assert.False(pipe.Busy);
    }

    [Fact]
    public void A_pipe_with_every_instance_created_and_none_listening_is_busy_and_listed_first()
    {
        var result = Arrange(name => name != Taken.Name, Roomy, Waiting, Taken);

        Assert.Equal(Taken.Name, result.Pipes[0].Name);
        Assert.True(result.Pipes[0].Busy);
        Assert.Single(result.Pipes, p => p.Busy);
    }

    [Fact]
    public void Probes_only_the_pipes_that_cannot_create_another_instance()
    {
        // A pipe below its limit, or with none, can still add an instance for the next client, so
        // asking costs a probe each across hundreds of healthy pipes for nothing.
        var probed = new System.Collections.Concurrent.ConcurrentBag<string>();

        var result = Arrange(name => { probed.Add(name); return true; }, Waiting, Roomy, Unlimited);

        Assert.Equal([Waiting.Name], probed);
        Assert.All(result.Pipes.Where(p => p.Name != Waiting.Name), p => Assert.Null(p.Listening));
        Assert.DoesNotContain(result.Pipes, p => p.Busy);
    }

    [Fact]
    public void Does_not_call_a_pipe_busy_when_the_probe_could_not_tell()
    {
        var pipe = Assert.Single(Arrange(_ => null, Taken).Pipes);

        Assert.Null(pipe.Listening);
        Assert.False(pipe.Busy);
    }

    [Fact]
    public void Says_nothing_alarming_about_a_pipe_that_is_only_fully_created()
    {
        var summary = ProcessTools.RenderPipes(Arrange(_ => true, Waiting), null);

        Assert.DoesNotContain("ATTENTION", summary);
        Assert.DoesNotContain("AT LIMIT", summary);
        Assert.DoesNotContain("BUSY", summary);
        Assert.Contains("1 of 1 instances created, one listening", summary);
    }

    [Fact]
    public void Calls_out_a_busy_pipe_and_says_what_a_client_would_see()
    {
        var summary = ProcessTools.RenderPipes(Arrange(_ => false, Taken, Roomy), null);

        Assert.StartsWith("ATTENTION: 1 pipe has every instance created and none listening", summary);
        Assert.Contains("ERROR_PIPE_BUSY", summary);
        Assert.Contains("2 of 2 instances created, none listening - BUSY", summary);
        Assert.Contains("1 of 4 instances created", summary);
    }

    [Fact]
    public void Says_so_when_it_could_not_tell_whether_a_fully_created_pipe_is_listening()
    {
        var summary = ProcessTools.RenderPipes(Arrange(_ => null, Taken), null);

        Assert.Contains("could not tell whether one is listening", summary);
        Assert.DoesNotContain("ATTENTION", summary);
    }
}
