namespace Diag.Mcp.Server.Tests;

public sealed class DrainAsyncTests
{
    [Fact]
    public async Task Returns_the_output_when_the_stream_completes()
    {
        var completed = Task.FromResult("rows");

        Assert.Equal("rows", await ProcessStreams.DrainAsync(completed));
    }

    [Fact]
    public async Task Gives_up_instead_of_hanging_when_a_pipe_never_closes()
    {
        // A grandchild process that inherited the stdout handle keeps the pipe open even after the
        // child is killed, so ReadToEndAsync never completes. Before this bound existed, that hung the
        // MCP call forever -- past the timeout that was supposed to prevent exactly this.
        var neverCompletes = new TaskCompletionSource<string>();

        var drain = ProcessStreams.DrainAsync(neverCompletes.Task);
        var winner = await Task.WhenAny(drain, Task.Delay(TimeSpan.FromSeconds(30)));

        Assert.Same(drain, winner);
        Assert.Equal(string.Empty, await drain);
    }

    [Fact]
    public async Task Surfaces_a_stream_failure_rather_than_reporting_empty_output()
    {
        // A broken pipe must not masquerade as "the tool found nothing", which is what silently
        // swallowing the fault and returning string.Empty would look like to the caller.
        var faulted = Task.FromException<string>(new IOException("pipe broke"));

        await Assert.ThrowsAsync<IOException>(() => ProcessStreams.DrainAsync(faulted));
    }
}
