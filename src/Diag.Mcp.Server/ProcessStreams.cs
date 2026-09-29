namespace Diag.Mcp.Server;

/// <summary>Draining a child process's redirected output without letting a stuck pipe hang a call.</summary>
/// <remarks>Shared by every runner that starts a child process, so the bound is the same everywhere.</remarks>
public static class ProcessStreams
{
    /// <summary>
    /// Awaits a stream drain with its own bound, so a stuck pipe cannot outlive the tool's timeout.
    /// </summary>
    /// <remarks>
    /// <see cref="StreamReader.ReadToEndAsync()"/> on a redirected pipe completes only when every write
    /// handle closes -- including any a grandchild process inherited. Killing the child normally closes
    /// them, but if a grandchild survives, an unbounded await here would hang the MCP call forever
    /// despite the timeout that was supposed to bound it. Returning what we have is strictly better
    /// than never returning.
    /// </remarks>
    public static async Task<string> DrainAsync(Task<string> readTask)
    {
        var completed = await Task.WhenAny(readTask, Task.Delay(DrainGrace)).ConfigureAwait(false);
        if (!ReferenceEquals(completed, readTask))
        {
            Observe(readTask);
            return string.Empty;
        }

        return await readTask.ConfigureAwait(false);
    }

    /// <summary>Grace period for a stream to finish draining after the process has exited or been killed.</summary>
    private static readonly TimeSpan DrainGrace = TimeSpan.FromSeconds(5);

    /// <summary>Marks an abandoned task's exception as observed so it cannot surface as unhandled.</summary>
    public static void Observe(Task task) =>
        _ = task.ContinueWith(static t => _ = t.Exception, TaskScheduler.Default);
}
