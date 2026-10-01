namespace MacDiag.Mcp.Tests;

/// <summary>A hand-written runner fake: answers by program, and records every call.</summary>
internal sealed class FakeCommands(Func<string, IReadOnlyList<string>, ExternalResult> answer) : IExternalCommand
{
    public List<(string Program, IReadOnlyList<string> Arguments)> Calls { get; } = [];

    /// <summary>The timeout each call was given, in call order.</summary>
    public List<TimeSpan> Timeouts { get; } = [];

    public Task<ExternalResult> RunAsync(
        string program, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken)
    {
        Calls.Add((program, arguments));
        Timeouts.Add(timeout);
        return Task.FromResult(answer(program, arguments));
    }

    public async Task<ExternalLinesResult> RunLinesAsync(
        string program, IReadOnlyList<string> arguments, TimeSpan timeout, Func<string, bool> onLine, CancellationToken cancellationToken)
    {
        var result = await RunAsync(program, arguments, timeout, cancellationToken).ConfigureAwait(false);
        foreach (var line in result.StandardOutput.Split('\n'))
        {
            if (!onLine(line))
            {
                return new ExternalLinesResult(-1, result.StandardError, StoppedEarly: true);
            }
        }

        return new ExternalLinesResult(result.ExitCode, result.StandardError, StoppedEarly: false);
    }

    public static ExternalResult Ok(string output) => new(0, output, string.Empty);

    /// <summary>What the real runner throws when a program outlives its timeout.</summary>
    public static ExternalResult Hang(string program) => throw new ExternalCommandException($"{program} did not finish within its timeout and was killed.", timedOut: true);
}
