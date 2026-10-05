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

    /// <summary>plutil -extract Label raw -o - over one or more plists, as macOS 26's plutil answers it.</summary>
    /// <remarks>Measured: a line on stdout per plist with a Label, an error on stderr per plist without one, which then
    /// leaves no line of its own, and exit 1 if any had none.</remarks>
    public static ExternalResult PlutilLabels(IReadOnlyList<string> arguments, Func<string, string?> labelOf)
    {
        var output = new System.Text.StringBuilder();
        var error = new System.Text.StringBuilder();
        foreach (var plist in arguments.Skip(5))
        {
            _ = labelOf(plist) is { } label
                ? output.Append(label).Append('\n')
                : error.Append(plist).Append(": Could not extract value, error: No value at that key path or invalid key path: Label\n");
        }

        return new ExternalResult(error.Length == 0 ? 0 : 1, output.ToString(), error.ToString());
    }

    /// <summary>What the real runner throws when a program outlives its timeout.</summary>
    public static ExternalResult Hang(string program) => throw new ExternalCommandException($"{program} did not finish within its timeout and was killed.", timedOut: true);
}
