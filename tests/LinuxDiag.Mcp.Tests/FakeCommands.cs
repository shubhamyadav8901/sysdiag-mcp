using LinuxDiag.Mcp.Linux.External;

namespace LinuxDiag.Mcp.Tests;

/// <summary>A hand-written runner fake: answers by program and arguments, and records every call.</summary>
internal sealed class FakeCommands(Func<string, IReadOnlyList<string>, ExternalResult> answer) : IExternalCommand
{
    public List<(string Program, IReadOnlyList<string> Arguments)> Calls { get; } = [];

    public Task<ExternalResult> RunAsync(
        string program, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken)
    {
        Calls.Add((program, arguments));
        return Task.FromResult(answer(program, arguments));
    }

    public static ExternalResult Ok(string output) => new(0, output, string.Empty);
}
