using WinDiag.Mcp.Diagnostics.Control;
using WinDiag.Mcp.Diagnostics.External;
using WinDiag.Mcp.Hosting;

namespace WinDiag.Mcp.Tests;

/// <summary>
/// The refusal messages are the product; this is what gets them to the caller.
/// </summary>
/// <remarks>
/// Without translation every failure arrives as "An error occurred invoking 'x'." — which is what the
/// real server returned for a refused service_control until this existed. A caller who cannot read why
/// they were refused simply tries again.
/// </remarks>
public sealed class ToolErrorTranslationTests
{
    [Fact]
    public void Reports_the_refusal_verbatim()
    {
        var ex = new ProcessControlException(
            "PID 1234 is 'svchost', not 'notepad'. Nothing has been done.");

        Assert.Equal(ex.Message, ToolErrorTranslation.Describe(ex));
    }

    [Fact]
    public void Includes_the_cause_because_it_usually_carries_the_actionable_part()
    {
        // "Could not open PID 900" is the wrapper; "Access is denied" is what the caller needs.
        var inner = new UnauthorizedAccessException("Access is denied.");
        var outer = new ServiceControlException("Could not stop 'Spooler':", inner);

        var described = ToolErrorTranslation.Describe(outer);

        Assert.Contains("Could not stop", described);
        Assert.Contains("Access is denied", described);
    }

    [Fact]
    public void Does_not_repeat_a_cause_the_wrapper_already_quoted()
    {
        // Wrapping commonly restates the inner message; printing it twice reads like a stutter.
        var inner = new InvalidOperationException("the service was not found");
        var outer = new ServiceControlException("Failed: the service was not found", inner);

        var described = ToolErrorTranslation.Describe(outer);

        Assert.Equal("Failed: the service was not found", described);
    }

    [Fact]
    public void Falls_back_to_the_type_when_there_is_no_message()
    {
        Assert.Contains("Exception", ToolErrorTranslation.Describe(new ProcessControlException(string.Empty)));
    }

    [Fact]
    public void Covers_every_diagnostic_failure_the_tools_can_raise()
    {
        // A new inspector that throws its own exception type would otherwise silently regress to the
        // generic message, which is exactly the failure this class was written to fix.
        var diagnostics = new Exception[]
        {
            new ToolNotFoundException("handle.exe"),
            new UnsafeArgumentException("-c"),
            new ProcessControlException("refused"),
            new ServiceControlException("refused"),
            new ArgumentException("bad parameter"),
            new FormatException("unexpected layout")
        };

        foreach (var ex in diagnostics)
        {
            Assert.False(string.IsNullOrWhiteSpace(ToolErrorTranslation.Describe(ex)));
        }
    }
}
