using System.Collections.Concurrent;
using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Diag.Mcp.Server.Tests;

public sealed class RejectedRequestLogTests
{
    /// <summary>A clock the test moves by hand.</summary>
    private sealed class ManualClock : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = new(2026, 10, 6, 12, 0, 0, TimeSpan.Zero);

        public override DateTimeOffset GetUtcNow() => Now;
    }

    /// <summary>Every line any logger wrote, with its level and category.</summary>
    private sealed class CapturingProvider : ILoggerProvider
    {
        public ConcurrentQueue<(LogLevel Level, string Category, string Message)> Lines { get; } = new();

        public ILogger CreateLogger(string categoryName) => new Logger(this, categoryName);

        public void Dispose()
        {
        }

        private sealed class Logger(CapturingProvider owner, string category) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state)
                where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
                owner.Lines.Enqueue((logLevel, category, formatter(state, exception)));
        }
    }

    private static (RejectedRequestLog Log, CapturingProvider Lines, ManualClock Clock) Make()
    {
        var lines = new CapturingProvider();
        var clock = new ManualClock();
        return (new RejectedRequestLog(lines.CreateLogger("gate"), clock), lines, clock);
    }

    [Fact]
    public void Many_rejections_from_one_address_write_one_warning_that_names_it()
    {
        var (log, lines, _) = Make();

        for (var i = 0; i < 1000; i++)
        {
            log.Record(IPAddress.Parse("10.0.0.5"));
        }

        var line = Assert.Single(lines.Lines);
        Assert.Equal(LogLevel.Warning, line.Level);
        Assert.Contains("10.0.0.5", line.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void The_rejections_that_were_only_counted_are_summed_up_once_the_minute_is_over()
    {
        var (log, lines, clock) = Make();
        for (var i = 0; i < 40; i++)
        {
            log.Record(IPAddress.Parse("10.0.0.5"));
        }

        clock.Now += TimeSpan.FromSeconds(61);
        log.Record(IPAddress.Parse("10.0.0.5"));

        Assert.Equal(3, lines.Lines.Count);
        var summary = lines.Lines.ElementAt(1);
        Assert.Equal(LogLevel.Warning, summary.Level);
        Assert.Contains("39 more", summary.Message, StringComparison.Ordinal);
        Assert.Contains("10.0.0.5 x39", summary.Message, StringComparison.Ordinal);
        Assert.Contains("10.0.0.5", lines.Lines.ElementAt(2).Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_flood_from_many_addresses_names_only_the_first_few_and_counts_the_rest()
    {
        // Every address costs a line, so a peer with a whole subnet would otherwise roll the log just the same.
        var (log, lines, clock) = Make();
        for (var i = 1; i <= 250; i++)
        {
            log.Record(IPAddress.Parse($"10.0.{i / 200}.{i % 200}"));
        }

        Assert.Equal(RejectedRequestLog.AddressesPerWindow, lines.Lines.Count);

        clock.Now += TimeSpan.FromMinutes(2);
        log.Record(IPAddress.Loopback);
        Assert.Contains(lines.Lines, l => l.Message.Contains("240 from addresses not named", StringComparison.Ordinal));
    }

    [Fact]
    public void An_ipv4_peer_on_a_dual_stack_socket_is_named_as_ipv4()
    {
        var (log, lines, _) = Make();

        log.Record(IPAddress.Parse("10.0.0.5").MapToIPv6());
        log.Record(null);

        Assert.Contains("10.0.0.5", lines.Lines.First().Message, StringComparison.Ordinal);
        Assert.DoesNotContain("::ffff:", lines.Lines.First().Message, StringComparison.Ordinal);
        Assert.Contains("an unknown address", lines.Lines.Last().Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Requests_without_the_token_do_not_add_a_log_line_each_on_the_real_host()
    {
        // Before: ASP.NET Core wrote "Request starting" and "Request finished ... 401" at Information for every one,
        // so any peer could roll MacDiag's 10 MB log, or exhaust journald's rate limit, with no token at all, and no line
        // said who it was.
        var lines = new CapturingProvider();
        await using var app = DiagServerHost.BuildHttp(
            new HttpHostSettings("http://127.0.0.1:0", "t", "[test]", "TEST_TOKEN", "t"),
            builder =>
            {
                builder.Logging.ClearProviders();
                builder.Logging.AddProvider(lines);
                builder.Services.AddMcpServer().WithHttpTransport();
            });
        await app.StartAsync();
        var address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.First();
        using var http = new HttpClient();

        async Task Reject(int times)
        {
            for (var i = 0; i < times; i++)
            {
                using var response = await http.PostAsync(new Uri(address), new StringContent("{}"));
                Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            }
        }

        await Reject(5);
        var afterFew = lines.Lines.Count;
        await Reject(100);

        Assert.Equal(afterFew, lines.Lines.Count);
        var warning = Assert.Single(lines.Lines, l => l.Category == typeof(BearerTokenGate).FullName);
        Assert.Equal(LogLevel.Warning, warning.Level);
        Assert.Contains("127.0.0.1", warning.Message, StringComparison.Ordinal);
    }
}
