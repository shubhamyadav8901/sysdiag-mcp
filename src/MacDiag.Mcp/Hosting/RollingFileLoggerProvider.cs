using System.Globalization;
using Microsoft.Extensions.Logging;

namespace MacDiag.Mcp.Hosting;

/// <summary>The daemon's own log under launchd: one file, rolled to a single backup past a size.</summary>
/// <remarks>
/// launchd neither rotates StandardErrorPath nor sends it anywhere searchable, so the server writes its own.
/// A write that fails is dropped, never thrown: a diagnostic channel must never break the thing it reports
/// on, and a sink that threw once took down update_self mid-run.
/// </remarks>
public sealed class RollingFileLoggerProvider(string path, long maxBytes = 10 * 1024 * 1024) : ILoggerProvider
{
    private readonly object _gate = new();

    public ILogger CreateLogger(string categoryName) => new FileLogger(this, categoryName);

    public void Dispose()
    {
    }

    private void Write(string line)
    {
        lock (_gate)
        {
            try
            {
                var file = new FileInfo(path);
                if (file.Exists && file.Length + line.Length > maxBytes)
                {
                    File.Move(path, path + ".1", overwrite: true);
                }

                using var stream = new FileStream(path, new FileStreamOptions
                {
                    Mode = FileMode.Append,
                    Access = FileAccess.Write,
                    Share = FileShare.Read,
                    UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
                });
                using var writer = new StreamWriter(stream);
                writer.Write(line);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Dropped: see the remarks.
            }
        }
    }

    private sealed class FileLogger(RollingFileLoggerProvider owner, string category) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Information;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel))
            {
                return;
            }

            var line = $"{DateTimeOffset.UtcNow.ToString("u", CultureInfo.InvariantCulture)} {logLevel} {category}: {formatter(state, exception)}" +
                       (exception is null ? string.Empty : $"\n{exception}") + "\n";
            owner.Write(line);
        }
    }
}
