using System.Globalization;
using System.Net;
using Microsoft.Extensions.Logging;

namespace Diag.Mcp.Server;

/// <summary>Records requests the bearer gate turned away: who, at a rate no peer can turn into a flood.</summary>
/// <remarks>
/// <para>Rejections come from anyone who can reach the port, before any token is checked, so a line per request
/// would hand them the log: MacDiag's rolls at 10 MB with one backup, and journald's per-service rate limit then
/// drops the server's own messages. Silence is no better -- an operator looking into a brute-force attempt needs the
/// address. So the first rejection from an address in each minute is a Warning naming it, at most
/// <see cref="AddressesPerWindow"/> addresses a minute; the rest are only counted.</para>
/// <para>The counts of a minute are written when the next rejection after it arrives, not by a timer: a timer would
/// wake every minute of a quiet server's life. If none follows, they are never written; the first lines already
/// named who it was.</para>
/// <para>Memory is bounded by the same cap: an address past it is a count, never an entry, so a peer cycling
/// through a subnet's addresses cannot grow the table either.</para>
/// </remarks>
internal sealed class RejectedRequestLog(ILogger logger, TimeProvider time)
{
    internal const int AddressesPerWindow = 10;

    internal static readonly TimeSpan Window = TimeSpan.FromMinutes(1);

    private readonly Lock _lock = new();
    private readonly Dictionary<string, int> _counts = new(StringComparer.Ordinal);
    private DateTimeOffset _windowStart = DateTimeOffset.MinValue;
    private long _unnamed;

    public void Record(IPAddress? peer)
    {
        var address = peer is null ? "an unknown address" : (peer.IsIPv4MappedToIPv6 ? peer.MapToIPv4() : peer).ToString();
        string? summary = null;
        var first = false;
        lock (_lock)
        {
            var now = time.GetUtcNow();
            if (now - _windowStart >= Window)
            {
                summary = Summary();
                _windowStart = now;
                _counts.Clear();
                _unnamed = 0;
            }

            if (_counts.TryGetValue(address, out var count))
            {
                _counts[address] = count + 1;
            }
            else if (_counts.Count < AddressesPerWindow)
            {
                _counts[address] = 1;
                first = true;
            }
            else
            {
                _unnamed++;
            }
        }

        // Written outside the lock: a slow sink must not hold up every other rejection.
        if (summary is not null)
        {
            logger.LogWarning("{Summary}", summary);
        }

        if (first)
        {
            logger.LogWarning(
                "Rejected a request without a valid bearer token from {Address}. Further rejections from it in the next {Seconds:0} s are counted, not logged.",
                address, Window.TotalSeconds);
        }
    }

    /// <summary>What the window now ending only counted, or null when every rejection in it was already written.</summary>
    private string? Summary()
    {
        var repeats = _counts.Where(c => c.Value > 1).OrderByDescending(c => c.Value).ToList();
        var more = repeats.Sum(c => (long)c.Value - 1) + _unnamed;
        if (more == 0)
        {
            return null;
        }

        var parts = repeats.Select(c => string.Create(CultureInfo.InvariantCulture, $"{c.Key} x{c.Value - 1}")).ToList();
        if (_unnamed > 0)
        {
            parts.Add(string.Create(CultureInfo.InvariantCulture, $"{_unnamed:N0} from addresses not named, past the first {AddressesPerWindow}"));
        }

        return string.Create(CultureInfo.InvariantCulture,
            $"{more:N0} more requests without a valid bearer token were rejected in the minute from {_windowStart:u}: {string.Join("; ", parts)}.");
    }
}
