namespace MacDiag.Mcp.Mac.Parsers;

public sealed record SwVersInfo(string? Name, string? Version, string? Build);

/// <summary>sw_vers(1): "Key:\tvalue" lines; unknown keys ignored, a missing key left null.</summary>
public static class SwVers
{
    public static SwVersInfo Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        var pairs = text.Split('\n')
            .Select(line => line.Split(':', 2))
            .Where(parts => parts.Length == 2)
            .Select(parts => (Key: parts[0].Trim(), Value: parts[1].Trim()))
            .ToList();

        string? Value(string key) => pairs.Where(p => p.Key == key).Select(p => p.Value).FirstOrDefault();

        return new SwVersInfo(Value("ProductName"), Value("ProductVersion"), Value("BuildVersion"));
    }
}
