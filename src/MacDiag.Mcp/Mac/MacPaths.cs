namespace MacDiag.Mcp.Mac;

/// <summary>macOS path arithmetic that gives the same answer wherever the tests run.</summary>
/// <remarks>
/// Path.GetFullPath on Windows turns /usr/bin into D:\usr\bin, so a parser or inspector judged by tests on
/// Windows must not use it on a Mac path. This is purely lexical: links are resolved elsewhere.
/// </remarks>
public static class MacPaths
{
    /// <summary>The path with ".", ".." and repeated slashes removed, or null when it is not absolute.</summary>
    public static string? Lexical(string path)
    {
        if (string.IsNullOrEmpty(path) || path[0] != '/')
        {
            return null;
        }

        var parts = new List<string>();
        foreach (var part in path.Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            if (part == "..")
            {
                if (parts.Count > 0)
                {
                    parts.RemoveAt(parts.Count - 1);
                }
            }
            else if (part != ".")
            {
                parts.Add(part);
            }
        }

        return "/" + string.Join('/', parts);
    }
}
