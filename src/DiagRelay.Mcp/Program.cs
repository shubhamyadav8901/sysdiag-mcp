using DiagRelay.Mcp;

if (args.Any(a => a is "--help" or "-h" or "/?"))
{
    Console.Error.WriteLine(
        """
        DiagRelay.Mcp -- local stdio MCP relay to remote diagnostics servers

        Usage:
          DiagRelay.Mcp            run the relay on stdio (what an MCP client launches)
          DiagRelay.Mcp --help     show this text

        Targets listed in ~/.windiag-targets.json are connected at launch; the 'connect' tool adds more.

        Environment:
          WINDIAG_RELAY_FILE_ROOT  semicolon-separated local directories push_file may read from and
                                   pull_file may write to (default: the parent of this executable's
                                   directory, plus a per-user 'windiag' folder: %TEMP%\windiag on
                                   Windows, $XDG_CACHE_HOME/windiag or ~/.cache/windiag elsewhere)
        """);
    return 0;
}

// Any other argument is ignored, deliberately: a registration carried over from the old
// `WinDiag.Mcp.exe --relay` still passes `--relay`, and it should simply work.
return await RelayServer.RunAsync(defaultPort: 4024).ConfigureAwait(false);
