using System.Security.Cryptography;
using Diag.Mcp.Server.SelfUpdate;

namespace LinuxDiag.Mcp.Diagnostics.SelfUpdate;

/// <summary>Hashes a staged build. Nothing on Linux is signed, so the verdict says so rather than guessing.</summary>
public sealed class LinuxStagedBuildInspector : IStagedBuildInspector
{
    public StagedBuild Inspect(string path, CancellationToken cancellationToken)
    {
        using var stream = File.OpenRead(path);
        var sha = Convert.ToHexString(SHA256.HashData(stream));
        return new StagedBuild(path, sha, new FileInfo(path).Length, "NotSigned", null);
    }
}
