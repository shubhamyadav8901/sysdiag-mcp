using System.Runtime.Versioning;
using Diag.Mcp.Server.SelfUpdate;
using WinDiag.Mcp.Diagnostics.Signatures;

namespace WinDiag.Mcp.Diagnostics.SelfUpdate;

/// <summary>Hashes a staged build and reads its Authenticode signature through WinTrust.</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsStagedBuildInspector : IStagedBuildInspector
{
    private readonly ISignatureInspector _signatures;

    public WindowsStagedBuildInspector(ISignatureInspector signatures)
    {
        _signatures = signatures;
    }

    public StagedBuild Inspect(string path, CancellationToken cancellationToken)
    {
        var file = _signatures.Inspect([path], cancellationToken).Files.Single();
        return new StagedBuild(path, file.Sha256, file.SizeBytes, file.Verdict.ToString(), file.Detail);
    }
}
