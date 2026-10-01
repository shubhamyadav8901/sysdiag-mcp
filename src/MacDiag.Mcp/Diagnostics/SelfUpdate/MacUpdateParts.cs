using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Diag.Mcp.Server.SelfUpdate;
using MacDiag.Mcp.Mac.Parsers;

namespace MacDiag.Mcp.Diagnostics.SelfUpdate;

/// <summary>Hashes a staged build and reads its code signature with codesign -dv.</summary>
public sealed class MacStagedBuildInspector(IExternalCommand commands) : IStagedBuildInspector
{
    public StagedBuild Inspect(string path, CancellationToken cancellationToken)
    {
        string sha;
        using (var stream = File.OpenRead(path))
        {
            sha = Convert.ToHexString(SHA256.HashData(stream));
        }

        var display = commands.RunAsync("codesign", ["-dv", "--", path], TimeSpan.FromSeconds(30), cancellationToken).GetAwaiter().GetResult();
        var (verdict, detail) = CodesignDisplay.Verdict(display.ExitCode, display.StandardError);
        return new StagedBuild(path, sha, new FileInfo(path).Length, verdict, detail);
    }
}

/// <summary>The staged build must be a Mach-O this Mac can run, and an arm64 one must carry a valid signature.</summary>
/// <remarks>An unsigned arm64 binary is killed by the kernel at launch, so installing one would end the server for good.</remarks>
public sealed class MachOUpdateGuard(IExternalCommand commands) : IUpdateGuard
{
    internal bool PreferArm64 { get; init; } = RuntimeInformation.OSArchitecture == Architecture.Arm64;

    internal Func<bool> RosettaInstalled { get; init; } = static () => File.Exists("/Library/Apple/usr/libexec/oah/libRosettaRuntime");

    public void RequireAcceptable(string livePath, StagedBuild staged, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(staged);

        MachOVerdict verdict;
        using (var stream = File.OpenRead(staged.Path))
        {
            verdict = MachO.Inspect((offset, count) => Read(stream, offset, count), PreferArm64, RosettaInstalled);
        }

        if (verdict.Problem is { } problem)
        {
            throw new SelfUpdateRejectedException($"'{staged.Path}' was refused because {problem} Nothing has been changed.");
        }

        if (verdict.CpuType == MachO.CpuTypeArm64)
        {
            var check = commands.RunAsync("codesign", ["--verify", "--", staged.Path], TimeSpan.FromSeconds(60), cancellationToken).GetAwaiter().GetResult();
            if (check.ExitCode != 0)
            {
                throw new SelfUpdateRejectedException(
                    $"'{staged.Path}' was refused because an unsigned arm64 binary is killed by macOS at launch ({check.StandardError.Trim()}). " +
                    "Sign it (codesign --force --sign -) before staging. Nothing has been changed.");
            }
        }
    }

    private static byte[] Read(FileStream stream, long offset, int count)
    {
        if (offset >= stream.Length || count <= 0)
        {
            return [];
        }

        var buffer = new byte[(int)Math.Min(count, stream.Length - offset)];
        stream.Position = offset;
        stream.ReadExactly(buffer);
        return buffer;
    }
}
