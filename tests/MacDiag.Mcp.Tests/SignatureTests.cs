using System.Collections;
using MacDiag.Mcp.Configuration;
using MacDiag.Mcp.Diagnostics.Signatures;
using MacDiag.Mcp.Mac.Parsers;
using MacDiag.Mcp.Tools;
using static MacDiag.Mcp.Tests.StatLinesTests;
using static MacDiag.Mcp.Tests.SystemOverviewTests;

namespace MacDiag.Mcp.Tests;

public sealed class SignatureTests
{
    private const string Tool = "/usr/local/bin/tool";
    private const string AppBinary = "/Applications/Example.app/Contents/MacOS/Example";
    private const string Digest = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    /// <summary>A Mac that answers stat for the given lines and codesign, spctl, pkgutil and shasum as told.</summary>
    private sealed class Mac
    {
        public Dictionary<string, string> Stats { get; } = new()
        {
            [Tool] = Line(Tool, 0, 0, "0755", "Regular File", size: 4096),
            [AppBinary] = Line(AppBinary, 0, 80, "0755", "Regular File", size: 1_048_576),
        };

        public Func<string, ExternalResult> Verify { get; set; } = _ => new ExternalResult(0, "", "");

        /// <summary>codesign -R="anchor apple": by default nothing here was signed by Apple, as codesign reports it.</summary>
        public Func<string, ExternalResult> AppleAnchored { get; set; } = path =>
            new ExternalResult(3, "", $"{path}: test-requirement: code failed to satisfy specified code requirement(s)");

        /// <summary>codesign -R="anchor apple generic": by default every chain here is one Apple issued, as a Developer ID is.</summary>
        public Func<string, ExternalResult> AppleIssued { get; set; } = _ => new ExternalResult(0, "", "");

        public Func<string, ExternalResult> Display { get; set; } = path =>
            new ExternalResult(0, "", Fixture(Unverified, path == AppBinary ? "codesign-dvvv-devid" : "codesign-dvvv-adhoc"));

        public Func<string, ExternalResult> Pkgutil { get; set; } = path =>
            path == Tool ? FakeCommands.Ok(Fixture(Unverified, "pkgutil-file-info")) : new ExternalResult(1, "", $"No receipt for '{path}' found at '/'.");

        public Func<string, ExternalResult> Shasum { get; set; } = path => FakeCommands.Ok($"{Digest}  {path}\n");

        public ExternalResult Spctl { get; set; } = new(0, "", "/Applications/Example.app: accepted\nsource=Notarized Developer ID\n");

        /// <summary>Programs that never finish, as the real runner reports it: by throwing.</summary>
        public HashSet<string> Hangs { get; } = [];

        public FakeCommands Commands() => new((program, args) => program switch
        {
            _ when Hangs.Contains(program) || Hangs.Contains($"{program} {args[0]}") => FakeCommands.Hang(program),
            "stat" => Answer(Stats, args),
            "shasum" => Shasum(args[^1]),
            "codesign" when args.Contains("-R=anchor apple generic") => AppleIssued(args[^1]),
            "codesign" when args.Contains("-R=anchor apple") => AppleAnchored(args[^1]),
            "codesign" when args[0] == "--verify" => Verify(args[^1]),
            "codesign" when args[0] == "-dvvv" => Display(args[^1]),
            "spctl" => Spctl,
            "pkgutil" => Pkgutil(args[^1]),
            _ => new ExternalResult(1, "", $"unexpected {program}"),
        });
    }

    private static MacSignatureInspector Inspector(FakeCommands commands) =>
        new(commands, MacDiagOptions.FromEnvironment(new Hashtable())) { Resolve = path => path };

    [Fact]
    public void A_developer_id_signature_gives_identifier_team_authorities_and_hardened_runtime()
    {
        var details = CodesignDisplay.Details(Fixture(Unverified, "codesign-dvvv-devid"));

        Assert.Equal(("com.example.app", "ABCDE12345", false, true), (details.Identifier, details.TeamId, details.AdHoc, details.HardenedRuntime));
        Assert.Equal(["Developer ID Application: Example Corp (ABCDE12345)", "Developer ID Certification Authority", "Apple Root CA"], details.Authorities);
    }

    [Fact]
    public void A_platform_binary_has_no_team_and_software_signing_as_its_leaf()
    {
        var details = CodesignDisplay.Details(Fixture(Unverified, "codesign-dvvv-apple"));

        Assert.Equal(("com.apple.ls", null, false), (details.Identifier, details.TeamId, details.HardenedRuntime));
        Assert.Equal("Software Signing", details.Authorities[0]);
    }

    [Fact]
    public void A_platform_binary_on_macos_26_names_macos_software_signing_as_its_leaf()
    {
        // codesign -dvvv /bin/ls on macOS 26.6.2 (25G83), trimmed to the lines the parser reads.
        var details = CodesignDisplay.Details("""
            Executable=/bin/ls
            Identifier=com.apple.ls
            Format=Mach-O universal (x86_64 arm64e)
            CodeDirectory v=20400 size=325 flags=0x0(none) hashes=5+2 location=embedded
            Platform identifier=26
            Authority=macOS Software Signing
            Authority=Apple Code Signing Certification Authority
            Authority=Apple Root CA
            TeamIdentifier=not set
            """);

        Assert.Equal(["macOS Software Signing", "Apple Code Signing Certification Authority", "Apple Root CA"], details.Authorities);
    }

    [Fact]
    public void An_ad_hoc_signature_has_no_authority_and_its_adhoc_flag_is_not_read_as_hardened_runtime()
    {
        var details = CodesignDisplay.Details(Fixture(Unverified, "codesign-dvvv-adhoc"));

        Assert.True(details.AdHoc);
        Assert.False(details.HardenedRuntime);
        Assert.Empty(details.Authorities);
    }

    [Fact]
    public void Pkgutil_gives_the_receipts_package_and_version()
    {
        Assert.Equal(("com.example.tool", "2.1.0"), PkgutilFileInfo.Parse(Fixture(Unverified, "pkgutil-file-info")));
        Assert.Equal((null, null), PkgutilFileInfo.Parse(""));
    }

    [Fact]
    public async Task A_signed_app_reports_signer_gatekeeper_package_size_and_hash()
    {
        var mac = new Mac();

        var file = (await Inspector(mac.Commands()).InspectAsync([AppBinary], CancellationToken.None)).Files.Single();

        Assert.Equal(SignatureVerdict.Valid, file.Verdict);
        Assert.Equal("Signed by certificate \"Developer ID Application: Example Corp (ABCDE12345)\" (team ABCDE12345), verified", file.Detail);
        Assert.Equal("accepted (Notarized Developer ID)", file.Gatekeeper);
        Assert.True(file.HardenedRuntime);
        Assert.Null(file.Package);
        Assert.Equal((1_048_576L, Digest.ToUpperInvariant()), (file.SizeBytes, file.Sha256));
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1727762400), file.LastWriteTime);
    }

    [Fact]
    public async Task Gatekeeper_is_asked_about_the_app_bundle_and_never_about_a_bare_tool()
    {
        var mac = new Mac();
        var commands = mac.Commands();

        var result = await Inspector(commands).InspectAsync([Tool, AppBinary], CancellationToken.None);

        var spctl = Assert.Single(commands.Calls, c => c.Program == "spctl");
        Assert.Equal(["--assess", "--type", "execute", "-v", "/Applications/Example.app"], spctl.Arguments);
        Assert.Equal("not applicable", result.Files.Single(f => f.Path == Tool).Gatekeeper);
    }

    [Fact]
    public async Task A_gatekeeper_rejection_and_an_assessment_error_are_told_apart()
    {
        var mac = new Mac { Spctl = new ExternalResult(3, "", "/Applications/Example.app: rejected\nsource=no usable signature\n") };
        Assert.StartsWith("rejected", (await Inspector(mac.Commands()).InspectAsync([AppBinary], CancellationToken.None)).Files[0].Gatekeeper, StringComparison.Ordinal);

        mac.Spctl = new ExternalResult(1, "", "spctl: internal error\n");
        Assert.StartsWith("not assessed", (await Inspector(mac.Commands()).InspectAsync([AppBinary], CancellationToken.None)).Files[0].Gatekeeper, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_ad_hoc_tool_with_a_receipt_is_ad_hoc_and_names_its_package()
    {
        var file = (await Inspector(new Mac().Commands()).InspectAsync([Tool], CancellationToken.None)).Files.Single();

        Assert.Equal(SignatureVerdict.AdHoc, file.Verdict);
        Assert.Equal(("com.example.tool", "2.1.0"), (file.Package, file.PackageVersion));
    }

    [Fact]
    public async Task A_certificate_named_apple_is_quoted_so_it_cannot_read_as_the_anchor_checked_verdict()
    {
        var mac = new Mac { Display = _ => new ExternalResult(0, "", "Identifier=x\nAuthority=Apple\" x\nAuthority=Apple Root CA\n") };

        var file = (await Inspector(mac.Commands()).InspectAsync([Tool], CancellationToken.None)).Files.Single();

        Assert.Equal("Signed by certificate \"Apple\\\" x\", verified", file.Detail);
    }

    [Fact]
    public async Task An_apple_check_that_does_not_finish_is_reported_as_undetermined_rather_than_as_another_signer()
    {
        var mac = new Mac
        {
            Display = _ => new ExternalResult(0, "", Fixture(Unverified, "codesign-dvvv-apple")),
            AppleAnchored = _ => FakeCommands.Hang("codesign"),
        };

        var file = (await Inspector(mac.Commands()).InspectAsync([Tool], CancellationToken.None)).Files.Single();

        Assert.Equal(SignatureVerdict.Valid, file.Verdict);
        Assert.Contains("whether Apple signed it was not determined", file.Detail, StringComparison.Ordinal);
        Assert.Contains("did not finish", file.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_signature_with_a_team_is_not_asked_whether_apple_signed_it()
    {
        // Apple's own code carries no team, and the check repeats the whole verification: seconds for a large app.
        var commands = new Mac().Commands();

        var file = (await Inspector(commands).InspectAsync([AppBinary], CancellationToken.None)).Files.Single();

        Assert.Equal("ABCDE12345", file.TeamId);
        Assert.DoesNotContain(commands.Calls, c => c.Arguments.Contains("-R=anchor apple"));
    }

    [Fact]
    public async Task A_signature_with_a_team_is_still_asked_whether_apple_issued_its_certificate()
    {
        // The team is the leaf's OU, which whoever made the certificate chose: it can skip the Apple question, never this one.
        var commands = new Mac().Commands();

        await Inspector(commands).InspectAsync([AppBinary], CancellationToken.None);

        Assert.Contains(commands.Calls, c => c.Program == "codesign" && c.Arguments.SequenceEqual(["--verify", "--strict", "-R=anchor apple generic", "--", AppBinary]));
    }

    [Fact]
    public async Task A_self_signed_chain_copying_a_developer_id_name_and_team_is_untrusted_not_valid()
    {
        // Before: Valid, "Signed by certificate "Developer ID Application: Google LLC (EQHXZ8M8AV)" (team EQHXZ8M8AV), verified" --
        // word for word what Google's real signature reads as, from a certificate anybody can make.
        var mac = new Mac
        {
            Display = _ => new ExternalResult(0, "",
                "Identifier=com.google.keystone\nAuthority=Developer ID Application: Google LLC (EQHXZ8M8AV)\nTeamIdentifier=EQHXZ8M8AV\n"),
            AppleIssued = path => new ExternalResult(3, "", $"{path}: test-requirement: code failed to satisfy specified code requirement(s)"),
        };

        var file = (await Inspector(mac.Commands()).InspectAsync([AppBinary], CancellationToken.None)).Files.Single();

        Assert.Equal(SignatureVerdict.Untrusted, file.Verdict);
        Assert.StartsWith("Signed by certificate \"Developer ID Application: Google LLC (EQHXZ8M8AV)\", which Apple did not issue", file.Detail, StringComparison.Ordinal);
        Assert.DoesNotContain("(team ", file.Detail, StringComparison.Ordinal);
        Assert.DoesNotContain("verified", file.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_issuer_check_that_does_not_finish_is_unknown_rather_than_valid()
    {
        // Whether anybody but the signer vouches for the name is the question left open: Valid would answer it.
        var mac = new Mac { AppleIssued = _ => FakeCommands.Hang("codesign") };

        var file = (await Inspector(mac.Commands()).InspectAsync([AppBinary], CancellationToken.None)).Files.Single();

        Assert.Equal(SignatureVerdict.Unknown, file.Verdict);
        Assert.Contains("whether Apple issued its certificate was not determined", file.Detail, StringComparison.Ordinal);
        Assert.Contains("did not finish", file.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Apples_own_signature_is_not_asked_the_issuer_question_as_well()
    {
        // anchor apple already settles it, and each requirement check repeats the whole verification.
        var mac = new Mac
        {
            Display = _ => new ExternalResult(0, "", Fixture(Unverified, "codesign-dvvv-apple")),
            AppleAnchored = _ => new ExternalResult(0, "", ""),
        };
        var commands = mac.Commands();

        await Inspector(commands).InspectAsync([Tool], CancellationToken.None);

        Assert.DoesNotContain(commands.Calls, c => c.Arguments.Contains("-R=anchor apple generic"));
    }

    [Fact]
    public async Task A_platform_binary_is_signed_by_apple()
    {
        var mac = new Mac
        {
            Display = _ => new ExternalResult(0, "", Fixture(Unverified, "codesign-dvvv-apple")),
            AppleAnchored = _ => new ExternalResult(0, "", ""),
        };

        var file = (await Inspector(mac.Commands()).InspectAsync([Tool], CancellationToken.None)).Files.Single();

        Assert.Equal((SignatureVerdict.Valid, "Signed by Apple, verified"), (file.Verdict, file.Detail));
    }

    [Fact]
    public async Task A_valid_signature_whose_leaf_is_only_named_like_apples_is_not_reported_as_signed_by_apple()
    {
        // A self-signed chain verifies, and its certificates can be called anything: only the anchor checks tell.
        var mac = new Mac
        {
            Display = _ => new ExternalResult(0, "", "Identifier=com.apple.ls\nAuthority=macOS Software Signing\nAuthority=Apple Root CA\n"),
            AppleIssued = path => new ExternalResult(3, "", $"{path}: test-requirement: code failed to satisfy specified code requirement(s)"),
        };

        var file = (await Inspector(mac.Commands()).InspectAsync([Tool], CancellationToken.None)).Files.Single();

        Assert.Equal(SignatureVerdict.Untrusted, file.Verdict);
        Assert.StartsWith("Signed by certificate \"macOS Software Signing\", which Apple did not issue", file.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_unsigned_file_and_a_broken_signature_are_told_apart()
    {
        var mac = new Mac
        {
            Verify = path => path == Tool
                ? new ExternalResult(1, "", $"{path}: code object is not signed at all\n")
                : new ExternalResult(1, "", $"{path}: a sealed resource is missing or invalid\nfile modified: Contents/Resources/x\n"),
        };

        var files = (await Inspector(mac.Commands()).InspectAsync([Tool, AppBinary], CancellationToken.None)).Files;

        Assert.Equal((SignatureVerdict.Unsigned, "Not signed"), (files[0].Verdict, files[0].Detail));
        Assert.Equal(SignatureVerdict.Invalid, files[1].Verdict);
        Assert.Contains("does NOT verify", files[1].Detail, StringComparison.Ordinal);
        Assert.Contains("sealed resource is missing", files[1].Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_fifo_is_never_opened_so_the_call_cannot_hang_on_it()
    {
        var mac = new Mac();
        mac.Stats["/tmp/pipe"] = Line("/tmp/pipe", 501, 20, "0644", "Fifo File");
        var commands = mac.Commands();

        var result = await Inspector(commands).InspectAsync(["/tmp/pipe"], CancellationToken.None);

        Assert.Empty(result.Files);
        Assert.Equal(["/tmp/pipe (not a regular file)"], result.NotFound);
        Assert.Equal(["stat"], commands.Calls.Select(c => c.Program));
    }

    [Fact]
    public async Task A_link_is_inspected_where_it_leads_and_reports_both_paths()
    {
        var mac = new Mac();
        var inspector = new MacSignatureInspector(mac.Commands(), MacDiagOptions.FromEnvironment(new Hashtable()))
        {
            Resolve = path => path == "/opt/homebrew/bin/tool" ? Tool : path,
        };

        var file = (await inspector.InspectAsync(["/opt/homebrew/bin/tool"], CancellationToken.None)).Files.Single();

        Assert.Equal(("/opt/homebrew/bin/tool", Tool), (file.Path, file.ResolvedPath));
    }

    [Fact]
    public async Task Absent_relative_and_control_character_paths_are_not_found_and_never_reach_a_program()
    {
        var mac = new Mac();
        var commands = mac.Commands();

        var result = await Inspector(commands).InspectAsync(["/nope", "relative/x", "/bad\nname"], CancellationToken.None);

        Assert.Equal(new[] { "/nope", "relative/x", "/bad\nname" }.Order(StringComparer.Ordinal), result.NotFound.Order(StringComparer.Ordinal));
        Assert.DoesNotContain(commands.Calls.SelectMany(c => c.Arguments), a => a.Contains('\n', StringComparison.Ordinal) || a == "relative/x");
    }

    [Fact]
    public async Task A_file_shasum_cannot_read_is_permission_denied()
    {
        var mac = new Mac { Shasum = path => new ExternalResult(1, "", $"shasum: {path}: Permission denied\n") };

        var result = await Inspector(mac.Commands()).InspectAsync([Tool], CancellationToken.None);

        Assert.Equal([$"{Tool} (permission denied)"], result.NotFound);
    }

    [Fact]
    public async Task More_than_two_hundred_paths_are_refused_before_anything_runs()
    {
        var commands = new Mac().Commands();

        await Assert.ThrowsAsync<ArgumentException>(() => Inspector(commands).InspectAsync(Enumerable.Repeat(Tool, 201).ToList(), CancellationToken.None));
        Assert.Empty(commands.Calls);
    }

    [Fact]
    public async Task Files_past_the_calls_time_budget_are_named_not_silently_dropped()
    {
        var mac = new Mac();
        var inspector = new MacSignatureInspector(mac.Commands(), MacDiagOptions.FromEnvironment(new Hashtable()))
        {
            Resolve = path => path,
            Deadline = TimeSpan.Zero,
        };

        var result = await inspector.InspectAsync([Tool], CancellationToken.None);

        Assert.Empty(result.Files);
        Assert.Contains("not inspected", result.Limitation, StringComparison.Ordinal);
        Assert.Contains(Tool, result.Limitation, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_digest_shasum_marks_with_a_backslash_for_an_escaped_name_is_still_read()
    {
        var mac = new Mac { Shasum = path => FakeCommands.Ok($"\\{Digest}  {path}\\\\odd\n") };

        var file = (await Inspector(mac.Commands()).InspectAsync([Tool], CancellationToken.None)).Files.Single();

        Assert.Equal(Digest.ToUpperInvariant(), file.Sha256);
    }

    [Fact]
    public async Task An_app_bundle_passed_whole_is_answered_with_where_its_executable_is()
    {
        var mac = new Mac();
        mac.Stats["/Applications/Example.app"] = Line("/Applications/Example.app", 0, 80, "0755", "Directory");

        var result = await Inspector(mac.Commands()).InspectAsync(["/Applications/Example.app"], CancellationToken.None);

        Assert.Contains(result.NotFound, n => n.Contains("app bundle", StringComparison.Ordinal) && n.Contains("Contents/MacOS", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Hashing_that_never_finishes_costs_that_file_not_the_whole_call()
    {
        var mac = new Mac();
        mac.Hangs.Add("shasum");

        var result = await Inspector(mac.Commands()).InspectAsync([Tool], CancellationToken.None);

        Assert.Empty(result.Files);
        Assert.Contains(result.NotFound, n => n.StartsWith(Tool, StringComparison.Ordinal) && n.Contains("did not finish", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_codesign_that_never_finishes_is_unknown_not_a_failed_call()
    {
        var mac = new Mac();
        mac.Hangs.Add("codesign --verify");

        var file = (await Inspector(mac.Commands()).InspectAsync([Tool], CancellationToken.None)).Files.Single();

        Assert.Equal(SignatureVerdict.Unknown, file.Verdict);
        Assert.Contains("did not finish", file.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_gatekeeper_check_that_never_finishes_is_not_assessed()
    {
        var mac = new Mac();
        mac.Hangs.Add("spctl");

        var file = (await Inspector(mac.Commands()).InspectAsync([AppBinary], CancellationToken.None)).Files.Single();

        Assert.StartsWith("not assessed", file.Gatekeeper, StringComparison.Ordinal);
        Assert.Equal(SignatureVerdict.Valid, file.Verdict);
    }

    [Fact]
    public async Task No_command_is_given_longer_than_what_is_left_of_the_calls_budget()
    {
        var mac = new Mac();
        var commands = mac.Commands();
        var inspector = new MacSignatureInspector(commands, MacDiagOptions.FromEnvironment(new Hashtable()))
        {
            Resolve = path => path,
            Deadline = TimeSpan.FromSeconds(10),
        };

        await inspector.InspectAsync([Tool, AppBinary], CancellationToken.None);

        Assert.All(commands.Timeouts.Skip(1), timeout => Assert.True(timeout <= TimeSpan.FromSeconds(10), timeout.ToString()));
    }

    [Fact]
    public void The_summary_names_signer_gatekeeper_package_and_hash()
    {
        var file = new FileSignature(AppBinary, SignatureVerdict.Valid, "Signed by Apple, verified", null, "com.apple.ls", null, ["Software Signing"],
            false, "not applicable", "com.apple.pkg.Core", "14.6", 10, DateTimeOffset.UnixEpoch, "ABC");

        var summary = SignatureTools.Render(new SignatureQueryResult([file], ["/nope"], "A valid signature says who signed the file."));

        Assert.Contains("VALID - Signed by Apple, verified", summary, StringComparison.Ordinal);
        Assert.Contains("Package: com.apple.pkg.Core 14.6", summary, StringComparison.Ordinal);
        Assert.Contains("NOT FOUND: /nope", summary, StringComparison.Ordinal);
        Assert.Contains("SHA-256: ABC", summary, StringComparison.Ordinal);
    }
}
