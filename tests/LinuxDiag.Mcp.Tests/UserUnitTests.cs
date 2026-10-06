using LinuxDiag.Mcp.Diagnostics.Autostart;
using LinuxDiag.Mcp.Linux.Packages;
using LinuxDiag.Mcp.Linux.Parsers;

namespace LinuxDiag.Mcp.Tests;

/// <summary>
/// Users' systemd units, read from a scratch tree laid out like a real machine: the system directories under a
/// root prefix, the user's home as given. Files are read with managed calls so this runs on any OS; the
/// [LinuxFact] repeats the central case through the server's own readers.
/// </summary>
public sealed class UserUnitTests : IDisposable
{
    private readonly string _root = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"ld-uu-{Guid.NewGuid():N}")).FullName;

    public void Dispose() => Directory.Delete(_root, recursive: true);

    private string Home => Path.Combine(_root, "home/u");

    private PasswdEntry User => new("u", 1000, Home);

    private string Write(string path, string text)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, text);
        return path;
    }

    private static void Link(string link, string target)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(link)!);
        File.CreateSymbolicLink(link, target);
    }

    private static string ManagedRead(string path) => File.Exists(path) ? File.ReadAllText(path) : string.Empty;

    private static string? ManagedRealPath(string path)
    {
        try
        {
            var info = new FileInfo(path);
            return info.LinkTarget is null ? info.FullName : info.ResolveLinkTarget(returnFinalTarget: true)?.FullName;
        }
        catch (IOException)
        {
            return null;
        }
    }

    private List<AutostartEntry> Audit(UserUnits? units = null, List<string>? limitations = null) =>
        (units ?? new UserUnits(ManagedRead, ManagedRealPath, _root)).Audit([User], _ => false, limitations ?? []).ToList();

    /// <summary>A packaged user unit, the user's enable link to it, and the user's drop-in that replaces its ExecStart.</summary>
    private (string Vendor, string DropIn) PackagedUnitOverriddenByTheUser()
    {
        var vendor = Write(Path.Combine(_root, "usr/lib/systemd/user/x.service"), "[Unit]\nDescription=x\n\n[Service]\nExecStart=/usr/bin/x --serve\n");
        Link(Path.Combine(Home, ".config/systemd/user/default.target.wants/x.service"), vendor);
        var dropIn = Write(Path.Combine(Home, ".config/systemd/user/x.service.d/o.conf"), "[Service]\nExecStart=\nExecStart=/home/u/.cache/p\n");
        return (vendor, dropIn);
    }

    [Fact]
    public void A_users_drop_in_that_replaces_a_packaged_units_ExecStart_is_what_is_reported_and_is_never_hidden_as_packaged()
    {
        // Review: an enabled packaged user unit plus ~/.config/systemd/user/x.service.d/o.conf resetting ExecStart ran
        // the user's payload at every login, while the audit read only the unit file: it reported the packaged
        // program, checked no drop-in, called the entry packaged, and unpackagedOnly hid it.
        var (vendor, dropIn) = PackagedUnitOverriddenByTheUser();

        var entry = Assert.Single(Audit());

        Assert.Equal("x.service", entry.Entry);
        Assert.Equal("u", entry.Profile);
        Assert.Equal(vendor, entry.Location);
        Assert.Equal("/home/u/.cache/p", entry.ImagePath);
        Assert.Equal([dropIn], entry.DropIns);

        var owners = new Dictionary<string, PackageFile>
        {
            [vendor] = new("x", "1", "unit", false, null),
            ["/usr/bin/x"] = new("x", "1", "binary", false, null),
        };
        var verified = LinuxAutostartInspector.Verify(entry, path => owners.GetValueOrDefault(path), path => path == vendor ? "unit" : "other");
        Assert.False(verified.Packaged);
        Assert.Contains(verified.PackageFindings, f => f.StartsWith(dropIn, StringComparison.Ordinal));
        Assert.False(LinuxAutostartInspector.Hidden(verified, new AutostartQuery(UnpackagedOnly: true)));
    }

    [LinuxFact]
    public void A_users_drop_in_that_replaces_ExecStart_is_found_through_the_servers_own_file_readers()
    {
        var (_, dropIn) = PackagedUnitOverriddenByTheUser();

        var entry = Assert.Single(Audit(UserUnits.Reading(_root)));

        Assert.Equal("/home/u/.cache/p", entry.ImagePath);
        Assert.Contains(dropIn, entry.DropIns);
    }

    [LinuxFact]
    public void A_symlink_loop_in_a_users_wants_directory_is_reported_not_fatal()
    {
        // Final review: one self-referencing link made the whole default audit fail.
        var link = Path.Combine(Home, ".config/systemd/user/default.target.wants/loop.service");
        Link(link, link);

        var entry = Assert.Single(Audit(UserUnits.Reading(_root)));

        Assert.Equal("loop.service", entry.Entry);
        Assert.Null(entry.ImagePath);
    }

    [Fact]
    public void A_unit_that_lists_a_benign_ExecStart_and_then_resets_it_reports_the_command_after_the_reset()
    {
        var unit = Write(Path.Combine(Home, ".config/systemd/user/y.service"),
            "[Unit]\nExecStart=/not/a/service/setting\n[Service]\nExecStart=/usr/bin/true\nExecStart=\n" +
            "# a comment between\nExecStart=/home/u/bin/payload \\\n  --quiet\n");
        Link(Path.Combine(Home, ".config/systemd/user/default.target.wants/y.service"), unit);

        var entry = Assert.Single(Audit());

        Assert.Equal("/home/u/bin/payload", entry.ImagePath);
        Assert.Equal("/home/u/bin/payload    --quiet", entry.LaunchString);
    }

    [Fact]
    public void A_users_own_unit_file_shadows_the_packaged_one_the_enable_link_points_at()
    {
        // systemd loads a unit by name from its search path; ~/.config comes before /usr/lib, wherever the link points.
        var vendor = Write(Path.Combine(_root, "usr/lib/systemd/user/x.service"), "[Service]\nExecStart=/usr/bin/x\n");
        Link(Path.Combine(Home, ".config/systemd/user/default.target.wants/x.service"), vendor);
        var own = Write(Path.Combine(Home, ".config/systemd/user/x.service"), "[Service]\nExecStart=/home/u/x\n");

        var entry = Assert.Single(Audit());

        Assert.Equal(own, entry.Location);
        Assert.Equal("/home/u/x", entry.ImagePath);
    }

    [Fact]
    public void A_unit_enabled_for_every_user_is_reported_again_for_a_user_whose_own_drop_in_changes_it()
    {
        // No enable needed: a type-level drop-in in the user's home rewrites every unit their manager runs,
        // including one enabled for everyone in /etc.
        var vendor = Write(Path.Combine(_root, "usr/lib/systemd/user/agent.service"), "[Service]\nExecStart=/usr/bin/agent\n");
        Link(Path.Combine(_root, "etc/systemd/user/default.target.wants/agent.service"), vendor);
        var dropIn = Write(Path.Combine(Home, ".config/systemd/user/service.d/zz.conf"), "[Service]\nExecStart=\nExecStart=/home/u/.p\n");

        var entries = Audit();

        var global = entries.Single(e => e.Profile == "(every user)");
        Assert.Equal("/usr/bin/agent", global.ImagePath);
        Assert.Empty(global.DropIns);
        var mine = entries.Single(e => e.Profile == "u");
        Assert.Equal("agent.service", mine.Entry);
        Assert.Equal("/home/u/.p", mine.ImagePath);
        Assert.Equal([dropIn], mine.DropIns);
        Assert.Contains("this user's own", mine.Description, StringComparison.Ordinal);
    }

    [Fact]
    public void A_same_named_drop_in_in_the_users_directory_replaces_the_systems_and_drop_ins_apply_in_name_order()
    {
        var vendor = Write(Path.Combine(_root, "usr/lib/systemd/user/a-b.service"), "[Service]\nExecStart=/usr/bin/ab\n");
        Link(Path.Combine(Home, ".config/systemd/user/default.target.wants/a-b.service"), vendor);
        Write(Path.Combine(_root, "etc/systemd/user/a-b.service.d/50-x.conf"), "[Service]\nExecStart=\nExecStart=/etc/shadowed\n");
        var mine = Write(Path.Combine(Home, ".config/systemd/user/a-b.service.d/50-x.conf"), "[Service]\nExecStart=\nExecStart=/home/u/first\n");
        var later = Write(Path.Combine(_root, "usr/lib/systemd/user/a-.service.d/60-y.conf"), "[Service]\nEnvironment=X=1\n");

        var entry = Assert.Single(Audit());

        Assert.Equal([mine, later], entry.DropIns);
        Assert.Equal("/home/u/first", entry.ImagePath);
    }

    [Fact]
    public void A_users_timer_reports_the_program_of_the_service_it_runs_with_that_services_files_checked()
    {
        // Enabled user timers were listed with no program at all: the service they trigger was never followed.
        var timer = Write(Path.Combine(Home, ".config/systemd/user/t.timer"), "[Timer]\nOnCalendar=hourly\nUnit=job.service\n");
        Link(Path.Combine(Home, ".config/systemd/user/timers.target.wants/t.timer"), timer);
        var job = Write(Path.Combine(Home, ".local/share/systemd/user/job.service"), "[Service]\nExecStart=/home/u/job.sh\n");
        var jobDropIn = Write(Path.Combine(Home, ".config/systemd/user/job.service.d/e.conf"), "[Service]\nNice=5\n");

        var entry = Assert.Single(Audit());

        Assert.Equal("t.timer", entry.Entry);
        Assert.Equal(timer, entry.Location);
        Assert.Equal("/home/u/job.sh", entry.ImagePath);
        Assert.Contains("runs job.service", entry.Description, StringComparison.Ordinal);
        Assert.Equal([job, jobDropIn], entry.DropIns);
    }

    [Fact]
    public void A_socket_with_Accept_runs_the_template_of_its_own_name()
    {
        var socket = Write(Path.Combine(Home, ".config/systemd/user/s.socket"), "[Socket]\nListenStream=%t/s\nAccept=yes\n");
        Link(Path.Combine(Home, ".config/systemd/user/sockets.target.wants/s.socket"), socket);
        Write(Path.Combine(Home, ".config/systemd/user/s@.service"), "[Service]\nExecStart=-/home/u/serve\n");

        var entry = Assert.Single(Audit());

        Assert.Equal("/home/u/serve", entry.ImagePath);
        Assert.Contains("runs s@.service", entry.Description, StringComparison.Ordinal);
    }

    [Fact]
    public void An_instance_resolves_to_its_template_and_its_template_drop_ins()
    {
        var template = Write(Path.Combine(_root, "usr/lib/systemd/user/w@.service"), "[Service]\nExecStart=/usr/bin/w %i\n");
        Link(Path.Combine(Home, ".config/systemd/user/default.target.wants/w@one.service"), template);
        var dropIn = Write(Path.Combine(Home, ".config/systemd/user/w@.service.d/o.conf"), "[Service]\nExecStart=\nExecStart=/home/u/w\n");

        var entry = Assert.Single(Audit());

        Assert.Equal(template, entry.Location);
        Assert.Equal([dropIn], entry.DropIns);
        Assert.Equal("/home/u/w", entry.ImagePath);
    }

    [Theory]
    [InlineData("x.service", new[] { "x.service", "service" })]
    [InlineData("a-b-c.service", new[] { "a-b-c.service", "a-b-.service", "a-.service", "service" })]
    [InlineData("w-x@i.service", new[] { "w-x@i.service", "w-x@.service", "w-.service", "service" })]
    [InlineData("-.slice", new[] { "-.slice", "slice" })]
    public void Drop_ins_are_looked_for_under_the_name_its_template_its_dash_prefixes_and_its_type(string name, string[] expected)
    {
        Assert.Equal(expected, UserUnits.DropInNames([name]));
    }

    [Fact]
    public void Unit_file_settings_honour_sections_continuations_comments_and_the_empty_reset()
    {
        string[] texts =
        [
            "[Service]\nExecStart=/a\r\nExecStart=/b \\\n; comment inside\n  two\n[Install]\nExecStart=/install\n",
            "[Service]\n  ExecStart =  \nExecStart=/c\nExecStart=/d\\\\\n",
        ];

        Assert.Equal(["/c", "/d\\\\"], UnitFile.Values(texts, "Service", "ExecStart"));
        Assert.Equal(["/a", "/b    two"], UnitFile.Values(texts.Take(1), "Service", "ExecStart"));
        Assert.Null(UnitFile.Last([], "Timer", "Unit"));
    }
}
