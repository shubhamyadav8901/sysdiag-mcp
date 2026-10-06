using DiagRelay.Mcp.Tests;
using LinuxDiag.Mcp.Diagnostics.Autostart;
using LinuxDiag.Mcp.Linux.Packages;
using LinuxDiag.Mcp.Linux.Parsers;

namespace LinuxDiag.Mcp.Tests;

/// <summary>
/// Users' systemd units, read from a scratch tree laid out like a real machine: the system directories under a
/// root prefix, the user's home as given. Files are read with managed calls so this runs on any OS; the
/// [LinuxFact] repeats the central case through the server's own readers.
/// </summary>
/// <remarks>
/// Unix only: these build a real systemd user tree on disk and the audit spells what it finds the Linux
/// way ("x.service.d/o.conf"), which on Windows mixes separators with the temp root. The code is
/// LinuxDiag's, which never runs on Windows; macOS and CI's Linux jobs run them.
/// </remarks>
public sealed class UserUnitTests : IDisposable
{
    private readonly string _root = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"ld-uu-{Guid.NewGuid():N}")).FullName;

    public void Dispose() => Directory.Delete(_root, recursive: true);

    // Normalised, like every path the tests expect back: the units are found by walking directories, which
    // spells them with this OS's separator, so "home/u" joined as written only matched where that is '/'.
    private string Home => Path.GetFullPath(Path.Combine(_root, "home/u"));

    private PasswdEntry User => new("u", 1000, Home);

    private string Write(string path, string text)
    {
        path = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, text);
        return path;
    }

    private static void Link(string link, string target)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(link)!);
        File.CreateSymbolicLink(link, target);
    }

    // File.Exists is true for a link that leads nowhere; opening it fails, which reads as nothing, as the server's
    // own reader has it.
    private static string ManagedRead(string path)
    {
        try
        {
            return File.Exists(path) ? File.ReadAllText(path) : string.Empty;
        }
        catch (IOException)
        {
            return string.Empty;
        }
    }

    private static string? ManagedRealPath(string path)
    {
        try
        {
            // As realpath(3): null for a link that leads nowhere, not the missing name it points at.
            var info = new FileInfo(path);
            return info.LinkTarget is null ? info.FullName
                : info.ResolveLinkTarget(returnFinalTarget: true) is { Exists: true } target ? target.FullName : null;
        }
        catch (IOException)
        {
            return null;
        }
    }

    /// <summary>The owner check the server makes on the file it opens, modelled by place.</summary>
    /// <remarks>
    /// Managed code cannot read a file's owner, so what lies under the user's home is theirs and anything else is
    /// another account's -- the case that matters, a link out of the home to root's file. A device, such as the
    /// /dev/null that masks a file, opens as nothing, as the server's reader refuses anything but a regular file.
    /// </remarks>
    private string? ManagedReadOwnedBy(string path, long owner)
    {
        var real = ManagedRealPath(path);
        if (real is null || !File.Exists(real) || real.StartsWith("/dev/", StringComparison.Ordinal))
        {
            return string.Empty;
        }

        return owner == User.UserId && real.StartsWith(Home + Path.DirectorySeparatorChar, StringComparison.Ordinal)
            ? File.ReadAllText(real)
            : null;
    }

    private List<AutostartEntry> Audit(UserUnits? units = null, List<string>? limitations = null) =>
        (units ?? new UserUnits(ManagedRead, ManagedReadOwnedBy, ManagedRealPath, _root)).Audit([User], _ => false, limitations ?? []).ToList();

    /// <summary>A packaged user unit, the user's enable link to it, and the user's drop-in that replaces its ExecStart.</summary>
    private (string Vendor, string DropIn) PackagedUnitOverriddenByTheUser()
    {
        var vendor = Write(Path.Combine(_root, "usr/lib/systemd/user/x.service"), "[Unit]\nDescription=x\n\n[Service]\nExecStart=/usr/bin/x --serve\n");
        Link(Path.Combine(Home, ".config/systemd/user/default.target.wants/x.service"), vendor);
        var dropIn = Write(Path.Combine(Home, ".config/systemd/user/x.service.d/o.conf"), "[Service]\nExecStart=\nExecStart=/home/u/.cache/p\n");
        return (vendor, dropIn);
    }

    [UnixFact]
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

    [UnixFact]
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

    [UnixFact]
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

    [UnixFact]
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

    /// <summary>pipewire.socket as a desktop ships it: enabled for every user by a vendor link, starting pipewire.service.</summary>
    private (string Socket, string Service) PackagedSocketEnabledForEveryone()
    {
        var socket = Write(Path.Combine(_root, "usr/lib/systemd/user/pipewire.socket"), "[Socket]\nListenStream=%t/pipewire-0\n");
        Link(Path.Combine(_root, "usr/lib/systemd/user/sockets.target.wants/pipewire.socket"), socket);
        var service = Write(Path.Combine(_root, "usr/lib/systemd/user/pipewire.service"), "[Service]\nExecStart=/usr/bin/pipewire\n");
        return (socket, service);
    }

    [UnixTheory]
    [InlineData(".config/systemd/user/pipewire.service.d/o.conf", "[Service]\nExecStart=\nExecStart=/home/u/.p\n", false)]
    [InlineData(".config/systemd/user/service.d/x.conf", "[Service]\nExecStart=\nExecStart=/home/u/.p\n", false)]
    [InlineData(".config/systemd/user/pipewire.service", "[Service]\nExecStart=/home/u/.p\n", true)]
    public void A_user_who_changes_the_service_a_socket_enabled_for_everyone_starts_is_reported_with_their_program(
        string relative, string text, bool replacesTheUnitFile)
    {
        // Review: only the socket's own files were compared with everyone's, so a user's drop-in or unit file for
        // the service it starts left one '(every user)' entry naming /usr/bin/pipewire -- packaged, and hidden by
        // unpackagedOnly -- while the user's payload ran at their login.
        var (_, service) = PackagedSocketEnabledForEveryone();
        var own = Write(Path.Combine(Home, relative), text);

        var entries = Audit();

        var global = entries.Single(e => e.Profile == "(every user)");
        Assert.Equal("/usr/bin/pipewire", global.ImagePath);
        var mine = entries.Single(e => e.Profile == "u");
        Assert.Equal("pipewire.socket", mine.Entry);
        Assert.Equal("/home/u/.p", mine.ImagePath);
        Assert.Contains(own, mine.DropIns);
        Assert.Equal(!replacesTheUnitFile, mine.DropIns.Contains(service));
        Assert.Contains("this user's own", mine.Description, StringComparison.Ordinal);
    }

    [UnixFact]
    public void A_drop_in_under_another_name_linked_to_the_same_unit_file_applies_to_the_enabled_unit()
    {
        // Re-check: systemd gives a unit file every name a link in the search path gives it, and reads drop-ins for
        // all of them -- that is how display-manager.service.d reaches gdm.service. Only the enabled name's drop-ins
        // were read, so ~/.config/systemd/user/zz.service -> x.service plus zz.service.d/o.conf ran the payload while
        // the audit reported the packaged program and unpackagedOnly hid it.
        var vendor = Write(Path.Combine(_root, "usr/lib/systemd/user/x.service"), "[Service]\nExecStart=/usr/bin/x\n");
        Link(Path.Combine(Home, ".config/systemd/user/default.target.wants/x.service"), vendor);
        Link(Path.Combine(Home, ".config/systemd/user/zz.service"), vendor);
        var dropIn = Write(Path.Combine(Home, ".config/systemd/user/zz.service.d/o.conf"), "[Service]\nExecStart=\nExecStart=/home/u/.cache/p\n");

        var entry = Assert.Single(Audit());

        Assert.Equal(vendor, entry.Location);
        Assert.Equal("/home/u/.cache/p", entry.ImagePath);
        Assert.Equal([dropIn], entry.DropIns);
    }

    [UnixFact]
    public void A_users_alias_of_the_service_a_socket_enabled_for_everyone_starts_is_reported_for_that_user()
    {
        // The same through a unit enabled for every user: no enable of their own, one link and one drop-in.
        PackagedSocketEnabledForEveryone();
        Link(Path.Combine(Home, ".config/systemd/user/zz.service"), Path.Combine(_root, "usr/lib/systemd/user/pipewire.service"));
        var dropIn = Write(Path.Combine(Home, ".config/systemd/user/zz.service.d/o.conf"), "[Service]\nExecStart=\nExecStart=/home/u/.p\n");

        var entries = Audit();

        Assert.Equal("/usr/bin/pipewire", entries.Single(e => e.Profile == "(every user)").ImagePath);
        var mine = entries.Single(e => e.Profile == "u");
        Assert.Equal("/home/u/.p", mine.ImagePath);
        Assert.Contains(dropIn, mine.DropIns);
    }

    [UnixFact]
    public void A_template_alias_gives_an_instance_its_drop_ins_under_the_aliases_instance_name()
    {
        var template = Write(Path.Combine(_root, "usr/lib/systemd/user/w@.service"), "[Service]\nExecStart=/usr/bin/w %i\n");
        Link(Path.Combine(Home, ".config/systemd/user/default.target.wants/w@one.service"), template);
        Link(Path.Combine(Home, ".config/systemd/user/zz@.service"), template);
        var dropIn = Write(Path.Combine(Home, ".config/systemd/user/zz@one.service.d/o.conf"), "[Service]\nExecStart=\nExecStart=/home/u/w\n");

        var entry = Assert.Single(Audit());

        Assert.Equal([dropIn], entry.DropIns);
        Assert.Equal("/home/u/w", entry.ImagePath);
    }

    [UnixFact]
    public void A_link_to_another_unit_file_or_of_another_type_is_not_an_alias()
    {
        var vendor = Write(Path.Combine(_root, "usr/lib/systemd/user/x.service"), "[Service]\nExecStart=/usr/bin/x\n");
        Link(Path.Combine(Home, ".config/systemd/user/default.target.wants/x.service"), vendor);
        var other = Write(Path.Combine(_root, "usr/lib/systemd/user/y.service"), "[Service]\nExecStart=/usr/bin/y\n");
        Link(Path.Combine(Home, ".config/systemd/user/zz.service"), other);
        Write(Path.Combine(Home, ".config/systemd/user/zz.service.d/o.conf"), "[Service]\nExecStart=\nExecStart=/home/u/nope\n");

        var entry = Assert.Single(Audit());

        Assert.Equal("/usr/bin/x", entry.ImagePath);
        Assert.Empty(entry.DropIns);
    }

    // The alias cases below were each set up for a live user manager (systemd 252, Debian 12) and checked with
    // `systemctl --user show -p Names,FragmentPath,DropInPaths,ExecStart`; what each asserts is what it showed.

    [UnixFact]
    public void A_link_that_dangles_but_names_a_unit_in_the_search_path_is_an_alias_of_the_unit_found_under_that_name()
    {
        // Re-check: aliases were matched by where a link leads, so ~/.config/systemd/user/zz.service ->
        // /etc/systemd/user/x.service -- no such file; x.service lives in /usr/lib -- led nowhere and was dropped.
        // systemd goes by name: zz.service is x.service, and zz.service.d/o.conf replaced its ExecStart.
        var vendor = Write(Path.Combine(_root, "usr/lib/systemd/user/x.service"), "[Service]\nExecStart=/usr/bin/x\n");
        Link(Path.Combine(Home, ".config/systemd/user/default.target.wants/x.service"), vendor);
        Link(Path.Combine(Home, ".config/systemd/user/zz.service"), Path.Combine(_root, "etc/systemd/user/x.service"));
        var dropIn = Write(Path.Combine(Home, ".config/systemd/user/zz.service.d/o.conf"), "[Service]\nExecStart=\nExecStart=/home/u/A\n");

        var entry = Assert.Single(Audit());

        Assert.Equal(vendor, entry.Location);
        Assert.Equal("/home/u/A", entry.ImagePath);
        Assert.Equal([dropIn], entry.DropIns);
    }

    [UnixFact]
    public void An_instance_linked_to_a_template_is_another_name_for_that_one_instance()
    {
        // Re-check: zz@one.service -> w@.service makes w@one.service also zz@one.service, and zz@one.service.d
        // applies to it. Only template-to-template links were taken as aliases of an instance.
        var template = Write(Path.Combine(_root, "usr/lib/systemd/user/w@.service"), "[Service]\nExecStart=/usr/bin/w %i\n");
        Link(Path.Combine(Home, ".config/systemd/user/default.target.wants/w@one.service"), template);
        Link(Path.Combine(Home, ".config/systemd/user/zz@one.service"), template);
        var dropIn = Write(Path.Combine(Home, ".config/systemd/user/zz@one.service.d/o.conf"), "[Service]\nExecStart=\nExecStart=/home/u/B\n");

        var entry = Assert.Single(Audit());

        Assert.Equal(template, entry.Location);
        Assert.Equal("/home/u/B", entry.ImagePath);
        Assert.Equal([dropIn], entry.DropIns);
    }

    [UnixFact]
    public void An_alias_of_an_alias_in_another_directory_is_followed_by_name()
    {
        // zz4.service -> /etc/systemd/user/zz5.service -> q.service: both names are q.service's, and so are their drop-ins.
        var vendor = Write(Path.Combine(_root, "usr/lib/systemd/user/q.service"), "[Service]\nExecStart=/usr/bin/q\n");
        Link(Path.Combine(Home, ".config/systemd/user/default.target.wants/q.service"), vendor);
        Link(Path.Combine(Home, ".config/systemd/user/zz4.service"), Path.Combine(_root, "etc/systemd/user/zz5.service"));
        Link(Path.Combine(_root, "etc/systemd/user/zz5.service"), vendor);
        var dropIn = Write(Path.Combine(Home, ".config/systemd/user/zz4.service.d/o.conf"), "[Service]\nExecStart=\nExecStart=/home/u/G\n");

        var entry = Assert.Single(Audit());

        Assert.Equal("/home/u/G", entry.ImagePath);
        Assert.Equal([dropIn], entry.DropIns);
    }

    [LinuxFact]
    public void Aliases_are_found_by_name_through_the_servers_own_realpath_even_where_a_link_dangles()
    {
        // The name map folds a link's target with realpath(3) on its directory, which is null for a directory that
        // does not exist -- here /etc/systemd/user -- where the managed fake above still answers.
        var vendor = Write(Path.Combine(_root, "usr/lib/systemd/user/x.service"), "[Service]\nExecStart=/usr/bin/x\n");
        Link(Path.Combine(Home, ".config/systemd/user/default.target.wants/x.service"), vendor);
        Link(Path.Combine(Home, ".config/systemd/user/zz.service"), Path.Combine(_root, "etc/systemd/user/x.service"));
        var dropIn = Write(Path.Combine(Home, ".config/systemd/user/zz.service.d/o.conf"), "[Service]\nExecStart=\nExecStart=/home/u/A\n");
        var template = Write(Path.Combine(_root, "usr/lib/systemd/user/w@.service"), "[Service]\nExecStart=/usr/bin/w %i\n");
        Link(Path.Combine(Home, ".config/systemd/user/default.target.wants/w@one.service"), template);
        Link(Path.Combine(Home, ".config/systemd/user/zz@one.service"), "../../../../../usr/lib/systemd/user/w@.service");
        var instanceDropIn = Write(Path.Combine(Home, ".config/systemd/user/zz@one.service.d/o.conf"), "[Service]\nExecStart=\nExecStart=/home/u/B\n");

        var entries = Audit(UserUnits.Reading(_root));

        Assert.Equal([dropIn], entries.Single(e => e.Entry == "x.service").DropIns);
        Assert.Equal("/home/u/A", entries.Single(e => e.Entry == "x.service").ImagePath);
        Assert.Equal([instanceDropIn], entries.Single(e => e.Entry == "w@one.service").DropIns);
        Assert.Equal("/home/u/B", entries.Single(e => e.Entry == "w@one.service").ImagePath);
    }

    [UnixFact]
    public void A_unit_file_linked_in_from_outside_the_search_path_goes_by_the_links_name_alone()
    {
        // ll.service -> /opt/real.service is a linked unit file, not an alias: systemd showed Names=ll.service and no
        // drop-ins, though real.service.d sat in the user's directory. The target's file name was taken as a name.
        var real = Write(Path.Combine(_root, "opt/real.service"), "[Service]\nExecStart=/opt/real\n");
        Link(Path.Combine(Home, ".config/systemd/user/ll.service"), real);
        Link(Path.Combine(Home, ".config/systemd/user/default.target.wants/ll.service"), Path.Combine(Home, ".config/systemd/user/ll.service"));
        Write(Path.Combine(Home, ".config/systemd/user/real.service.d/o.conf"), "[Service]\nExecStart=\nExecStart=/home/u/C\n");

        var entry = Assert.Single(Audit());

        Assert.Equal(real, entry.Location);
        Assert.Equal("/opt/real", entry.ImagePath);
        Assert.Empty(entry.DropIns);
    }

    [UnixFact]
    public void A_dangling_link_for_a_unit_hides_the_packaged_file_of_that_name_rather_than_falling_back_to_it()
    {
        // ~/.config/systemd/user/y.service -> /opt/missing.service: systemd took the first y.service on the path and
        // found it not-found; it never loaded /usr/lib's y.service. The audit skipped the link and reported /usr/bin/y.
        var vendor = Write(Path.Combine(_root, "usr/lib/systemd/user/y.service"), "[Service]\nExecStart=/usr/bin/y\n");
        Link(Path.Combine(Home, ".config/systemd/user/default.target.wants/y.service"), vendor);
        var link = Path.Combine(Home, ".config/systemd/user/y.service");
        Link(link, Path.Combine(_root, "opt/missing.service"));

        var entry = Assert.Single(Audit());

        Assert.Equal(link, entry.Location);
        Assert.Null(entry.ImagePath);
    }

    [UnixTheory]
    [InlineData(".config/environment.d/50-x.conf", "# comment\nLD_PRELOAD=/home/u/evil.so\nPATH=/home/u/bin:$PATH\n", "environment.d/50-x.conf", "every unit")]
    [InlineData(".config/systemd/user.conf", "[Manager]\nDefaultEnvironment=\"LD_PRELOAD=/home/u/evil.so\" PATH=/home/u/bin\n", "user.conf", "every unit")]
    [InlineData(".config/systemd/user.conf.d/o.conf", "[Manager]\nDefaultEnvironment=LD_PRELOAD=/home/u/evil.so 'PATH=/home/u/bin x'\n", "user.conf.d/o.conf", "every unit")]
    [InlineData(".config/systemd/user.conf.d/m.conf", "[Manager]\nManagerEnvironment=LD_PRELOAD=/home/u/evil.so PATH=/x\n", "user.conf.d/m.conf", "the generators it runs")]
    public void A_users_own_environment_for_their_systemd_manager_is_reported_as_unpackaged_input(string relative, string text, string name, string reach)
    {
        // Re-check: the user manager hands ~/.config/environment.d and DefaultEnvironment= in ~/.config/systemd/user.conf
        // to every unit it starts, so LD_PRELOAD there ran the user's code inside every packaged user service --
        // each still Packaged=true, and hidden by unpackagedOnly. The files are reported as entries of their own.
        PackagedSocketEnabledForEveryone();
        var file = Write(Path.Combine(Home, relative), text);

        var entries = Audit();

        var environment = entries.Single(e => e.Entry == name);
        Assert.Equal("u", environment.Profile);
        Assert.Equal(file, environment.Location);
        Assert.Contains("LD_PRELOAD, PATH", environment.Description, StringComparison.Ordinal);
        Assert.Contains(reach, environment.Description, StringComparison.Ordinal);
        Assert.DoesNotContain("evil.so", environment.Description, StringComparison.Ordinal);

        var verified = LinuxAutostartInspector.Verify(environment, _ => null, _ => "md5");
        Assert.False(verified.Packaged);
        Assert.False(LinuxAutostartInspector.Hidden(verified, new AutostartQuery(UnpackagedOnly: true)));
    }

    [UnixTheory]
    [InlineData("[x]\nLD_PRELOAD=/home/u/e.so\n")]
    [InlineData("X\\\nLD_PRELOAD=/home/u/e.so\n")]
    [InlineData("# a comment that ends in a backslash \\\nLD_PRELOAD=/home/u/e.so\n")]
    public void An_environment_d_file_is_read_as_systemd_reads_it_so_no_line_before_a_variable_hides_it(string text)
    {
        // Re-check: environment.d was read as a unit file, so one "[x]" line made everything after it a section's
        // and the file no entry at all -- while systemd's env-file parser, which has no sections, set LD_PRELOAD in
        // every unit. A line ending in a backslash hid the next line the same way.
        Write(Path.Combine(Home, ".config/environment.d/k.conf"), text);

        var entry = Assert.Single(Audit());

        Assert.Contains("sets LD_PRELOAD for every unit", entry.Description, StringComparison.Ordinal);
    }

    [UnixFact]
    public void An_environment_file_that_sets_nothing_or_is_masked_is_not_an_entry()
    {
        PackagedSocketEnabledForEveryone();
        Write(Path.Combine(Home, ".config/environment.d/empty.conf"), "# nothing\n\n");
        Write(Path.Combine(Home, ".config/systemd/user.conf"), "[Manager]\n#DefaultEnvironment=A=1\nDefaultTimeoutStopSec=5s\n");
        // Masked: a link to /dev/null is how a user switches off a system-wide environment.d file of the same name.
        // It sets nothing, and is not someone else's file to report -- the reader opens a device as nothing.
        Link(Path.Combine(Home, ".config/environment.d/50-masked.conf"), "/dev/null");

        var entry = Assert.Single(Audit());

        Assert.Equal("pipewire.socket", entry.Entry);
    }

    [UnprivilegedLinuxFact]
    public void The_servers_own_reader_reads_a_users_own_environment_file_and_never_one_linked_to_roots()
    {
        // The owner is read from the file the server opens, which only the real reader can do: here the test's own
        // account is the user, and /etc/os-release -- root's, with NAME= and VERSION_ID= lines -- is linked in.
        // Unprivileged, because run as root the test's account would own /etc/os-release.
        var user = new PasswdEntry("u", LinuxDiag.Mcp.Linux.Native.LibC.EffectiveUserId(), Home);
        Write(Path.Combine(Home, ".config/environment.d/50-own.conf"), "LD_PRELOAD=/home/u/evil.so\n");
        Link(Path.Combine(Home, ".config/environment.d/60-root.conf"), "/etc/os-release");
        Link(Path.Combine(Home, ".config/environment.d/70-masked.conf"), "/dev/null");

        var entries = UserUnits.Reading(_root).Audit([user], _ => false, []).ToList();

        Assert.Equal(["environment.d/50-own.conf", "environment.d/60-root.conf"], entries.Select(e => e.Entry));
        Assert.Contains("sets LD_PRELOAD for", entries[0].Description, StringComparison.Ordinal);
        Assert.Contains("owned by another account", entries[1].Description, StringComparison.Ordinal);
        Assert.DoesNotContain("NAME", entries[1].Description, StringComparison.Ordinal);
    }

    [UnixFact]
    public void An_environment_file_linked_to_another_accounts_file_is_named_but_its_contents_never_reach_the_caller()
    {
        // Review: environment.d/k.conf -> /root/.ssh/id_ed25519 had the root server read the key, and the base64 line
        // ending in '=' padding came back as a "variable name". The caller may hold no file-read grant at all.
        var key = Write(Path.Combine(_root, "root/.ssh/id_ed25519"),
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\nc2VjcmV0dG9rZW4=\n-----END OPENSSH PRIVATE KEY-----\n");
        var link = Path.Combine(Home, ".config/environment.d/k.conf");
        Link(link, key);

        var entries = Audit();

        var entry = Assert.Single(entries);
        Assert.Equal("environment.d/k.conf", entry.Entry);
        Assert.Equal(link, entry.Location);
        Assert.Contains("owned by another account", entry.Description, StringComparison.Ordinal);
        Assert.All(entries, e => Assert.DoesNotContain("c2VjcmV0dG9rZW4", e.Description, StringComparison.Ordinal));
        Assert.False(LinuxAutostartInspector.Hidden(
            LinuxAutostartInspector.Verify(entry, _ => null, _ => "md5"), new AutostartQuery(UnpackagedOnly: true)));
    }

    [UnixFact]
    public void Only_names_systemd_would_take_as_variables_are_reported_from_a_users_own_file()
    {
        // systemd ignores an assignment whose name is not [A-Za-z_][A-Za-z0-9_]*; reporting such text as a name would
        // pass on whatever the line holds rather than what the manager sets.
        Write(Path.Combine(Home, ".config/environment.d/x.conf"), "GOOD_1=a\n1BAD=b\nA-B=c\nhas space=d\n");
        Write(Path.Combine(Home, ".config/systemd/user.conf"), "[Manager]\nDefaultEnvironment=OK=1 9NO=2 \"x y=3\"\n");

        var entries = Audit();

        Assert.Contains("sets GOOD_1 for", entries.Single(e => e.Entry == "environment.d/x.conf").Description, StringComparison.Ordinal);
        Assert.Contains("sets OK for", entries.Single(e => e.Entry == "user.conf").Description, StringComparison.Ordinal);
    }

    [UnixFact]
    public void A_user_with_only_an_environment_file_and_no_units_of_their_own_is_still_read()
    {
        // The per-user pass skipped every home with no ~/.config/systemd/user, which is where environment.d users are.
        Write(Path.Combine(Home, ".config/environment.d/x.conf"), "LD_PRELOAD=/home/u/evil.so\n");

        var entry = Assert.Single(Audit());

        Assert.Equal("environment.d/x.conf", entry.Entry);
    }

    [UnixFact]
    public void A_socket_enabled_for_everyone_is_not_repeated_for_a_user_whose_files_leave_it_alone()
    {
        PackagedSocketEnabledForEveryone();
        Write(Path.Combine(Home, ".config/systemd/user/other.service.d/o.conf"), "[Service]\nNice=5\n");

        var entry = Assert.Single(Audit());

        Assert.Equal("(every user)", entry.Profile);
    }

    [UnixFact]
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

    [UnixFact]
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

    [UnixFact]
    public void A_socket_with_Accept_runs_the_template_of_its_own_name()
    {
        var socket = Write(Path.Combine(Home, ".config/systemd/user/s.socket"), "[Socket]\nListenStream=%t/s\nAccept=yes\n");
        Link(Path.Combine(Home, ".config/systemd/user/sockets.target.wants/s.socket"), socket);
        Write(Path.Combine(Home, ".config/systemd/user/s@.service"), "[Service]\nExecStart=-/home/u/serve\n");

        var entry = Assert.Single(Audit());

        Assert.Equal("/home/u/serve", entry.ImagePath);
        Assert.Contains("runs s@.service", entry.Description, StringComparison.Ordinal);
    }

    [UnixFact]
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

    [UnixTheory]
    [InlineData("x.service", new[] { "x.service", "service" })]
    [InlineData("a-b-c.service", new[] { "a-b-c.service", "a-b-.service", "a-.service", "service" })]
    [InlineData("w-x@i.service", new[] { "w-x@i.service", "w-x@.service", "w-.service", "service" })]
    [InlineData("-.slice", new[] { "-.slice", "slice" })]
    public void Drop_ins_are_looked_for_under_the_name_its_template_its_dash_prefixes_and_its_type(string name, string[] expected)
    {
        Assert.Equal(expected, UserUnits.DropInNames([name]));
    }

    [UnixFact]
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

    [Fact]
    public void Environment_file_names_are_the_ones_systemds_env_file_parser_sets()
    {
        // Each file was handed to a live systemd 252's environment.d generator; it set exactly A1, A2, A4, A6, A8, A9,
        // A11, A12 and B12. A3 follows a comment ending in a backslash, which 252 still continued onto the next line
        // and 254 and later do not: it is reported, as the newer systemd sets it. "export A7" is pushed by the parser
        // and then refused as a name -- that filter is the caller's. An empty value sets nothing.
        string[] files =
        [
            "[x]\nA1=1\n", "X\\\nA2=1\n", "# c \\\nA3=1\n", "A4=\"x\nB4=y\"\n", "A5=\nA5b=\"\"\n", "  A6 = v\n",
            "export A7=1\n", "A8='a'b\nA9=a\\\nB9=c\n", "A10", "A11=1", "A12=1\r\nB12=2\r\n",
        ];

        Assert.Equal(
            ["A1", "A2", "A3", "A4", "A6", "export A7", "A8", "A9", "A11", "A12", "B12"],
            files.SelectMany(UnitFile.EnvironmentFileKeys));
    }
}
