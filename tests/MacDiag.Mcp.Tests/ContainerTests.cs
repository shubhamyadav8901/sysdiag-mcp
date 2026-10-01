using System.Collections;
using MacDiag.Mcp.Configuration;
using MacDiag.Mcp.Diagnostics.Containers;
using MacDiag.Mcp.Mac.Parsers;
using MacDiag.Mcp.Tools;
using static MacDiag.Mcp.Tests.StatLinesTests;
using static MacDiag.Mcp.Tests.SystemOverviewTests;

namespace MacDiag.Mcp.Tests;

public sealed class ContainerTests
{
    private const string Alice = "/Users/alice";
    private const string AliceDesktop = "/Users/alice/.docker/run/docker.sock";
    private const string AliceOrb = "/Users/alice/.orbstack/run/docker.sock";
    private const string System = "/var/run/docker.sock";

    /// <summary>A Mac where alice (501) runs Docker Desktop: her socket, and /var/run/docker.sock linked to it.</summary>
    private static Dictionary<string, string> AliceRunsDockerDesktop() => new()
    {
        [System] = Line(System, 0, 1, "0755", "Symbolic Link"),
        ["/"] = Line("/", 0, 0, "0755", "Directory"),
        ["/Users"] = Line("/Users", 0, 80, "0755", "Directory"),
        [Alice] = Line(Alice, 501, 20, "0750", "Directory"),
        ["/Users/alice/.docker"] = Line("/Users/alice/.docker", 501, 20, "0755", "Directory"),
        ["/Users/alice/.docker/run"] = Line("/Users/alice/.docker/run", 501, 20, "0755", "Directory"),
        [AliceDesktop] = Line(AliceDesktop, 501, 20, "0755", "Socket"),
    };

    private sealed class FakeDocker(Func<string, (IReadOnlyList<DockerContainer>, string?)> answer) : IDockerQuery
    {
        public List<string> Asked { get; } = [];

        public Task<(IReadOnlyList<DockerContainer> Containers, string? Limitation)> QueryAsync(string socketPath, CancellationToken cancellationToken)
        {
            Asked.Add(socketPath);
            return Task.FromResult(answer(socketPath));
        }
    }

    private static readonly DockerContainer Web = new("8dfafdbc3a40", "web", "nginx:1.27", "running");

    private sealed class Probe(bool root) : IPrivilegeProbe
    {
        public bool IsElevated => root;
    }

    private static MacContainerInspector Inspector(
        Dictionary<string, string> stats, IDockerQuery docker, string[]? homes = null, Dictionary<string, string>? links = null,
        Func<string, IEnumerable<string>>? directories = null, bool root = true, Func<string, string>? resolve = null) =>
        new(new FakeCommands((_, args) => Answer(stats, args)), MacDiagOptions.FromEnvironment(new Hashtable()), docker, new Probe(root))
        {
            ListHomes = () => homes ?? [Alice],
            ListDirectories = directories ?? (_ => []),
            Resolve = resolve ?? (path => links is not null && links.TryGetValue(path, out var target) ? target : path),
        };

    [Fact]
    public void Candidates_cover_the_system_socket_and_every_homes_docker_desktop_colima_orbstack_and_rancher_sockets()
    {
        var candidates = DockerSockets.Candidates(["/Users/alice", "/Users/bob"], directory =>
            directory == "/Users/bob/.colima" ? ["/Users/bob/.colima/default", "/Users/bob/.colima/work"] : []);

        Assert.Equal(System, candidates[0].Path);
        Assert.Null(candidates[0].Home);
        Assert.Contains(candidates, c => c.Path == AliceDesktop && c.Home == Alice);
        Assert.Contains(candidates, c => c.Path == "/Users/alice/Library/Containers/com.docker.docker/Data/docker.raw.sock");
        Assert.Contains(candidates, c => c.Path == AliceOrb);
        Assert.Contains(candidates, c => c.Path == "/Users/alice/.rd/docker.sock");
        Assert.Contains(candidates, c => c.Path == "/Users/bob/.colima/default/docker.sock" && c.Engine == "Colima (default)");
        Assert.Contains(candidates, c => c.Path == "/Users/bob/.colima/work/docker.sock" && c.Home == "/Users/bob");
    }

    [Fact]
    public void A_socket_with_the_homes_owner_in_directories_only_that_owner_can_change_is_accepted()
    {
        var stats = StatLines.Parse(string.Join('\n', AliceRunsDockerDesktop().Values)).ToDictionary(s => s.Path);

        Assert.Null(DockerSockets.Problem(AliceDesktop, new HashSet<int> { 501 }, stats));
    }

    [Fact]
    public void A_socket_owned_by_another_account_than_the_homes_owner_is_refused()
    {
        var lines = AliceRunsDockerDesktop();
        lines[AliceDesktop] = Line(AliceDesktop, 502, 20, "0755", "Socket");
        var stats = StatLines.Parse(string.Join('\n', lines.Values)).ToDictionary(s => s.Path);

        Assert.Contains("owned by uid 502", DockerSockets.Problem(AliceDesktop, new HashSet<int> { 501 }, stats), StringComparison.Ordinal);
    }

    [Fact]
    public void Something_that_is_not_a_socket_is_refused()
    {
        var lines = AliceRunsDockerDesktop();
        lines[AliceDesktop] = Line(AliceDesktop, 501, 20, "0644", "Regular File");
        var stats = StatLines.Parse(string.Join('\n', lines.Values)).ToDictionary(s => s.Path);

        Assert.Contains("not a socket", DockerSockets.Problem(AliceDesktop, new HashSet<int> { 501 }, stats), StringComparison.Ordinal);
    }

    [Fact]
    public void A_socket_in_a_directory_another_account_can_write_is_refused_because_it_could_be_swapped()
    {
        var lines = AliceRunsDockerDesktop();
        lines["/Users/alice/.docker/run"] = Line("/Users/alice/.docker/run", 501, 20, "0777", "Directory");
        var stats = StatLines.Parse(string.Join('\n', lines.Values)).ToDictionary(s => s.Path);

        Assert.Contains("/Users/alice/.docker/run", DockerSockets.Problem(AliceDesktop, new HashSet<int> { 501 }, stats), StringComparison.Ordinal);
    }

    [Fact]
    public void A_directory_that_could_not_be_checked_refuses_the_socket()
    {
        var lines = AliceRunsDockerDesktop();
        lines.Remove("/Users/alice/.docker");
        var stats = StatLines.Parse(string.Join('\n', lines.Values)).ToDictionary(s => s.Path);

        Assert.Contains("could not be checked", DockerSockets.Problem(AliceDesktop, new HashSet<int> { 501 }, stats), StringComparison.Ordinal);
    }

    [Fact]
    public void The_system_run_directory_that_group_daemon_can_write_is_accepted_for_a_root_socket()
    {
        var lines = new[]
        {
            Line("/", 0, 0, "0755", "Directory"),
            Line("/private", 0, 0, "0755", "Directory"),
            Line("/private/var", 0, 0, "0755", "Directory"),
            Line("/private/var/run", 0, 1, "0775", "Directory"),
            Line("/private/var/run/docker.sock", 0, 1, "0660", "Socket"),
        };
        var stats = StatLines.Parse(string.Join('\n', lines)).ToDictionary(s => s.Path);

        Assert.Null(DockerSockets.Problem("/private/var/run/docker.sock", new HashSet<int> { 0 }, stats));
    }

    [Fact]
    public void Docker_containers_parse_from_the_engines_json_and_a_container_without_an_id_is_an_error()
    {
        var containers = DockerContainers.Parse(Fixture(Unverified, "docker-containers.json"));

        Assert.Equal(3, containers.Count);
        Assert.Equal(("web", "nginx:1.27", "running"), (containers[0].Name, containers[0].Image, containers[0].State));
        Assert.Null(containers[2].Name);
        Assert.Throws<FormatException>(() => DockerContainers.Parse("""[{"Names":["/x"]}]"""));
        Assert.Throws<FormatException>(() => DockerContainers.Parse("""{"message":"page not found"}"""));
    }

    [Fact]
    public async Task A_link_into_a_home_is_followed_and_the_same_daemon_is_asked_once()
    {
        var docker = new FakeDocker(_ => ([Web], null));

        var catalog = await Inspector(AliceRunsDockerDesktop(), docker, links: new() { [System] = AliceDesktop }).ListAsync(CancellationToken.None);

        Assert.Equal([AliceDesktop], docker.Asked);
        var container = Assert.Single(catalog.Containers);
        Assert.Equal(("docker", "Docker Desktop", AliceDesktop, "web"), (container.Runtime, container.Engine, container.Socket, container.Name));
        Assert.Null(container.MainProcessId);
    }

    [Fact]
    public async Task A_link_pointing_outside_every_home_is_never_asked_and_is_named()
    {
        var lines = AliceRunsDockerDesktop();
        lines.Remove(AliceDesktop);
        var docker = new FakeDocker(_ => ([Web], null));

        var catalog = await Inspector(lines, docker, links: new() { [System] = "/tmp/evil.sock" }).ListAsync(CancellationToken.None);

        Assert.Empty(docker.Asked);
        Assert.Contains(catalog.Limitations, l => l.Contains(System, StringComparison.Ordinal) && l.Contains("/tmp/evil.sock", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_refused_socket_is_never_asked_and_the_refusal_is_a_limitation()
    {
        var lines = AliceRunsDockerDesktop();
        lines[AliceDesktop] = Line(AliceDesktop, 502, 20, "0755", "Socket");
        var docker = new FakeDocker(_ => ([Web], null));

        var catalog = await Inspector(lines, docker).ListAsync(CancellationToken.None);

        Assert.Empty(docker.Asked);
        Assert.Empty(catalog.Containers);
        Assert.Contains(catalog.Limitations, l => l.Contains(AliceDesktop, StringComparison.Ordinal) && l.Contains("uid 502", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Two_engines_reporting_the_same_container_list_it_once_and_listing_any_names_the_virtual_machine()
    {
        var lines = AliceRunsDockerDesktop();
        lines["/Users/alice/.orbstack"] = Line("/Users/alice/.orbstack", 501, 20, "0755", "Directory");
        lines["/Users/alice/.orbstack/run"] = Line("/Users/alice/.orbstack/run", 501, 20, "0755", "Directory");
        lines[AliceOrb] = Line(AliceOrb, 501, 20, "0755", "Socket");
        var db = new DockerContainer("1b2c3d4e5f60", "db", "postgres:16", "exited");
        var docker = new FakeDocker(socket => socket == AliceOrb ? ([Web, db], null) : ([Web], null));

        var catalog = await Inspector(lines, docker).ListAsync(CancellationToken.None);

        Assert.Equal(2, docker.Asked.Count);
        Assert.Equal(["db", "web"], catalog.Containers.Select(c => c.Name));
        Assert.Contains(catalog.Limitations, l => l.Contains("virtual machine", StringComparison.Ordinal));
    }

    [Fact]
    public async Task No_engine_at_all_is_an_empty_list_with_no_limitation()
    {
        var docker = new FakeDocker(_ => throw new InvalidOperationException("asked"));

        var catalog = await Inspector(new Dictionary<string, string> { [Alice] = Line(Alice, 501, 20, "0750", "Directory") }, docker)
            .ListAsync(CancellationToken.None);

        Assert.Empty(catalog.Containers);
        Assert.Empty(catalog.Limitations);
    }

    [Fact]
    public async Task A_colima_profile_whose_name_has_a_control_character_is_never_statted_and_is_named()
    {
        var commands = new List<IReadOnlyList<string>>();
        var docker = new FakeDocker(_ => ([], null));
        var inspector = new MacContainerInspector(
            new FakeCommands((_, args) =>
            {
                commands.Add(args);
                return Answer(AliceRunsDockerDesktop(), args);
            }),
            MacDiagOptions.FromEnvironment(new Hashtable()), docker, new Probe(true))
        {
            ListHomes = () => [Alice],
            ListDirectories = directory => directory == "/Users/alice/.colima" ? ["/Users/alice/.colima/x\n0\t0\t0755"] : [],
            Resolve = path => path,
        };

        var catalog = await inspector.ListAsync(CancellationToken.None);

        Assert.DoesNotContain(commands.SelectMany(a => a), a => a.Contains('\n', StringComparison.Ordinal));
        Assert.Contains(catalog.Limitations, l => l.Contains("control character", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_link_that_loops_is_a_limitation_not_a_failed_call()
    {
        var docker = new FakeDocker(_ => ([Web], null));

        var catalog = await Inspector(AliceRunsDockerDesktop(), docker,
            resolve: path => path == System ? throw new IOException("Too many levels of symbolic links") : path).ListAsync(CancellationToken.None);

        Assert.Contains(catalog.Limitations, l => l.Contains(System, StringComparison.Ordinal) && l.Contains("Too many levels", StringComparison.Ordinal));
        Assert.Equal([AliceDesktop], docker.Asked);
    }

    [Fact]
    public void A_container_name_that_is_not_a_string_is_left_out_rather_than_failing_the_list()
    {
        var container = Assert.Single(DockerContainers.Parse("""[{"Id":"x","Names":[1],"Image":"busybox"}]"""));

        Assert.Equal(("x", null, "busybox"), (container.Id, container.Name, container.Image));
        Assert.Throws<FormatException>(() => DockerContainers.Parse("[1]"));
    }

    [Fact]
    public async Task Without_root_the_list_says_other_users_engines_may_be_unseen()
    {
        var catalog = await Inspector(new Dictionary<string, string>(), new FakeDocker(_ => ([], null)), root: false).ListAsync(CancellationToken.None);

        Assert.Contains(catalog.Limitations, l => l.Contains("root", StringComparison.Ordinal));
    }

    [Fact]
    public void The_tool_filters_on_name_image_and_id_and_caps_the_rows()
    {
        ContainerInfo Row(string name, string image, string id) => new("docker", "Docker Desktop", AliceDesktop, id, name, image, "running", null);
        var all = new[] { Row("web", "nginx:1.27", "aaa111"), Row("db", "postgres:16", "bbb222"), Row("cache", "redis:7", "ccc333") };

        Assert.Equal(["db"], ContainerTools.Build(all, [], "postgres", 50).Containers.Select(c => c.Name));
        Assert.Equal(["cache"], ContainerTools.Build(all, [], "CCC3", 50).Containers.Select(c => c.Name));
        var capped = ContainerTools.Build(all, [], null, 2);
        Assert.Equal((2, 3, true), (capped.Containers.Count, capped.TotalMatched, capped.Truncated));
    }

    [Fact]
    public void An_empty_list_with_limitations_says_it_is_not_proof_there_are_none()
    {
        var summary = ContainerTools.RenderContainers([], ["Not asking /x: it is owned by uid 502."], null);

        Assert.Contains("WARNING: Not asking /x", summary, StringComparison.Ordinal);
        Assert.Contains("not proof", summary, StringComparison.Ordinal);
    }
}
