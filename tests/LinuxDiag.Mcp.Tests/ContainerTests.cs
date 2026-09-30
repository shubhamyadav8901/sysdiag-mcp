using System.Diagnostics;
using System.Net.Sockets;
using LinuxDiag.Mcp.Diagnostics.Containers;
using LinuxDiag.Mcp.Diagnostics.Processes;
using LinuxDiag.Mcp.Linux.Parsers;
using LinuxDiag.Mcp.Tools;

namespace LinuxDiag.Mcp.Tests;

public sealed class ContainerTests
{
    private const string Id = "5e8adee615fb5940921b8d3b75f357a0ff9d84515283e9359c02b34f44671f9e";

    // Trimmed from `curl --unix-socket /var/run/docker.sock http://localhost/containers/json?all=1` in WSL.
    private const string DockerJson =
        "[{\"Id\":\"" + Id + "\",\"Names\":[\"/ld-cap\"],\"Image\":\"busybox\",\"ImageID\":\"sha256:fd7d\"," +
        "\"Command\":\"sleep 600\",\"Created\":1790774065,\"Ports\":[],\"Labels\":{},\"State\":\"running\"," +
        "\"Status\":\"Up Less than a second\",\"HostConfig\":{\"NetworkMode\":\"bridge\"},\"Mounts\":[]}]";

    // Written from containerd's CRI annotation keys (pkg/cri/annotations), not captured: WSL has no
    // Kubernetes, so there is no CRI-created task to copy from.
    private const string CriConfig =
        "{\"ociVersion\":\"1.1.0\",\"annotations\":{" +
        "\"io.kubernetes.cri.container-type\":\"container\"," +
        "\"io.kubernetes.cri.container-name\":\"web\"," +
        "\"io.kubernetes.cri.image-name\":\"docker.io/library/nginx:1.27\"," +
        "\"io.kubernetes.cri.sandbox-name\":\"web-7d9f\"," +
        "\"io.kubernetes.cri.sandbox-namespace\":\"shop\"}}";

    private static ProcessRecord Process(int pid, ContainerReference? container, int? innermost) =>
        new(pid, 1, "sleep", "S", false, 100, DateTimeOffset.UnixEpoch, 0, 1, 0, null, "sleep 600", false,
            "/", container, innermost, "net:[1]", "mnt:[1]");

    [Fact]
    public void Containers_past_the_row_cap_are_counted_and_the_summary_says_how_to_see_the_rest()
    {
        var all = Enumerable.Range(1, 3)
            .Select(i => new ContainerInfo("docker", $"id{i}", $"c{i}", "busybox", "running", i, [i], null, null, false))
            .ToList();

        var result = ContainerTools.Build(all, [], null, maxResults: 2);

        Assert.Equal(2, result.Containers.Count);
        Assert.Equal(3, result.TotalMatched);
        Assert.True(result.Truncated);
        Assert.Contains("LINUXDIAG_MAX_RESULTS", result.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public void Docker_list_gives_id_name_image_and_state()
    {
        var container = Assert.Single(DockerContainers.Parse(DockerJson));

        Assert.Equal(new DockerContainer(Id, "ld-cap", "busybox", "running"), container);
        Assert.Throws<FormatException>(() => DockerContainers.Parse("{\"message\":\"page not found\"}"));
        Assert.Throws<FormatException>(() => DockerContainers.Parse("not json"));
    }

    [Fact]
    public void A_cri_task_gives_the_pod_and_marks_a_sandbox()
    {
        var task = ContainerdTask.Parse("k8s.io", "f00", CriConfig, "4242\n");
        var sandbox = ContainerdTask.Parse("k8s.io", "f01",
            "{\"annotations\":{\"io.kubernetes.cri.container-type\":\"sandbox\"}}", null);

        Assert.Equal(new ContainerdTaskEntry("k8s.io", "f00", "web", "docker.io/library/nginx:1.27", "web-7d9f", "shop", false, 4242), task);
        Assert.True(sandbox.Sandbox);
        Assert.Null(sandbox.InitProcessId);
    }

    [Fact]
    public void The_main_pid_is_the_containers_innermost_pid_1_and_containerd_init_pid_is_the_fallback()
    {
        var docker = new List<DockerContainer> { new(Id, "ld-cap", "busybox", "running") };
        var tasks = new List<ContainerdTaskEntry>
        {
            new("k8s.io", "f00", "web", "nginx", "web-7d9f", "shop", false, 4242),
            new("k8s.io", Id, "dup", "dup", null, null, false, 1), // the same container seen twice: Docker's entry wins
        };
        var table = new ProcessTable(
            [Process(771, new("docker", Id), 1), Process(772, new("docker", Id), 7), Process(900, null, null)], 0);

        var joined = LinuxContainerInspector.Join(docker, tasks, table);

        Assert.Equal(2, joined.Count);
        Assert.Equal(771, joined.Single(c => c.Id == Id).MainProcessId);
        Assert.Equal([771, 772], joined.Single(c => c.Id == Id).ProcessIds);
        Assert.Equal("docker", joined.Single(c => c.Id == Id).Runtime);
        Assert.Equal(4242, joined.Single(c => c.Id == "f00").MainProcessId);
    }

    [Fact]
    public void A_container_sharing_the_hosts_pid_namespace_has_no_main_pid_and_the_summary_says_why()
    {
        var joined = LinuxContainerInspector.Join(
            [new DockerContainer(Id, "hostpid", "busybox", "running")], [],
            new ProcessTable([Process(771, new("docker", Id), innermost: null)], 0));

        Assert.Null(Assert.Single(joined).MainProcessId);
        Assert.Contains("main PID unknown", ContainerTools.RenderContainers(joined, [], null), StringComparison.Ordinal);
    }

    [Fact]
    public void An_empty_list_with_an_unreachable_runtime_says_it_is_not_proof_of_none()
    {
        var summary = ContainerTools.RenderContainers([], ["Docker did not answer."], null);

        Assert.Contains("WARNING: Docker did not answer.", summary, StringComparison.Ordinal);
        Assert.Contains("not proof", summary, StringComparison.Ordinal);
    }

    [Fact]
    public void A_process_in_a_catalogued_container_gets_its_name_and_image()
    {
        var catalog = new ContainerCatalog([new ContainerInfo("docker", Id, "ld-cap", "busybox", "running", 771, [771], null, null, false)], []);

        var tagged = ContainerJoin.For(Process(771, new("docker", Id), 1), ContainerJoin.ById(catalog));
        var unknown = ContainerJoin.For(Process(5, new("kubernetes", new string('e', 64)), 3), ContainerJoin.ById(catalog));

        Assert.Equal(new ProcessContainer("docker", Id, "ld-cap", "busybox", 1), tagged);
        Assert.Equal(new ProcessContainer("kubernetes", new string('e', 64), null, null, 3), unknown);
        Assert.Null(ContainerJoin.For(Process(9, null, null), ContainerJoin.ById(catalog)));
    }

    [Fact]
    public void Every_captured_docker_list_parses()
    {
        foreach (var distro in ProcParserTests.Distros())
        {
            if (ProcParserTests.Fixture(distro, "docker-containers.json") is { } json)
            {
                Assert.NotEmpty(DockerContainers.Parse(json));
            }
        }
    }

    [Fact]
    public void The_docker_socket_is_given_five_seconds_by_default()
    {
        // The README promises it; update_self waits for in-flight calls, so the bound is what keeps a hung dockerd
        // from stalling a deploy.
        Assert.Equal(TimeSpan.FromSeconds(5), new DockerEngineClient().Budget);
    }

    [LinuxFact]
    public async Task A_redirect_is_not_followed_and_a_proxy_is_never_used()
    {
        // A 3xx would be a second request to a root-equivalent socket, and a proxy from the environment must not
        // change what is sent: the request line stays origin-form, never "GET http://docker/...".
        var path = Path.Combine(Path.GetTempPath(), $"ld-redirect-{Guid.NewGuid():N}.sock");
        using var listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        listener.Bind(new UnixDomainSocketEndPoint(path));
        listener.Listen();
        var previous = HttpClient.DefaultProxy;
        HttpClient.DefaultProxy = new System.Net.WebProxy("http://127.0.0.1:9");
        try
        {
            var served = Task.Run(async () =>
            {
                using var connection = await listener.AcceptAsync();
                var buffer = new byte[4096];
                var request = new System.Text.StringBuilder();
                while (!request.ToString().Contains("\r\n\r\n", StringComparison.Ordinal))
                {
                    var read = await connection.ReceiveAsync(buffer, SocketFlags.None);
                    if (read == 0) break;
                    request.Append(System.Text.Encoding.ASCII.GetString(buffer, 0, read));
                }

                await connection.SendAsync(System.Text.Encoding.ASCII.GetBytes(
                    "HTTP/1.1 307 Temporary Redirect\r\nLocation: /somewhere/else\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"), SocketFlags.None);
                return request.ToString().Split("\r\n")[0];
            });

            var (containers, limitation) = await new DockerEngineClient(path, TimeSpan.FromSeconds(5))
                .ListAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(10));

            Assert.Equal("GET " + DockerEngineClient.ListRequest + " HTTP/1.1", await served.WaitAsync(TimeSpan.FromSeconds(5)));
            Assert.Empty(containers);
            Assert.Contains("answered 307", limitation, StringComparison.Ordinal);
        }
        finally
        {
            HttpClient.DefaultProxy = previous;
            File.Delete(path);
        }
    }

    [LinuxFact]
    public async Task A_daemon_that_accepts_and_never_answers_is_a_limitation_within_the_budget_not_a_hang()
    {
        // Review Focus 4: update_self waits for in-flight calls, so a hung dockerd must not hang a tool.
        var path = Path.Combine(Path.GetTempPath(), $"ld-hung-{Guid.NewGuid():N}.sock");
        using var listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        listener.Bind(new UnixDomainSocketEndPoint(path));
        listener.Listen();
        try
        {
            var watch = Stopwatch.StartNew();
            // WaitAsync so a regression fails the test instead of hanging the run: xUnit 2 has no default timeout.
            var (containers, limitation) = await new DockerEngineClient(path, TimeSpan.FromMilliseconds(300))
                .ListAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5));

            Assert.True(watch.Elapsed < TimeSpan.FromSeconds(5), $"took {watch.Elapsed}");
            Assert.Empty(containers);
            Assert.Contains("did not answer", limitation, StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [DockerFact]
    public async Task A_started_container_is_listed_with_its_host_main_pid()
    {
        var id = Docker("run -d busybox sleep 120");
        try
        {
            var hostPid = int.Parse(Docker($"inspect -f {{{{.State.Pid}}}} {id}"), System.Globalization.CultureInfo.InvariantCulture);
            var catalog = await new LinuxContainerInspector()
                .ListAsync(new LinuxProcessTable().Read(CancellationToken.None), CancellationToken.None);

            var container = Assert.Single(catalog.Containers, c => c.Id == id);
            Assert.Equal("docker", container.Runtime);
            Assert.Equal("busybox", container.Image);
            Assert.Equal(hostPid, container.MainProcessId);
        }
        finally
        {
            Docker($"rm -f {id}");
        }
    }

    internal static string Docker(string arguments)
    {
        using var docker = System.Diagnostics.Process.Start(new ProcessStartInfo("docker", arguments)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        })!;
        var output = docker.StandardOutput.ReadToEnd();
        docker.WaitForExit();
        Assert.True(docker.ExitCode == 0, $"docker {arguments} exited {docker.ExitCode}: {docker.StandardError.ReadToEnd()}");
        return output.Trim();
    }
}
