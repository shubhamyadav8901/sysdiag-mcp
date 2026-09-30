using System.Buffers.Binary;
using LinuxDiag.Mcp.Linux.Parsers;

namespace LinuxDiag.Mcp.Tests;

public sealed class AccessFormatTests
{
    internal const uint Undefined = uint.MaxValue;

    /// <summary>An ACL in the kernel's xattr form: version 2, then (tag u16, perm u16, id u32) per entry.</summary>
    internal static byte[] Acl(params (ushort Tag, ushort Permissions, uint Id)[] entries)
    {
        var blob = new byte[4 + (8 * entries.Length)];
        BinaryPrimitives.WriteUInt32LittleEndian(blob, 2);
        for (var i = 0; i < entries.Length; i++)
        {
            var at = blob.AsSpan(4 + (8 * i));
            BinaryPrimitives.WriteUInt16LittleEndian(at, entries[i].Tag);
            BinaryPrimitives.WriteUInt16LittleEndian(at[2..], entries[i].Permissions);
            BinaryPrimitives.WriteUInt32LittleEndian(at[4..], entries[i].Id);
        }

        return blob;
    }

    [Fact]
    public void An_acl_parses_to_tagged_entries_and_renders_as_getfacl_would_with_the_mask_applied()
    {
        var acl = PosixAcl.Parse(Acl((0x01, 6, Undefined), (0x02, 7, 1000), (0x04, 4, Undefined), (0x08, 6, 4), (0x10, 5, Undefined), (0x20, 0, Undefined)));

        Assert.Equal(new AclEntry(AclTag.User, 1000, 7), acl[1]);
        Assert.Null(acl[0].Id);
        Assert.Equal(
            ["user::rw-", "user:alice:rwx  #effective:r-x", "group::r--", "group:adm:rw-  #effective:r--", "mask::r-x", "other::---"],
            PosixAcl.Describe(acl, uid => uid == 1000 ? "alice" : null, gid => gid == 4 ? "adm" : null));
    }

    [Theory]
    [InlineData(new byte[] { 1, 0, 0, 0 })]
    [InlineData(new byte[] { 2, 0, 0, 0, 1, 0 })]
    [InlineData(new byte[] { 2, 0, 0, 0, 0x40, 0, 7, 0, 0, 0, 0, 0 })]
    public void A_wrong_version_a_torn_entry_or_an_unknown_tag_is_a_format_error(byte[] blob)
    {
        Assert.Throws<FormatException>(() => PosixAcl.Parse(blob));
    }

    [Fact]
    public void File_capabilities_parse_in_both_the_v2_and_the_namespaced_v3_forms()
    {
        var v2 = new byte[20];
        BinaryPrimitives.WriteUInt32LittleEndian(v2, 0x02000001);
        BinaryPrimitives.WriteUInt32LittleEndian(v2.AsSpan(4), 1u << 13);
        var v3 = new byte[24];
        BinaryPrimitives.WriteUInt32LittleEndian(v3, 0x03000000);
        BinaryPrimitives.WriteUInt32LittleEndian(v3.AsSpan(4), 1u << 21);
        BinaryPrimitives.WriteUInt32LittleEndian(v3.AsSpan(12), 1u << 6);
        BinaryPrimitives.WriteUInt32LittleEndian(v3.AsSpan(20), 100000);

        var ping = FileCapabilities.Parse(v2);
        var namespaced = FileCapabilities.Parse(v3);

        Assert.Equal(["cap_net_raw"], ping.Permitted);
        Assert.True(ping.Effective);
        Assert.Equal("cap_net_raw=ep", FileCapabilities.Describe(ping));
        Assert.Equal(["cap_sys_admin", "cap_perfmon"], namespaced.Permitted);
        Assert.Equal(100000u, namespaced.RootId);
        Assert.Equal("cap_sys_admin,cap_perfmon=p [rootid=100000]", FileCapabilities.Describe(namespaced));
        Assert.Throws<FormatException>(() => FileCapabilities.Parse(new byte[] { 0, 0, 0, 0x07 }));
    }

    [Fact]
    public void A_captured_ping_capability_parses_where_the_distro_has_one()
    {
        foreach (var distro in ProcParserTests.Distros())
        {
            if (ProcParserTests.Fixture(distro, "xattr-capability-ping.hex") is { } hex)
            {
                Assert.Contains("cap_net_raw", FileCapabilities.Parse(Convert.FromHexString(hex.Trim())).Permitted);
            }
        }
    }

    [Fact]
    public void Mountinfo_gives_each_mount_point_unescaped_with_per_mount_and_superblock_options_merged()
    {
        // From proc(5), plus a read-only superblock under a read-write mount and an escaped space.
        var mounts = MountInfo.Parse(
            "22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n" +
            "36 22 98:0 /mnt1 /mnt/parent rw,noatime master:1 - ext3 /dev/root rw,errors=continue\n" +
            "37 22 98:1 / /mnt/my\\040disk rw,noexec - vfat /dev/sdb1 ro\n" +
            "garbage line\n");

        Assert.Equal(3, mounts.Count);
        Assert.Equal("/mnt/my disk", mounts[2].MountPoint);
        Assert.True(mounts[2].ReadOnly);
        Assert.True(mounts[2].NoExec);
        Assert.False(mounts[1].ReadOnly);
        Assert.Equal("/mnt/parent", MountInfo.Containing(mounts, "/mnt/parent/x/y")!.MountPoint);
        Assert.Equal("/", MountInfo.Containing(mounts, "/mnt/parentx")!.MountPoint);
        Assert.Equal("/mnt/my disk", MountInfo.Containing(mounts, "/mnt/my disk")!.MountPoint);
    }

    [Fact]
    public void Credentials_use_the_filesystem_uid_and_gid_not_the_real_ones()
    {
        var credentials = ProcCredentials.Parse("Name:\tx\nUid:\t1000\t0\t0\t33\nGid:\t1000\t1000\t1000\t44\nGroups:\t4 27 \nCapEff:\t0000000000000004\n");

        Assert.Equal(33u, credentials.FsUserId);
        Assert.Equal(44u, credentials.FsGroupId);
        Assert.Equal([4u, 27u], credentials.Groups);
        Assert.True(credentials.Has(2));
        Assert.False(credentials.Has(1));
        Assert.Throws<FormatException>(() => ProcCredentials.Parse("Name:\tx\n"));
    }

    [Fact]
    public void Every_captured_distro_parses()
    {
        foreach (var distro in ProcParserTests.Distros())
        {
            var mounts = MountInfo.Parse(ProcParserTests.Fixture(distro, "pid-mountinfo")!);
            Assert.Contains(mounts, m => m.MountPoint == "/");
            var status = ProcParserTests.Fixture(distro, "pid-status")!;
            var uidLine = status.Split('\n').Single(l => l.StartsWith("Uid:", StringComparison.Ordinal));
            Assert.Equal(uint.Parse(uidLine.Split('\t', StringSplitOptions.RemoveEmptyEntries)[4], System.Globalization.CultureInfo.InvariantCulture),
                ProcCredentials.Parse(status).FsUserId);
        }
    }
}
