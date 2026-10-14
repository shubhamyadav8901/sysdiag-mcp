using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;

namespace WinDiag.Mcp.Hosting;

/// <summary>The accounts and groups the local Administrators group lists as its own members.</summary>
/// <remarks>
/// <para>For judging the directories above a server or artifact directory, which windiag never changes.
/// One owned by an individual administrator -- the built-in Administrator on Windows Server, whose objects
/// are owned by that account and not the group under the default "Object creator" policy -- is that
/// administrator's to have made, and refusing it stranded the target after update_self with no way to
/// repair it from the service.</para>
/// <para>Direct members only. Expanding a domain group such as Domain Admins needs a domain controller,
/// and the service checks this on every start, when the network may not be up; a member reached only
/// through such a group reads as untrusted, and the refusal says how to hand the directory to the
/// group.</para>
/// </remarks>
[SupportedOSPlatform("windows")]
internal static class LocalAdministrators
{
    private const int MaxPreferredLength = -1;

    /// <summary>The group's direct members; empty if they cannot be read, so nothing more is trusted than before.</summary>
    public static IReadOnlyCollection<SecurityIdentifier> Members()
    {
        try
        {
            // By name, which is localised -- Administratoren, Administrateurs -- so looked up from the SID.
            var name = ProtectedAcl.Administrators.Translate(typeof(NTAccount)).Value;
            return Members(name[(name.IndexOf('\\', StringComparison.Ordinal) + 1)..]);
        }
        catch (SystemException)
        {
            // Unmapped, or the lookup failed: the directories above are then judged as before, and one an
            // individual administrator owns is refused with how to hand it to the group.
            return [];
        }
    }

    private static List<SecurityIdentifier> Members(string group)
    {
        var status = NetLocalGroupGetMembers(null, group, 0, out var buffer, MaxPreferredLength, out var read, out _, IntPtr.Zero);
        try
        {
            if (status != 0)
            {
                throw new Win32Exception(status);
            }

            var members = new List<SecurityIdentifier>(read);
            for (var i = 0; i < read; i++)
            {
                // LOCALGROUP_MEMBERS_INFO_0: one PSID each.
                members.Add(new SecurityIdentifier(Marshal.ReadIntPtr(buffer, i * IntPtr.Size)));
            }

            return members;
        }
        finally
        {
            if (buffer != IntPtr.Zero)
            {
                _ = NetApiBufferFree(buffer);
            }
        }
    }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetLocalGroupGetMembers(
        string? serverName, string groupName, int level, out IntPtr buffer, int preferredMaximumLength,
        out int entriesRead, out int totalEntries, IntPtr resumeHandle);

    [DllImport("netapi32.dll")]
    private static extern int NetApiBufferFree(IntPtr buffer);
}
