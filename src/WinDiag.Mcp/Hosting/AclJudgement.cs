using System.Security.AccessControl;

namespace WinDiag.Mcp.Hosting;

/// <summary>
/// Who, besides the accounts trusted, owns an object or holds rights over it: the decision
/// <see cref="ProtectedAcl.Exposures"/> makes, on an owner and a DACL given as plain data.
/// </summary>
/// <remarks>
/// <para>Apart from the Windows types that read a descriptor off a handle so it runs anywhere, and can be
/// tested against the ACLs Windows actually ships -- a volume root's, C:\Users', C:\ProgramData's,
/// C:\Program Files' -- rather than against ones made up to match the rule. Every test of the rule had been
/// built from .NET's own ACL objects, so none of them saw that the TrustedInstaller SID written here was not
/// the one that owns C:\, and every service on a real machine refused to start.</para>
/// <para>tools/windiag-acl.ps1 makes the same decision in PowerShell, on the same raw ACEs, with the same SIDs
/// and masks; a test reads them out of the script to keep the two from drifting.</para>
/// </remarks>
internal static class AclJudgement
{
    public const string LocalSystemSid = "S-1-5-18";

    public const string AdministratorsSid = "S-1-5-32-544";

    /// <summary>
    /// NT SERVICE\TrustedInstaller, which owns C:\, Program Files and System32: the OS's own servicing account,
    /// which can already replace the OS itself, so trusting it adds nothing to what an administrator could do.
    /// </summary>
    /// <remarks>
    /// A service SID is S-1-5-80- followed by the SHA-1 of the service's upper-cased name in UTF-16LE, read as
    /// five little-endian 32-bit numbers, so this one is the same on every Windows machine. A test derives it
    /// that way; a digit wrong here distrusts the owner of every drive root.
    /// </remarks>
    public const string TrustedInstallerSid = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

    /// <summary>
    /// CREATOR OWNER only ever describes what a future child's creator gets: no token carries it, so an ACE for
    /// it grants nothing on the object itself, and that creator needed rights here to make the child at all.
    /// </summary>
    public const string CreatorOwnerSid = "S-1-3-0";

    /// <summary>Everyone, who holds every right on an object with no DACL at all.</summary>
    public const string EveryoneSid = "S-1-1-0";

    /// <summary>SYSTEM, Administrators and TrustedInstaller: who may always own or change windiag's directories and what is above them.</summary>
    public static readonly IReadOnlyList<string> AlwaysTrusted = [LocalSystemSid, AdministratorsSid, TrustedInstallerSid];

    /// <summary>One ACE of a DACL, as it is stored.</summary>
    /// <param name="Sid">Whom it names, as S-1-....</param>
    /// <param name="Mask">The access mask, generic rights included as stored.</param>
    /// <param name="Flags">Its inheritance flags; <see cref="AceFlags.InheritOnly"/> is the one that matters here.</param>
    /// <param name="Allows">An allow ACE, rather than a deny or an audit one.</param>
    public readonly record struct Ace(string Sid, int Mask, AceFlags Flags = AceFlags.None, bool Allows = true);

    /// <summary>Someone untrusted who can act on the object: by owning it, or through an ACE.</summary>
    public readonly record struct Holder(string Sid, bool Owns);

    /// <summary>
    /// Everyone not in <paramref name="trusted"/> who owns the object -- an owner can rewrite the DACL whatever
    /// it says -- or holds any of <paramref name="rights"/> through an allow ACE that applies to the object
    /// itself; the owner first, each account once.
    /// </summary>
    /// <param name="owner">The owner's SID, or null when the descriptor has none.</param>
    /// <param name="dacl">The DACL's ACEs in order, or null for no DACL, which lets everyone do anything.</param>
    /// <param name="rights">The rights that count.</param>
    /// <param name="trusted">The SIDs that count as nobody else.</param>
    /// <remarks>
    /// <para>An inherit-only ACE is ignored however much it grants: it describes what children get, not what
    /// anyone may do to this object. A volume root's "Authenticated Users: Modify", subfolders and files only,
    /// carries DELETE, and counting it would read C:\ as anybody's to rename.</para>
    /// <para>Deny ACEs are ignored too. One could narrow an allow in principle, but counting on one would make
    /// this an access-check reimplementation, and the cost of being conservative is a refusal that names the
    /// ACE, not a hole.</para>
    /// </remarks>
    public static IReadOnlyList<Holder> Holders(string? owner, IReadOnlyList<Ace>? dacl, int rights, IReadOnlySet<string> trusted)
    {
        ArgumentNullException.ThrowIfNull(trusted);

        var found = new List<Holder>();
        if (owner is not null && !trusted.Contains(owner))
        {
            found.Add(new Holder(owner, Owns: true));
        }

        if (dacl is null)
        {
            if (!trusted.Contains(EveryoneSid))
            {
                found.Add(new Holder(EveryoneSid, Owns: false));
            }

            return found;
        }

        foreach (var ace in dacl)
        {
            if (!ace.Allows
                || ace.Flags.HasFlag(AceFlags.InheritOnly)
                || string.Equals(ace.Sid, CreatorOwnerSid, StringComparison.OrdinalIgnoreCase)
                || trusted.Contains(ace.Sid)
                || (ace.Mask & rights) == 0)
            {
                continue;
            }

            var holder = new Holder(ace.Sid, Owns: false);
            if (!found.Contains(holder))
            {
                found.Add(holder);
            }
        }

        return found;
    }

    /// <summary>A set of SIDs compared as Windows compares their string forms, ignoring case.</summary>
    public static IReadOnlySet<string> Sids(IEnumerable<string> sids) => sids.ToHashSet(StringComparer.OrdinalIgnoreCase);
}
