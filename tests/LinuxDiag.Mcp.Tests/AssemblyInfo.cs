using System.Runtime.Versioning;

// The server assembly is Linux-only, so the analyzer needs its callers to be too. Tests that touch a
// Linux API are [LinuxFact] and skip elsewhere; parser and registration tests touch none, which is why
// they still run -- and must pass -- on Windows.
[assembly: SupportedOSPlatform("linux")]
