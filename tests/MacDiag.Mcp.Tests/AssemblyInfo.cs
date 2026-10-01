using System.Runtime.Versioning;

// The server assembly is macOS-only. Tests that touch a macOS API are [MacFact]; parser and registration
// tests touch none, so they run -- and must pass -- on Windows and Linux too.
[assembly: SupportedOSPlatform("macos")]
