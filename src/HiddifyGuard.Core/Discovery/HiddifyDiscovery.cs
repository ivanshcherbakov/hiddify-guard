using System.ComponentModel;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Microsoft.Win32;
using HiddifyGuard.Core.Native;
using HiddifyGuard.Core.Policy;
using HiddifyGuard.Core.Storage;

namespace HiddifyGuard.Core.Discovery;

public static class HiddifyDiscovery
{
    private const int ProprietaryVirtualInterface = 53; // IF_TYPE_PROP_VIRTUAL, used by Wintun.
    private static readonly string[] BinaryNames = ["Hiddify.exe", "HiddifyCli.exe", "sing-box.exe"];
    public static bool ValidateSavedPaths(GuardSettings settings) => settings.HiddifyDirectory is null ||
        File.Exists(Path.Combine(settings.HiddifyDirectory, "Hiddify.exe"));
    public static DiscoverySnapshot Scan(GuardSettings settings)
    {
        var runningDirectories = new List<string>();
        var running = false;
        foreach (var name in new[] { "Hiddify", "HiddifyCli" })
            foreach (var process in Process.GetProcessesByName(name))
                using (process)
                {
                    running = true;
                    try
                    {
                        if (process.MainModule?.FileName is { } path)
                            runningDirectories.Add(Path.GetDirectoryName(path)!);
                    }
                    catch (Exception error) when (error is Win32Exception or InvalidOperationException or NotSupportedException) { }
                }

        var candidates = settings.HiddifyDirectory is { } configured
            ? [configured] : runningDirectories.Concat(InstallDirectories());
        var directory = candidates.Distinct(StringComparer.OrdinalIgnoreCase)
            .FirstOrDefault(path => File.Exists(Path.Combine(path, "Hiddify.exe")));
        var apps = directory is null ? [] : BinaryNames.Select(name => Path.Combine(directory, name))
            .Where(File.Exists).Select(Path.GetFullPath).ToArray();
        var tun = new List<TunBinding>();
        var lan = new List<IpNetwork>();
        var tunUp = false;
        foreach (var adapter in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (adapter.OperationalStatus != OperationalStatus.Up) continue;
            var description = adapter.Name + " " + adapter.Description;
            var hiddifyNamed = description.Contains("hiddify", StringComparison.OrdinalIgnoreCase);
            var tunCandidate = IsTunCandidate(adapter.NetworkInterfaceType, description);
            ulong luid = 0;
            if (tunCandidate && Guid.TryParse(adapter.Id, out var interfaceGuid) &&
                WfpNative.ConvertInterfaceGuidToLuid(interfaceGuid, out var interfaceLuid) == 0)
                luid = interfaceLuid;
            foreach (var address in adapter.GetIPProperties().UnicastAddresses)
            {
                if (address.Address.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6) ||
                    System.Net.IPAddress.IsLoopback(address.Address)) continue;
                var v6 = address.Address.AddressFamily == AddressFamily.InterNetworkV6;
                if (tunCandidate)
                {
                    var knownTunAddress = v6 ? PolicyBuilder.DefaultTunV6 : PolicyBuilder.DefaultTunV4;
                    if (luid == 0 || !hiddifyNamed && !knownTunAddress.Contains(address.Address)) continue;
                    tun.Add(new(new IpNetwork(address.Address, v6 ? 128 : 32), luid));
                    tunUp = true;
                }
                else if (adapter.NetworkInterfaceType is NetworkInterfaceType.Ethernet or NetworkInterfaceType.Wireless80211)
                {
                    // Never admit a default route or a suspiciously broad public prefix.
                    if (address.PrefixLength >= (v6 ? 64 : 24))
                        lan.Add(new(address.Address, address.PrefixLength));
                }
            }
        }
        return new(directory, apps, tun.Select(binding => binding.Address).Distinct().ToArray(),
            lan.Distinct().ToArray(), tunUp && running, running) { TunBindings = tun.Distinct().ToArray() };
    }

    internal static bool IsTunCandidate(NetworkInterfaceType type, string description) =>
        (type == NetworkInterfaceType.Tunnel || (int)type == ProprietaryVirtualInterface) &&
        (description.Contains("hiddify", StringComparison.OrdinalIgnoreCase) ||
         description.Contains("wintun", StringComparison.OrdinalIgnoreCase));

    private static IEnumerable<string> InstallDirectories()
    {
        foreach (var root in new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs"),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)
        })
            foreach (var name in new[] { "Hiddify", "Hiddify Next" })
                yield return Path.Combine(root, name);
        foreach (var hive in new[] { Registry.CurrentUser, Registry.LocalMachine })
            foreach (var subkey in new[] { @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                         @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" })
            {
                using var uninstall = hive.OpenSubKey(subkey);
                if (uninstall is null) continue;
                foreach (var name in uninstall.GetSubKeyNames())
                {
                    using var entry = uninstall.OpenSubKey(name);
                    if (entry?.GetValue("DisplayName") is string display &&
                        display.Contains("Hiddify", StringComparison.OrdinalIgnoreCase) &&
                        entry.GetValue("InstallLocation") is string location && Path.IsPathFullyQualified(location))
                        yield return location;
                }
            }
    }
}
