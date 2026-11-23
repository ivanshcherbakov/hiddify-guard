using System.ComponentModel;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Microsoft.Win32;
using HiddifyGuard.Core.Policy;
using HiddifyGuard.Core.Storage;

namespace HiddifyGuard.Core.Discovery;

public static class HiddifyDiscovery
{
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
        var tun = new List<IpNetwork>();
        var lan = new List<IpNetwork>();
        var tunUp = false;
        foreach (var adapter in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (adapter.OperationalStatus != OperationalStatus.Up) continue;
            var description = adapter.Name + " " + adapter.Description;
            var hiddifyNamed = description.Contains("hiddify", StringComparison.OrdinalIgnoreCase);
            var tunNamed = hiddifyNamed || description.Contains("wintun", StringComparison.OrdinalIgnoreCase);
            foreach (var address in adapter.GetIPProperties().UnicastAddresses)
            {
                if (address.Address.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6) ||
                    System.Net.IPAddress.IsLoopback(address.Address)) continue;
                var v6 = address.Address.AddressFamily == AddressFamily.InterNetworkV6;
                if (tunNamed)
                {
                    tun.Add(new(address.Address, v6 ? 128 : 32));
                    if (hiddifyNamed || PolicyBuilder.DefaultTunV4.Contains(address.Address) ||
                        PolicyBuilder.DefaultTunV6.Contains(address.Address)) tunUp = true;
                }
                else if (adapter.NetworkInterfaceType is NetworkInterfaceType.Ethernet or NetworkInterfaceType.Wireless80211)
                {
                    // Never admit a default route or a suspiciously broad public prefix.
                    if (address.PrefixLength >= (v6 ? 64 : 24))
                        lan.Add(new(address.Address, address.PrefixLength));
                }
            }
        }
        return new(directory, apps, tun.Distinct().ToArray(), lan.Distinct().ToArray(), tunUp && running, running);
    }

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
