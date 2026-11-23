using System.Security.Cryptography;
using System.Text;

namespace HiddifyGuard.Core.Policy;

public static class GuardIds
{
    // Never change these identifiers: old versions and the uninstaller share ownership.
    public static readonly Guid Provider = new("e63eab9f-20a3-4593-b584-418ca64ee984");
    public static readonly Guid SubLayer = new("630ce4c8-a814-4ee4-b24a-46f8a801e05d");
    public const string Tag = "HiddifyGuard/v1:";

    public static Guid Filter(string name)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes($"{Provider:D}/{name}"));
        return new Guid(bytes.AsSpan(0, 16));
    }
}

public sealed record FilterRule(
    string Key, bool IsV6, bool BootTime, bool Permit, ulong Weight,
    IpNetwork? Local = null, IpNetwork? Remote = null,
    byte? Protocol = null, ushort? LocalPort = null, ushort? RemotePort = null,
    string? Application = null, bool Required = false)
{
    public Guid Id => GuardIds.Filter(Key);
    public uint Flags => BootTime ? 2u : 1u; // Mutually exclusive, by construction.
    public string Fingerprint => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
        $"{Key}|{IsV6}|{Flags}|{Permit}|{Weight}|{Local}|{Remote}|{Protocol}|{LocalPort}|{RemotePort}|{Application?.ToUpperInvariant()}")));
}

public sealed record DiscoverySnapshot(
    string? Directory, IReadOnlyList<string> Applications,
    IReadOnlyList<IpNetwork> TunAddresses, IReadOnlyList<IpNetwork> LanNetworks,
    bool TunUp, bool HiddifyRunning)
{
    public static DiscoverySnapshot Empty { get; } = new(null, [], [], [], false, false);
}

public static class PolicyBuilder
{
    public static readonly IpNetwork DefaultTunV4 = IpNetwork.Parse("172.19.0.1/28");
    public static readonly IpNetwork DefaultTunV6 = IpNetwork.Parse("fdfe:dcba:9876::1/126");
    public static readonly string[] PrivateLan = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fe80::/10"];

    public static IReadOnlyList<FilterRule> Build(bool allowLan, DiscoverySnapshot discovery)
    {
        var rules = new List<FilterRule>();
        foreach (var v6 in new[] { false, true })
        {
            var family = v6 ? "v6" : "v4";
            foreach (var boot in new[] { false, true })
            {
                var prefix = $"{(boot ? "boot" : "persistent")}/{family}";
                rules.Add(new($"{prefix}/block", v6, boot, false, 1, Required: true));
                rules.Add(new($"{prefix}/loopback", v6, boot, true, 100,
                    Remote: IpNetwork.Parse(v6 ? "::1/128" : "127.0.0.0/8"), Required: true));
                rules.Add(new($"{prefix}/dhcp", v6, boot, true, 100, Protocol: 17,
                    LocalPort: (ushort)(v6 ? 546 : 68), RemotePort: (ushort)(v6 ? 547 : 67), Required: true));
            }

            var persistent = $"persistent/{family}";
            var tun = discovery.TunAddresses.Append(v6 ? DefaultTunV6 : DefaultTunV4)
                .Where(n => n.IsV6 == v6).Distinct().OrderBy(n => n.ToString(), StringComparer.Ordinal);
            foreach (var network in tun)
                rules.Add(new($"{persistent}/tun/{network}", v6, false, true, 90, Local: network));

            foreach (var app in discovery.Applications.Select(Path.GetFullPath)
                         .Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase))
                rules.Add(new($"{persistent}/app/{app.ToUpperInvariant()}", v6, false, true, 100, Application: app));

            if (allowLan)
                foreach (var network in PrivateLan.Select(IpNetwork.Parse).Concat(discovery.LanNetworks)
                             .Where(n => n.IsV6 == v6 && n.PrefixLength > 0).Distinct()
                             .OrderBy(n => n.ToString(), StringComparer.Ordinal))
                    rules.Add(new($"{persistent}/lan/{network}", v6, false, true, 80, Remote: network));
        }
        if (rules.Select(r => r.Id).Distinct().Count() != rules.Count)
            throw new InvalidOperationException("Duplicate filter identity.");
        return rules;
    }
}
