using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using HiddifyGuard.Core.Discovery;
using HiddifyGuard.Core.Native;
using HiddifyGuard.Core.Policy;

namespace HiddifyGuard.Core.Tests;

public sealed class PolicyTests
{
    [Fact] public void X64AbiMatchesWindowsSdk() => WfpAbi.Verify();
    [Theory]
    [InlineData("127.0.0.1/8", 0x7F000000u, 0xFF000000u)]
    [InlineData("127.0.0.1/32", 0x7F000001u, 0xFFFFFFFFu)]
    [InlineData("0.0.0.0/0", 0u, 0u)]
    [InlineData("192.168.42.9/24", 0xC0A82A00u, 0xFFFFFF00u)]
    public void Ipv4UsesHostOrder(string text, uint address, uint mask)
    {
        var network = IpNetwork.Parse(text);
        Assert.Equal(address, network.V4Address); Assert.Equal(mask, network.V4Mask);
    }
    [Fact] public void Ipv6UsesNetworkBytesAndOneBytePrefix()
    {
        using var arena = new NativeArena();
        var network = IpNetwork.Parse("fdfe:dcba:9876::1/126");
        var native = Marshal.PtrToStructure<V6AddressMask>(WfpSession.Address(WfpConstants.LocalAddress, network, arena).Value.Pointer);
        Assert.Equal(new byte[] { 0xfd, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, native.Address);
        Assert.Equal(126, native.PrefixLength);
        Assert.True(network.Contains(IPAddress.Parse("fdfe:dcba:9876::3")));
        Assert.False(network.Contains(IPAddress.Parse("fdfe:dcba:9876::4")));
    }
    [Theory] [InlineData("1.2.3.4/33")] [InlineData("::/129")] [InlineData("::/-1")]
    public void InvalidPrefixIsRejected(string text) => Assert.Throws<ArgumentOutOfRangeException>(() => IpNetwork.Parse(text));
    [Fact] public void BootAndPersistentFlagsAreNeverCombined()
    {
        var plan = PolicyBuilder.Build(true, DiscoverySnapshot.Empty);
        Assert.All(plan, rule => Assert.Equal(rule.BootTime ? 2u : 1u, rule.Flags));
        Assert.Equal(6, plan.Count(r => r.BootTime));
        Assert.Equal(4, plan.Count(r => !r.Permit && r.Weight == 1));
        Assert.Equal(12, plan.Count(r => r.Required));
    }
    [Fact] public void DhcpPortsAndWeightsAreExactInBothFamiliesAndLifetimes()
    {
        var plan = PolicyBuilder.Build(false, DiscoverySnapshot.Empty);
        foreach (var rule in plan.Where(r => r.Key.EndsWith("/dhcp", StringComparison.Ordinal)))
        {
            Assert.Equal((byte)17, rule.Protocol);
            Assert.Equal((ushort)(rule.IsV6 ? 546 : 68), rule.LocalPort);
            Assert.Equal((ushort)(rule.IsV6 ? 547 : 67), rule.RemotePort);
            Assert.True(rule.Weight > 1);
        }
    }
    [Fact] public void LanSwitchNeverRemovesTunOrApplicationRules()
    {
        var v4 = IpNetwork.Parse("172.19.0.1/32");
        var v6 = IpNetwork.Parse("fdfe:dcba:9876::1/128");
        var discovery = new DiscoverySnapshot(@"C:\Hiddify", [@"C:\Hiddify\Hiddify.exe"], [v4, v6], [], true, true)
        {
            TunBindings = [new(v4, 0x0035000000000001), new(v6, 0x0035000000000001)]
        };
        var enabled = PolicyBuilder.Build(true, discovery);
        var disabled = PolicyBuilder.Build(false, discovery);
        Assert.DoesNotContain(disabled, r => r.Key.Contains("/lan/", StringComparison.Ordinal));
        Assert.Equal(enabled.Where(r => !r.Key.Contains("/lan/", StringComparison.Ordinal)), disabled);
        Assert.Equal(2, disabled.Count(r => r.Application is not null));
        Assert.Contains(disabled, r => !r.BootTime && r.Local == v4 && r.NextHopInterfaceLuid == 0x0035000000000001);
        Assert.Contains(disabled, r => !r.BootTime && r.Local == v6 && r.NextHopInterfaceLuid == 0x0035000000000001);
    }

    [Fact] public void AddressAloneNeverCreatesATunPermit()
    {
        var address = IpNetwork.Parse("172.19.0.1/32");
        var discovery = DiscoverySnapshot.Empty with { TunAddresses = [address], TunBindings = [new(address, 0)] };
        Assert.DoesNotContain(PolicyBuilder.Build(false, discovery), rule => rule.Key.Contains("/tun/", StringComparison.Ordinal));
    }

    [Fact] public void TunNextHopUsesSdkGuidAndPointerToUnsigned64BitLuid()
    {
        const ulong luid = 0x0035000000001234;
        using var arena = new NativeArena();
        var condition = WfpSession.NextHopInterface(luid, arena);

        Assert.Equal(new Guid("93ae8f5b-7f6f-4719-98c8-14e97429ef04"), condition.FieldKey);
        Assert.Equal(4u, condition.Value.Type);
        Assert.Equal(luid, unchecked((ulong)Marshal.ReadInt64(condition.Value.Pointer)));
    }

    [Theory]
    [InlineData(NetworkInterfaceType.Ethernet, "Hiddify Ethernet", false)]
    [InlineData(NetworkInterfaceType.Wireless80211, "Wintun Wi-Fi", false)]
    [InlineData(NetworkInterfaceType.Tunnel, "Hiddify TUN", true)]
    [InlineData((NetworkInterfaceType)53, "Wintun Userspace Tunnel", true)]
    public void TunDiscoveryRequiresAnInterfaceTypeConsistentWithATunnel(NetworkInterfaceType type, string name, bool expected) =>
        Assert.Equal(expected, HiddifyDiscovery.IsTunCandidate(type, name));
    [Fact] public void IdentitiesSurviveDiscoveryOrderAndDuplicatePaths()
    {
        var discovery = DiscoverySnapshot.Empty with { Applications = [@"C:\Hiddify\Hiddify.exe", @"C:\Hiddify\HiddifyCli.exe"] };
        var reordered = discovery with { Applications = discovery.Applications.Reverse().Append(@"c:\hiddify\hiddify.exe").ToArray() };
        Assert.Equal(PolicyBuilder.Build(true, discovery).Select(r => r.Id), PolicyBuilder.Build(true, reordered).Select(r => r.Id));
    }
}
