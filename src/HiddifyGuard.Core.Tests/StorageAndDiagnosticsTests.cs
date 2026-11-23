using HiddifyGuard.Core.Diagnostics;
using HiddifyGuard.Core.Discovery;
using HiddifyGuard.Core.Policy;
using HiddifyGuard.Core.Storage;

namespace HiddifyGuard.Core.Tests;

public sealed class StorageAndDiagnosticsTests
{
    [Fact] public void ConfigRoundTripsAndCorruptionIsNotSilentlyReset()
    {
        var folder = Path.Combine(Path.GetTempPath(), "HiddifyGuard.Tests", Guid.NewGuid().ToString("N"));
        try
        {
            var store = new ConfigStore(folder, secure: false);
            Assert.True(store.Load().AllowLan);
            var expected = new GuardSettings { AllowLan = false, Language = "ru", HiddifyDirectory = @"C:\Hiddify" };
            store.Save(expected); Assert.Equal(expected, store.Load());
            File.WriteAllText(store.FilePath, "{broken");
            Assert.Throws<InvalidDataException>(() => store.Load());
            Assert.Equal("{broken", File.ReadAllText(store.FilePath));
        }
        finally { if (Directory.Exists(folder)) Directory.Delete(folder, true); }
    }
    [Theory] [InlineData("relative")] [InlineData(@"\\server\Hiddify")]
    public void NetworkAndRelativeExecutablePathsAreRejected(string path) =>
        Assert.Throws<InvalidDataException>(() => new GuardSettings { HiddifyDirectory = path }.Validate());
    [Theory]
    [InlineData(ProtectionState.On, true, GuardVisualState.ProtectedConnected)]
    [InlineData(ProtectionState.On, false, GuardVisualState.ProtectedBlocked)]
    [InlineData(ProtectionState.Off, true, GuardVisualState.Unprotected)]
    [InlineData(ProtectionState.Degraded, true, GuardVisualState.Attention)]
    public void VisualStateNeverConfusesTunPresenceWithProtection(ProtectionState protection, bool tun, GuardVisualState expected)
    {
        var status = new GuardStatus(new(), DiscoverySnapshot.Empty with { Directory = @"C:\Hiddify", TunUp = tun },
            new(protection, 10, true));
        Assert.Equal(expected, GuardVisualStates.Resolve(status));
    }
    [Fact] public void TimeoutAndMissingIpv6NeverBecomePassingLeakTests()
    {
        Assert.Equal(LeakVerdict.Inconclusive, LeakTester.Evaluate(true,
            [new("v4", ProbeOutcome.Blocked, "", 0), new("v6", ProbeOutcome.NotApplicable, "", 0),
             new("dns", ProbeOutcome.Inconclusive, "timeout", 3000)]));
        Assert.Equal(LeakVerdict.PossibleLeak, LeakTester.Evaluate(true, [new("v4", ProbeOutcome.Reachable, "", 0)]));
        Assert.Equal(LeakVerdict.ProtectionOff, LeakTester.Evaluate(false, [new("v4", ProbeOutcome.Reachable, "", 0)]));
    }
    [Fact] public void DnsReplyRequiresMatchingIdAndResponseFlag()
    {
        var packet = LeakTester.DnsPacket(0x1234);
        Assert.False(LeakTester.IsDnsResponse(packet, 0x1234));
        packet[2] |= 0x80;
        Assert.True(LeakTester.IsDnsResponse(packet, 0x1234));
        Assert.False(LeakTester.IsDnsResponse(packet, 0x1235));
        Assert.False(LeakTester.IsDnsResponse(packet.AsSpan(0, 4), 0x1234));
    }
}
