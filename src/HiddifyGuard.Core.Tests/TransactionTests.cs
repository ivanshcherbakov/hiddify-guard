using HiddifyGuard.Core.Native;
using HiddifyGuard.Core.Policy;

namespace HiddifyGuard.Core.Tests;

public sealed class TransactionTests
{
    private static StoredFilter Stored(FilterRule rule) => new(rule.Id, WfpConstants.Layer(rule.IsV6), GuardIds.SubLayer,
        rule.Flags, rule.Permit ? 0x1002u : 0x1001u, GuardIds.Tag + rule.Fingerprint);
    [Fact] public void EnableCommitsOneTransactionContainingBothLifetimes()
    {
        var fake = new FakeSession();
        var plan = PolicyBuilder.Build(false, DiscoverySnapshot.Empty);
        new PolicyEngine(() => fake).Replace(plan);
        Assert.Equal(1, fake.Begins); Assert.Equal(1, fake.Commits); Assert.Equal(0, fake.Aborts);
        Assert.Equal(plan.Count, fake.Filters.Count);
        Assert.Contains(fake.Filters, f => f.Flags == 2);
        Assert.Contains(fake.Filters, f => f.Flags == 1);
    }
    [Theory] [InlineData(false)] [InlineData(true)]
    public void AddOrCommitFailureRestoresPreviousPolicy(bool commitFailure)
    {
        var original = PolicyBuilder.Build(true, DiscoverySnapshot.Empty).Select(Stored).ToArray();
        var fake = new FakeSession { FailAdd = !commitFailure, FailCommit = commitFailure };
        fake.Filters.AddRange(original);
        Assert.Throws<WfpException>(() => new PolicyEngine(() => fake).Replace(PolicyBuilder.Build(false, DiscoverySnapshot.Empty)));
        Assert.Equal(original, fake.Filters);
        Assert.Equal(1, fake.Aborts);
    }
    [Fact] public void DisableCleansBootDisabledAndOldVersionFiltersAndIsIdempotent()
    {
        var fake = new FakeSession();
        fake.Filters.AddRange(PolicyBuilder.Build(true, DiscoverySnapshot.Empty).Select(Stored));
        fake.Filters.Add(new(Guid.NewGuid(), WfpConstants.ConnectV4, Guid.NewGuid(), 0x21, 0x1001, "old"));
        var engine = new PolicyEngine(() => fake);
        engine.Disable(); engine.Disable();
        Assert.Empty(fake.Filters); Assert.Equal(2, fake.Commits);
        Assert.Equal(new[] { "sublayer", "provider", "sublayer", "provider" }, fake.Deletions);
    }
    [Fact] public void MissingBootFilterAndDisabledProviderAreDegraded()
    {
        var fake = new FakeSession();
        var plan = PolicyBuilder.Build(false, DiscoverySnapshot.Empty);
        fake.Filters.AddRange(plan.Select(Stored));
        var engine = new PolicyEngine(() => fake);
        Assert.True(engine.Inspect(plan).MatchesPlan);
        fake.ProviderDisabled = true;
        var disabled = engine.Inspect(plan);
        Assert.Equal(ProtectionState.Degraded, disabled.State);
        Assert.False(disabled.MatchesPlan);
        fake.ProviderDisabled = false;
        fake.Filters.RemoveAll(f => f.Id == GuardIds.Filter("boot/v6/block"));
        Assert.Equal(ProtectionState.Degraded, engine.Inspect().State);
    }

    [Theory]
    [InlineData(0x00000001u, false)]
    [InlineData(0x00000002u, false)]
    [InlineData(0x00000010u, true)]
    [InlineData(0x00000011u, true)]
    public void ProviderUsesSdkDisabledFlag(uint flags, bool expected) =>
        Assert.Equal(expected, new NativeProvider { Flags = flags }.IsDisabled);

    [Fact] public void DisabledOptionalFilterIsDegraded()
    {
        var fake = new FakeSession();
        var plan = PolicyBuilder.Build(true, DiscoverySnapshot.Empty);
        fake.Filters.AddRange(plan.Select(Stored));
        var index = fake.Filters.FindIndex(filter => filter.Id == GuardIds.Filter("persistent/v4/lan/10.0.0.0/8"));
        fake.Filters[index] = fake.Filters[index] with { Flags = 0x21 };

        var status = new PolicyEngine(() => fake).Inspect(plan);
        Assert.Equal(ProtectionState.Degraded, status.State);
        Assert.False(status.MatchesPlan);
    }

    [Theory]
    [InlineData(false, null)]
    [InlineData(true, (ushort)123)]
    public void UnconditionalPermitAndExtraBootPermitAreRejectedBeforeTransaction(bool boot, ushort? port)
    {
        var fake = new FakeSession();
        var plan = PolicyBuilder.Build(false, DiscoverySnapshot.Empty)
            .Append(new FilterRule("extra-permit", false, boot, true, 100, RemotePort: port)).ToArray();

        Assert.Throws<ArgumentException>(() => new PolicyEngine(() => fake).Replace(plan));
        Assert.Equal(0, fake.Begins);
    }
    [Fact] public void UnsafeOrIncompletePlanNeverBeginsATransaction()
    {
        var fake = new FakeSession();
        var engine = new PolicyEngine(() => fake);
        Assert.Throws<ArgumentException>(() => engine.Replace([]));
        var unsafePlan = PolicyBuilder.Build(false, DiscoverySnapshot.Empty)
            .Append(new FilterRule("unsafe", false, false, true, 10, Remote: IpNetwork.Parse("0.0.0.0/0"))).ToArray();
        Assert.Throws<ArgumentException>(() => engine.Replace(unsafePlan));
        Assert.Equal(0, fake.Begins);
    }
    private sealed class FakeSession : IWfpSession
    {
        public List<StoredFilter> Filters { get; } = [];
        public List<string> Deletions { get; } = [];
        private StoredFilter[] backup = [];
        public int Begins, Commits, Aborts;
        public bool FailAdd, FailCommit;
        public bool ProviderDisabled { get; set; }
        public void Begin() { Begins++; backup = Filters.ToArray(); }
        public void Commit() { if (FailCommit) throw new WfpException("commit", 5); Commits++; }
        public void Abort() { Aborts++; Filters.Clear(); Filters.AddRange(backup); }
        public IReadOnlyList<StoredFilter> Enumerate() => Filters.ToArray();
        public void AddProviderAndSubLayer() { }
        public void Add(FilterRule rule) { if (FailAdd) throw new WfpException("add", 5); Filters.Add(Stored(rule)); }
        public void DeleteFilter(Guid id) => Filters.RemoveAll(f => f.Id == id);
        public void DeleteSubLayer() => Deletions.Add("sublayer");
        public void DeleteProvider() => Deletions.Add("provider");
        public void Dispose() { } // Disposal deliberately does NOT delete persistent filters.
    }
}
