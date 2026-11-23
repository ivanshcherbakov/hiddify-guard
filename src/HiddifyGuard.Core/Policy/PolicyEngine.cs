namespace HiddifyGuard.Core.Policy;

public sealed record StoredFilter(Guid Id, Guid Layer, Guid SubLayer, uint Flags, uint Action, string Tag, string Name = "");
public enum ProtectionState { Off, On, Degraded }
public sealed record ProtectionSnapshot(ProtectionState State, int FilterCount, bool MatchesPlan,
    int BootTimeFilters = 0, int PersistentFilters = 0, IReadOnlyList<string>? AllowedApplications = null);

public interface IWfpSession : IDisposable
{
    void Begin();
    void Commit();
    void Abort();
    IReadOnlyList<StoredFilter> Enumerate();
    bool ProviderDisabled { get; }
    void AddProviderAndSubLayer();
    void Add(FilterRule rule);
    void DeleteFilter(Guid id);
    void DeleteSubLayer();
    void DeleteProvider();
}

public sealed class PolicyEngine(Func<IWfpSession> open)
{
    public ProtectionSnapshot Inspect(IReadOnlyList<FilterRule>? plan = null)
    {
        using var session = open();
        var filters = session.Enumerate();
        if (filters.Count == 0) return new(ProtectionState.Off, 0, false);
        var required = PolicyBuilder.Build(false, DiscoverySnapshot.Empty).Where(r => r.Required);
        bool Matches(FilterRule rule) => filters.Any(f => f.Id == rule.Id &&
            f.SubLayer == GuardIds.SubLayer && f.Layer == Native.WfpConstants.Layer(rule.IsV6) &&
            f.Flags == rule.Flags && f.Action == (rule.Permit ? 0x1002u : 0x1001u) &&
            f.Tag == GuardIds.Tag + rule.Fingerprint);
        var healthy = !session.ProviderDisabled && required.All(Matches) &&
            filters.All(f => (f.Flags & Native.WfpConstants.FilterDisabled) == 0);
        var applications = filters.Where(f => f.Name.Contains("/app/", StringComparison.Ordinal))
            .Select(f => f.Name[(f.Name.IndexOf("/app/", StringComparison.Ordinal) + 5)..])
            .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        return new(healthy ? ProtectionState.On : ProtectionState.Degraded, filters.Count,
            healthy && plan is not null && filters.Count == plan.Count && plan.All(Matches),
            filters.Count(f => (f.Flags & 2) != 0), filters.Count(f => (f.Flags & 1) != 0), applications);
    }

    public void Replace(IReadOnlyList<FilterRule> rules)
    {
        if (!rules.Any() || rules.Any(r => r.Flags is not (1 or 2)))
            throw new ArgumentException("A persistent and boot-time policy is required.", nameof(rules));
        // Validate before touching WFP. A malformed plan must not replace a working kill switch.
        var required = PolicyBuilder.Build(false, DiscoverySnapshot.Empty).Where(r => r.Required).ToArray();
        if (required.Any(r => !rules.Contains(r)) || rules.Select(r => r.Id).Distinct().Count() != rules.Count ||
            rules.Any(r => r.BootTime && !required.Contains(r)))
            throw new ArgumentException("The complete IPv4/IPv6 baseline is required.", nameof(rules));
        if (rules.Any(r => r.Permit && (r.Weight <= 1 ||
                (r.Local is null && r.Remote is null && r.Protocol is null &&
                 r.LocalPort is null && r.RemotePort is null && r.Application is null &&
                 r.NextHopInterfaceLuid is null) ||
                r.Local?.PrefixLength == 0 ||
                r.Remote?.PrefixLength == 0 || r.Local is not null && r.Local.IsV6 != r.IsV6 ||
                r.Remote is not null && r.Remote.IsV6 != r.IsV6)))
            throw new ArgumentException("An unsafe allow rule was rejected.", nameof(rules));
        Transact(session =>
        {
            RemoveOwned(session);
            session.AddProviderAndSubLayer();
            foreach (var rule in rules) session.Add(rule);
        });
    }

    public void Disable() => Transact(RemoveOwned);

    private static void RemoveOwned(IWfpSession session)
    {
        // The native enumeration includes BOTH boot-time and disabled filters.
        foreach (var filter in session.Enumerate()) session.DeleteFilter(filter.Id);
        session.DeleteSubLayer();
        session.DeleteProvider();
    }

    private void Transact(Action<IWfpSession> action)
    {
        using var session = open();
        session.Begin();
        try
        {
            action(session);
            session.Commit();
        }
        catch (Exception failure)
        {
            try { session.Abort(); }
            catch (Exception abortFailure) { throw new AggregateException("WFP transaction and rollback failed.", failure, abortFailure); }
            throw;
        }
    }
}
