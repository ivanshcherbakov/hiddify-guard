using System.Security.Principal;
using HiddifyGuard.Core.Discovery;
using HiddifyGuard.Core.Native;
using HiddifyGuard.Core.Policy;
using HiddifyGuard.Core.Storage;

namespace HiddifyGuard.Core;

public sealed record GuardStatus(GuardSettings Settings, DiscoverySnapshot Discovery, ProtectionSnapshot Protection);

public sealed class GuardController
{
    public ConfigStore Store { get; } = new();
    private readonly PolicyEngine engine = new(() => new WfpSession());
    public GuardLog Log { get; }
    public GuardController() => Log = new(Store);

    public GuardStatus Status(bool refresh = false)
    {
        using var policyLock = PolicyLock.Take();
        var settings = Store.Load();
        var discovery = HiddifyDiscovery.Scan(settings);
        var plan = PolicyBuilder.Build(settings.AllowLan, discovery);
        var protection = engine.Inspect(plan);
        if (refresh && protection.State == ProtectionState.On && !protection.MatchesPlan &&
            discovery.Directory is not null)
        {
            RequireAdministrator();
            engine.Replace(plan); // Atomic replacement. Never disable during discovery changes.
            protection = engine.Inspect(plan);
            Log.Write("refresh");
        }
        return new(settings, discovery, protection);
    }

    public GuardStatus Enable()
    {
        RequireAdministrator();
        using (PolicyLock.Take())
        {
            var settings = Store.Load();
            var discovery = HiddifyDiscovery.Scan(settings);
            if (discovery.Directory is null || discovery.Applications.Count == 0)
                throw new InvalidOperationException("Hiddify.exe was not found. Select its folder in Advanced settings.");
            Store.Save(settings);
            engine.Replace(PolicyBuilder.Build(settings.AllowLan, discovery));
            Log.Write("enable");
        }
        return Status();
    }

    public void Disable()
    {
        RequireAdministrator();
        using var policyLock = PolicyLock.Take();
        engine.Disable(); // No configuration read: recovery also works with damaged config.json.
        Log.Write("disable");
    }

    public void SaveSettings(GuardSettings settings)
    {
        RequireAdministrator();
        settings.Validate();
        using var policyLock = PolicyLock.Take();
        var previous = Store.Load();
        var discovery = HiddifyDiscovery.Scan(settings);
        var plan = PolicyBuilder.Build(settings.AllowLan, discovery);
        var protection = engine.Inspect(plan);
        if (protection.State != ProtectionState.Off && discovery.Directory is null)
            throw new InvalidOperationException("Select a folder containing Hiddify.exe before changing an active policy.");
        Store.Save(settings);
        try
        {
            if (protection.State != ProtectionState.Off && !protection.MatchesPlan)
                engine.Replace(plan);
        }
        catch (Exception policyError)
        {
            try { Store.Save(previous); }
            catch (Exception configError) { throw new AggregateException("Policy update failed; settings rollback also failed.", policyError, configError); }
            throw;
        }
        Log.Write("settings");
    }

    public static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
    public static void RequireAdministrator()
    {
        if (!IsAdministrator()) throw new UnauthorizedAccessException("Run Hiddify Guard as administrator.");
    }
}

internal sealed class PolicyLock : IDisposable
{
    private readonly Mutex mutex = new(false, @"Global\HiddifyGuard.Policy.v1");
    private bool owned;
    private PolicyLock()
    {
        try { owned = mutex.WaitOne(TimeSpan.FromSeconds(20)); }
        catch (AbandonedMutexException) { owned = true; }
        if (!owned) { mutex.Dispose(); throw new TimeoutException("Another Hiddify Guard operation is still running."); }
    }
    public static PolicyLock Take() => new();
    public void Dispose()
    {
        if (owned) { owned = false; mutex.ReleaseMutex(); }
        mutex.Dispose();
    }
}
