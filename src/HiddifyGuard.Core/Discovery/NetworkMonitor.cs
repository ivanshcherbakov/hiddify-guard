using System.Net.NetworkInformation;
using HiddifyGuard.Core.Policy;

namespace HiddifyGuard.Core.Discovery;

public enum GuardVisualState { ProtectedConnected, ProtectedBlocked, Unprotected, HiddifyNotFound, Attention }

public static class GuardVisualStates
{
    public static GuardVisualState Resolve(GuardStatus status)
    {
        if (status.Protection.State == ProtectionState.Degraded) return GuardVisualState.Attention;
        if (status.Discovery.Directory is null) return GuardVisualState.HiddifyNotFound;
        if (status.Protection.State == ProtectionState.Off) return GuardVisualState.Unprotected;
        return status.Discovery.TunUp ? GuardVisualState.ProtectedConnected : GuardVisualState.ProtectedBlocked;
    }
}

/// <summary>Reports changes only. Never adds or removes firewall policy.</summary>
public sealed class NetworkMonitor : IDisposable
{
    private Timer? timer;
    private int started;
    public event EventHandler? Changed;
    public void Start()
    {
        if (Interlocked.Exchange(ref started, 1) != 0) return;
        NetworkChange.NetworkAddressChanged += AddressChanged;
        NetworkChange.NetworkAvailabilityChanged += AvailabilityChanged;
        timer = new Timer(_ => Raise(), null, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(2));
    }
    private void AddressChanged(object? sender, EventArgs args) => Raise();
    private void AvailabilityChanged(object? sender, NetworkAvailabilityEventArgs args) => Raise();
    private void Raise() { if (Volatile.Read(ref started) != 0) Changed?.Invoke(this, EventArgs.Empty); }
    public void Dispose()
    {
        if (Interlocked.Exchange(ref started, 0) == 0) return;
        NetworkChange.NetworkAddressChanged -= AddressChanged;
        NetworkChange.NetworkAvailabilityChanged -= AvailabilityChanged;
        timer?.Dispose(); timer = null;
    }
}
