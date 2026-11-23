using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace HiddifyGuard.Core.Diagnostics;

public enum ProbeOutcome { Reachable, Blocked, Inconclusive, NotApplicable }
public enum LeakVerdict { ProtectionOff, PossibleLeak, BlockObserved, Inconclusive }
public sealed record ProbeResult(string Name, ProbeOutcome Outcome, string Reason, long ElapsedMs);
public sealed record LeakReport(LeakVerdict Verdict, IReadOnlyList<ProbeResult> Probes, string? ExternalIp);
internal sealed record PhysicalBinding(IPAddress Address, int InterfaceIndex);

/// <summary>Explicit, user-initiated probes. A timeout is NEVER counted as a passing result.</summary>
public sealed class LeakTester
{
    public static LeakVerdict Evaluate(bool protectionOn, IReadOnlyList<ProbeResult> results)
    {
        if (!protectionOn) return LeakVerdict.ProtectionOff;
        if (results.Any(r => r.Outcome == ProbeOutcome.Reachable)) return LeakVerdict.PossibleLeak;
        // Missing IPv6, unreachable destinations or a disconnected NIC cannot prove containment.
        return results.Count == 3 && results.All(r => r.Outcome == ProbeOutcome.Blocked)
            ? LeakVerdict.BlockObserved : LeakVerdict.Inconclusive;
    }
    public async Task<LeakReport> RunAsync(bool protectionOn, bool tunUp, CancellationToken cancellationToken = default)
    {
        var results = new List<ProbeResult>();
        results.Add(await Probe("IPv4 TCP", false, false, cancellationToken));
        results.Add(await Probe("IPv6 TCP", true, false, cancellationToken));
        results.Add(await Probe("DNS UDP", false, true, cancellationToken));
        string? ip = null;
        if (tunUp)
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(3));
            using var handler = new HttpClientHandler { UseProxy = false };
            using var client = new HttpClient(handler);
            try
            {
                var value = (await client.GetStringAsync("https://api.ipify.org", timeout.Token)).Trim();
                if (IPAddress.TryParse(value, out var address)) ip = address.ToString();
            }
            catch (HttpRequestException) { }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { }
        }
        cancellationToken.ThrowIfCancellationRequested();
        return new(Evaluate(protectionOn, results), results, ip);
    }
    private static async Task<ProbeResult> Probe(string name, bool v6, bool dns, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var watch = Stopwatch.StartNew();
        IReadOnlyList<PhysicalBinding> bindings;
        try { bindings = FindPhysical(v6); }
        catch (NetworkInformationException) { return new(name, ProbeOutcome.Inconclusive, "interface-query-failed", watch.ElapsedMilliseconds); }
        var attempts = await Task.WhenAll(bindings.Select(binding => ProbeBinding(binding, dns, cancellationToken)));
        return SummarizeAttempts(name, attempts, watch.ElapsedMilliseconds);
    }

    internal static ProbeResult SummarizeAttempts(string name, IReadOnlyList<ProbeResult> attempts, long elapsedMs)
    {
        if (attempts.Count == 0) return new(name, ProbeOutcome.NotApplicable, "no-physical-address", elapsedMs);
        var outcome = attempts.Any(attempt => attempt.Outcome == ProbeOutcome.Reachable)
            ? ProbeOutcome.Reachable
            : attempts.All(attempt => attempt.Outcome == ProbeOutcome.Blocked) ? ProbeOutcome.Blocked : ProbeOutcome.Inconclusive;
        var reason = string.Join(", ", attempts.Select(attempt => $"{attempt.Name}: {attempt.Reason}"));
        return new(name, outcome, reason, elapsedMs);
    }

    private static async Task<ProbeResult> ProbeBinding(PhysicalBinding binding, bool dns, CancellationToken cancellationToken)
    {
        var watch = Stopwatch.StartNew();
        var name = $"if {binding.InterfaceIndex}";
        var v6 = binding.Address.AddressFamily == AddressFamily.InterNetworkV6;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(3));
        var checkingOutbound = false;
        try
        {
            using var socket = new Socket(binding.Address.AddressFamily,
                dns ? SocketType.Dgram : SocketType.Stream, dns ? ProtocolType.Udp : ProtocolType.Tcp);
            // Pin BOTH source and outgoing interface. An unbound probe could just use the VPN.
            socket.Bind(new IPEndPoint(binding.Address, 0));
            socket.SetSocketOption(v6 ? SocketOptionLevel.IPv6 : SocketOptionLevel.IP,
                (SocketOptionName)31, v6 ? binding.InterfaceIndex : IPAddress.HostToNetworkOrder(binding.InterfaceIndex));
            // Windows IP_UNICAST_IF / IPV6_UNICAST_IF = 31 (ws2ipdef.h); absent from the .NET 8 enum.
            checkingOutbound = true;
            var target = IPAddress.Parse(dns ? "8.8.8.8" : v6 ? "2606:4700:4700::1111" : "1.1.1.1");
            await socket.ConnectAsync(new IPEndPoint(target, dns ? 53 : 443), timeout.Token);
            if (dns)
            {
                var id = (ushort)RandomNumberGenerator.GetInt32(65536);
                var packet = DnsPacket(id);
                await socket.SendAsync(packet, SocketFlags.None, timeout.Token);
                checkingOutbound = false;
                var response = new byte[512];
                var size = await socket.ReceiveAsync(response, SocketFlags.None, timeout.Token);
                if (!IsDnsResponse(response.AsSpan(0, size), id))
                    return new(name, ProbeOutcome.Inconclusive, "unexpected-dns-response", watch.ElapsedMilliseconds);
            }
            return new(name, ProbeOutcome.Reachable, "physical-interface-reachable", watch.ElapsedMilliseconds);
        }
        catch (SocketException error)
        {
            return new(name, checkingOutbound && error.SocketErrorCode == SocketError.AccessDenied
                ? ProbeOutcome.Blocked : ProbeOutcome.Inconclusive,
                $"socket-{error.ErrorCode}", watch.ElapsedMilliseconds);
        }
        catch (OperationCanceledException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return new(name, ProbeOutcome.Inconclusive, "timeout", watch.ElapsedMilliseconds);
        }
    }
    internal static byte[] DnsPacket(ushort id)
    {
        byte[] packet = [0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
            7, (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e',
            3, (byte)'c', (byte)'o', (byte)'m', 0, 0, 1, 0, 1];
        BinaryPrimitives.WriteUInt16BigEndian(packet, id);
        return packet;
    }
    internal static bool IsDnsResponse(ReadOnlySpan<byte> packet, ushort id) =>
        packet.Length >= 12 && BinaryPrimitives.ReadUInt16BigEndian(packet) == id && (packet[2] & 0x80) != 0;

    private static IReadOnlyList<PhysicalBinding> FindPhysical(bool v6)
    {
        var family = v6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork;
        var bindings = new List<PhysicalBinding>();
        foreach (var adapter in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (adapter.OperationalStatus != OperationalStatus.Up ||
                adapter.NetworkInterfaceType is not (NetworkInterfaceType.Ethernet or NetworkInterfaceType.Wireless80211) ||
                (adapter.Name + adapter.Description).Contains("wintun", StringComparison.OrdinalIgnoreCase) ||
                (adapter.Name + adapter.Description).Contains("hiddify", StringComparison.OrdinalIgnoreCase)) continue;
            var properties = adapter.GetIPProperties();
            // A more-specific route can exist without a default gateway on this adapter.
            var addresses = properties.UnicastAddresses.Select(address => address.Address)
                .Where(address => address.AddressFamily == family && !address.IsIPv6LinkLocal && !IPAddress.IsLoopback(address))
                .ToArray();
            if (addresses.Length == 0) continue;
            var index = v6 ? properties.GetIPv6Properties().Index : properties.GetIPv4Properties().Index;
            if (index <= 0) throw new NetworkInformationException();
            bindings.AddRange(addresses.Select(address => new PhysicalBinding(address, index)));
        }
        return bindings;
    }
}
