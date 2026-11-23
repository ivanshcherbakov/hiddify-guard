using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace HiddifyGuard.Core.Policy;

public sealed record IpNetwork
{
    public IPAddress Address { get; }
    public byte PrefixLength { get; }
    public bool IsV6 => Address.AddressFamily == AddressFamily.InterNetworkV6;

    public IpNetwork(IPAddress address, int prefixLength)
    {
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        var bytes = address.GetAddressBytes();
        if (prefixLength < 0 || prefixLength > bytes.Length * 8)
            throw new ArgumentOutOfRangeException(nameof(prefixLength));
        PrefixLength = checked((byte)prefixLength);
        // Apply the mask explicitly; /0 must never shift a uint by 32.
        for (var i = 0; i < bytes.Length; i++)
        {
            var bits = Math.Clamp(prefixLength - i * 8, 0, 8);
            bytes[i] &= (byte)(0xff << (8 - bits));
        }
        Address = new IPAddress(bytes);
    }

    public static IpNetwork Parse(string text)
    {
        var pieces = text.Split('/');
        if (pieces.Length != 2) throw new FormatException("Use an address and CIDR prefix.");
        return new IpNetwork(IPAddress.Parse(pieces[0]), int.Parse(pieces[1],
            System.Globalization.CultureInfo.InvariantCulture));
    }

    public bool Contains(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        return address.AddressFamily == Address.AddressFamily &&
            new IpNetwork(address, PrefixLength).Address.Equals(Address);
    }

    public uint V4Address => !IsV6
        ? BinaryPrimitives.ReadUInt32BigEndian(Address.GetAddressBytes())
        : throw new InvalidOperationException("Not IPv4.");
    public uint V4Mask => !IsV6
        ? PrefixLength == 0 ? 0 : uint.MaxValue << (32 - PrefixLength)
        : throw new InvalidOperationException("Not IPv4.");
    public override string ToString() => $"{Address}/{PrefixLength}";
}
