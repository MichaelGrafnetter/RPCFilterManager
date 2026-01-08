using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using Windows.Win32;

namespace DSInternals.Win32.RpcFilters;

/// <summary>
/// Specifies an IPv6 address and mask.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct FWP_V6_ADDR_AND_MASK
{
    internal const int MinIpv6PrefixLength = 1;
    internal const int MaxIpv6PrefixLength = (int)PInvoke.FWP_V6_ADDR_SIZE * 8;

    /// <summary>
    /// Specifies an IPv6 address.
    /// </summary>
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = (int)PInvoke.FWP_V6_ADDR_SIZE)]
    private byte[] addr;

    /// <summary>
    /// Specifies the prefix length of the IPv6 address.
    /// </summary>
    private byte prefixLength;

    /// <summary>
    /// Specifies an IPv6 address.
    /// </summary>
    public IPAddress Address
    {
        readonly get => new(this.addr);

        [MemberNotNull(nameof(addr))]
        set
        {
            ArgumentNullException.ThrowIfNull(value);

            if (value.AddressFamily != AddressFamily.InterNetworkV6)
            {
                throw new ArgumentOutOfRangeException(nameof(value), "Address must be IPv6.");
            }

            this.addr = value.GetAddressBytes();
        }
    }

    /// <summary>
    /// Specifies the prefix length of the IPv6 address.
    /// </summary>
    public byte PrefixLength
    {
        readonly get => this.prefixLength;
        set
        {
            if (value < MinIpv6PrefixLength || value > MaxIpv6PrefixLength)
            {
                throw new ArgumentOutOfRangeException(nameof(value), "Prefix length must be between 1 and 128.");
            }

            this.prefixLength = value;
        }
    }

    public FWP_V6_ADDR_AND_MASK(IPAddress address, byte prefixLength)
    {
        this.Address = address;
        this.PrefixLength = prefixLength;
    }
}
