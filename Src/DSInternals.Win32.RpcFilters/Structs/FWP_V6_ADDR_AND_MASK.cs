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

    public IPAddress Address
    {
        get => new IPAddress(this.addr);
        set
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            if (value.AddressFamily != AddressFamily.InterNetworkV6)
            {
                throw new ArgumentException("Address must be IPv6.", nameof(value));
            }

            this.addr = value.GetAddressBytes();
        } 
    }

    public byte PrefixLength
    {
        get => this.prefixLength;
        set
        {
            if (value > MaxIpv6PrefixLength)
            {
                throw new ArgumentOutOfRangeException(nameof(value), "Prefix length must be between 0 and 128.");
            }

            this.prefixLength = value;
        }
    }
}
