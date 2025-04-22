using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace DSInternals.Win32.RpcFilters;

/// <summary>
/// Specifies IPv4 address and mask in host order.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct FWP_V4_ADDR_AND_MASK
{
    internal const int MaxIpv4PrefixLength = sizeof(int) * 8;

    /// <summary>
    /// Specifies an IPv4 address.
    /// </summary>
    private uint addr;

    /// <summary>
    /// Specifies an IPv4 mask.
    /// </summary>
    private uint mask;

    public IPAddress Address
    {
        get => new IPAddress(this.addr);
        set
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            if (value.AddressFamily != AddressFamily.InterNetwork)
            {
                throw new ArgumentException("Address must be IPv4.", nameof(value));
            }

            byte[] binaryAddress = value.GetAddressBytes();
            this.addr = BitConverter.ToUInt32(binaryAddress, 0);
        } 
    }

    public byte PrefixLength
    {
        get => (byte)this.mask;
        set
        {
            if (value > MaxIpv4PrefixLength)
            {
                throw new ArgumentOutOfRangeException(nameof(value), $"Mask must be between 0 and {MaxIpv4PrefixLength}.");
            }

            this.mask = value;
        }
    }
}
