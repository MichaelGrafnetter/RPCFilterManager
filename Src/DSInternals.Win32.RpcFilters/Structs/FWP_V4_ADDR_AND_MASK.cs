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
    internal const int MinIpv4PrefixLength = 1;
    internal const int MaxIpv4PrefixLength = sizeof(int) * 8;

    /// <summary>
    /// Specifies an IPv4 address.
    /// </summary>
    private uint addr;

    /// <summary>
    /// Specifies an IPv4 mask.
    /// </summary>
    private uint mask;

    /// <summary>
    /// Specifies an IPv4 address.
    /// </summary>
    public IPAddress Address
    {
        readonly get => new(this.addr);
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

    /// <summary>
    /// Specifies an IPv4 mask length.
    /// </summary>
    public byte PrefixLength
    {
        readonly get
        {
            byte result = 0;
            uint maskCopy = this.mask;

            // Count the number of leading 1 bits in the mask
            while (maskCopy != 0)
            {
                result++;
                maskCopy <<= 1;
            }

            return result;
        }
        set
        {
            if (value < MinIpv4PrefixLength || value > MaxIpv4PrefixLength)
            {
                throw new ArgumentOutOfRangeException(nameof(value), $"Mask must be between 1 and {MaxIpv4PrefixLength}.");
            }

            // Convert the prefix length to mask
            this.mask = ~(uint.MaxValue >>> value);
        }
    }

    public FWP_V4_ADDR_AND_MASK(IPAddress address, byte prefixLength)
    {
        this.Address = address;
        this.PrefixLength = prefixLength;
    }
}
