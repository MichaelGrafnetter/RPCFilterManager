using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using Windows.Win32.NetworkManagement.WindowsFilteringPlatform;

namespace DSInternals.Win32.RpcFilters;

/// <summary>
/// Defines a data value that can be one of a number of different data types.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal readonly struct FWP_VALUE0
{
    /// <summary>
    /// The type of data for this value.
    /// </summary>
    public readonly FWP_DATA_TYPE Type;

    /// <summary>
    /// Data value.
    /// </summary>
    private readonly FWP_VALUE0_UNION Value;

    [StructLayout(LayoutKind.Explicit)]
    public struct FWP_VALUE0_UNION
    {
        /// <summary>
        /// An unsigned 8-bit integer.
        /// </summary>
        [FieldOffset(0)]
        public byte uint8;

        /// <summary>
        /// An unsigned 16-bit integer.
        /// </summary>
        [FieldOffset(0)]
        public ushort uint16;

        /// <summary>
        /// An unsigned 32-bit integer.
        /// </summary>
        [FieldOffset(0)]
        public uint uint32;

        /// <summary>
        /// A pointer to an unsigned 64-bit integer.
        /// </summary>
        [FieldOffset(0)]
        public IntPtr uint64;

        /// <summary>
        /// A signed 8-bit integer.
        /// </summary>
        [FieldOffset(0)]
        public sbyte int8;

        /// <summary>
        /// A signed 16-bit integer.
        /// </summary>
        [FieldOffset(0)]
        public short int16;

        /// <summary>
        /// A signed 32-bit integer.
        /// </summary>
        [FieldOffset(0)]
        public int int32;

        /// <summary>
        /// A pointer to a signed 64-bit integer.
        /// </summary>
        [FieldOffset(0)]
        public IntPtr int64;

        /// <summary>
        /// A single-precision floating-point value.
        /// </summary>
        [FieldOffset(0)]
        public float float32;

        /// <summary>
        /// A pointer to a double-precision floating-point value.
        /// </summary>
        [FieldOffset(0)]
        public IntPtr double64;

        /// <summary>
        /// A pointer to an array containing a variable number of bytes.
        /// </summary>
        [FieldOffset(0)]
        public IntPtr byteBlob;

        /// <summary>
        /// A pointer to a byte array of constant length.
        /// </summary>
        [FieldOffset(0)]
        public IntPtr byteArray16;

        /// <summary>
        /// A pointer to a byte array of constant length.
        /// </summary>
        [FieldOffset(0)]
        public IntPtr byteArray6;

        /// <summary>
        /// A pointer to a security descriptor.
        /// </summary>
        [FieldOffset(0)]
        public IntPtr sd;

        /// <summary>
        /// A pointer to an IPv4 address structure.
        /// </summary>
        [FieldOffset(0)]
        public IntPtr v4AddrMask;

        /// <summary>
        /// A pointer to an IPv6 address structure.
        /// </summary>
        [FieldOffset(0)]
        public IntPtr v6AddrMask;
    }

    public readonly ulong? UIntValue => this.Type switch
    {
        FWP_DATA_TYPE.FWP_UINT8 => this.Value.uint8,
        FWP_DATA_TYPE.FWP_UINT16 => this.Value.uint16,
        FWP_DATA_TYPE.FWP_UINT32 => this.Value.uint32,
        FWP_DATA_TYPE.FWP_UINT64 => unchecked((ulong)Marshal.ReadInt64(this.Value.uint64)),
        FWP_DATA_TYPE.FWP_EMPTY => null,
        _ => null,
    };

    public readonly byte? UInt8Value => this.Type switch
    {
        FWP_DATA_TYPE.FWP_UINT8 => this.Value.uint8,
        FWP_DATA_TYPE.FWP_EMPTY => null,
        _ => null,
    };

    public readonly ushort? UInt16Value => this.Type switch
    {
        FWP_DATA_TYPE.FWP_UINT16 => this.Value.uint16,
        FWP_DATA_TYPE.FWP_EMPTY => null,
        _ => null,
    };

    public readonly uint? UInt32Value => this.Type switch
    {
        FWP_DATA_TYPE.FWP_UINT32 => this.Value.uint32,
        FWP_DATA_TYPE.FWP_EMPTY => null,
        _ => null,
    };

    public readonly ulong? UInt64Value => this.Type switch
    {
        FWP_DATA_TYPE.FWP_UINT64 => unchecked((ulong)Marshal.ReadInt64(this.Value.uint64)),
        FWP_DATA_TYPE.FWP_EMPTY => null,
        _ => null,
    };

    public readonly long? IntValue => this.Type switch
    {
        FWP_DATA_TYPE.FWP_INT8 => this.Value.int8,
        FWP_DATA_TYPE.FWP_INT16 => this.Value.int16,
        FWP_DATA_TYPE.FWP_INT32 => this.Value.int32,
        FWP_DATA_TYPE.FWP_INT64 => Marshal.ReadInt64(this.Value.int64),
        // Shorter unsigned values will fit into 64-bit signed integer
        FWP_DATA_TYPE.FWP_UINT8 => this.Value.uint8,
        FWP_DATA_TYPE.FWP_UINT16 => this.Value.uint16,
        FWP_DATA_TYPE.FWP_UINT32 => this.Value.uint32,
        FWP_DATA_TYPE.FWP_EMPTY => null,
        _ => null,
    };

    public readonly sbyte? Int8Value => this.Type switch
    {
        FWP_DATA_TYPE.FWP_INT8 => this.Value.int8,
        FWP_DATA_TYPE.FWP_EMPTY => null,
        _ => null,
    };

    public readonly short? Int16Value => this.Type switch
    {
        FWP_DATA_TYPE.FWP_INT16 => this.Value.int16,
        FWP_DATA_TYPE.FWP_EMPTY => null,
        _ => null,
    };

    public readonly int? Int32Value => this.Type switch
    {
        FWP_DATA_TYPE.FWP_INT32  => this.Value.int32,
        FWP_DATA_TYPE.FWP_EMPTY => null,
        _ => null,
    };

    public readonly long? Int64Value => this.Type switch
    {
        FWP_DATA_TYPE.FWP_INT64 => Marshal.ReadInt64(this.Value.int64),
        FWP_DATA_TYPE.FWP_EMPTY => null,
        _ => null,
    };

    public readonly float? FloatValue => this.Type switch
    {
        FWP_DATA_TYPE.FWP_FLOAT => this.Value.float32,
        FWP_DATA_TYPE.FWP_EMPTY => null,
        _ => null,
    };

    public readonly Guid? GuidValue => this.Type switch
    {
        FWP_DATA_TYPE.FWP_BYTE_ARRAY16_TYPE => Marshal.PtrToStructure<Guid>(this.Value.byteArray16),
        FWP_DATA_TYPE.FWP_EMPTY => null,
        _ => null,
    };

    public readonly (IPAddress? address, byte? prefixLength) IPAddressAndMaskValue
    {
        get
        {
            if (this.Type == FWP_DATA_TYPE.FWP_V4_ADDR_MASK)
            {
                var addrAndMask = Marshal.PtrToStructure<FWP_V4_ADDR_AND_MASK>(this.Value.v4AddrMask);
                return (addrAndMask.Address, addrAndMask.PrefixLength);
            }
            else if (this.Type == FWP_DATA_TYPE.FWP_V6_ADDR_MASK)
            {
                var addrAndMask = Marshal.PtrToStructure<FWP_V6_ADDR_AND_MASK>(this.Value.v6AddrMask);
                return (addrAndMask.Address, addrAndMask.PrefixLength);
            }
            else
            {
                return (null, null);
            }
        }
    }

    public readonly byte[]? ByteArrayValue
    {
        get
        {
            if (this.Type == FWP_DATA_TYPE.FWP_BYTE_ARRAY16_TYPE)
            {
                byte[] byteArray = new byte[16];
                Marshal.Copy(this.Value.byteArray16, byteArray, 0, 16);
                return byteArray;
            }
            else if (this.Type == FWP_DATA_TYPE.FWP_BYTE_ARRAY6_TYPE)
            {
                byte[] byteArray = new byte[6];
                Marshal.Copy(this.Value.byteArray6, byteArray, 0, 6);
                return byteArray;
            }
            else if (this.Type == FWP_DATA_TYPE.FWP_BYTE_BLOB_TYPE)
            {
                return Marshal.PtrToStructure<FWP_BYTE_BLOB_PTR>(this.Value.byteBlob).Data;
            }
            else
            {
                return null;
            }
        }
    }

    public readonly RawSecurityDescriptor? SecurityDescriptorValue
    {
        get
        {
            if (this.Type == FWP_DATA_TYPE.FWP_SECURITY_DESCRIPTOR_TYPE)
            {
                var blob = Marshal.PtrToStructure<FWP_BYTE_BLOB_PTR>(this.Value.sd);
                byte[]? binaryForm = blob.Data;

                if (binaryForm != null)
                {
                    return new RawSecurityDescriptor(binaryForm, 0);
                }
            }

            // In all other cases
            return null;
        }
    }

    public readonly string? StringValue
    {
        get
        {
            if (this.Type == FWP_DATA_TYPE.FWP_BYTE_BLOB_TYPE)
            {
                byte[]? data = this.ByteArrayValue;

                if(data != null)
                {
                   // Remover the trailing null character
                   return System.Text.Encoding.Unicode.GetString(data, 0, data.Length - sizeof(char));
                }
            }

            // In all other cases
            return null;
        }
    }

    public FWP_VALUE0()
    {
        this.Type = FWP_DATA_TYPE.FWP_EMPTY;
    }

    public FWP_VALUE0(byte value)
    {
        this.Type = FWP_DATA_TYPE.FWP_UINT8;
        this.Value.uint8 = value;
    }

    public FWP_VALUE0(ushort value)
    {
        this.Type = FWP_DATA_TYPE.FWP_UINT16;
        this.Value.uint16 = value;
    }

    public FWP_VALUE0(uint value)
    {
        this.Type = FWP_DATA_TYPE.FWP_UINT32;
        this.Value.uint32 = value;
    }

    private FWP_VALUE0(FWP_DATA_TYPE pointerType, SafeHandle memoryHandle)
    {
        this.Type = pointerType;
        this.Value.byteBlob = memoryHandle.DangerousGetHandle();
    }

    public static (FWP_VALUE0 nativeValue, SafeHandle memoryHandle) Allocate(Guid value)
    {
        var memoryHandle = new SafeStructHandle<Guid>(value);
        var valueWrapper = new FWP_VALUE0(FWP_DATA_TYPE.FWP_BYTE_ARRAY16_TYPE, memoryHandle);

        return (valueWrapper, memoryHandle);
    }

    public static (FWP_VALUE0 nativeValue, SafeHandle memoryHandle) Allocate(string value)
    {
        var blob = new FWP_BYTE_BLOB_STRING(value);
        var memoryHandle = new SafeStructHandle<FWP_BYTE_BLOB_STRING>(blob);
        var valueWrapper = new FWP_VALUE0(FWP_DATA_TYPE.FWP_BYTE_BLOB_TYPE, memoryHandle);

        return (valueWrapper, memoryHandle);
    }
    public static (FWP_VALUE0 nativeValue, SafeHandle memoryHandleOuter, SafeHandle memoryHandleInner) Allocate(RawSecurityDescriptor value)
    {
        // Convert the string to binary
        byte[] binaryValue = new byte[value.BinaryLength];
        value.GetBinaryForm(binaryValue, 0);
        var securityDescriptorHandle = new SafeByteArrayHandle(binaryValue);

        var blob = new FWP_BYTE_BLOB_PTR(securityDescriptorHandle, (uint)binaryValue.Length);
        var blobHandle = new SafeStructHandle<FWP_BYTE_BLOB_PTR>(blob);
        var valueWrapper = new FWP_VALUE0(FWP_DATA_TYPE.FWP_SECURITY_DESCRIPTOR_TYPE, blobHandle);

        return (valueWrapper, blobHandle, securityDescriptorHandle);
    }

    public static (FWP_VALUE0 nativeValue, SafeHandle? memoryHandle) Allocate(IPAddress address, byte? mask)
    {
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            if (mask.HasValue && mask.Value != FWP_V4_ADDR_AND_MASK.MaxIpv4PrefixLength)
            {
                // IPV4 address and mask
                var v4AddrMask = new FWP_V4_ADDR_AND_MASK(address, mask.Value);
                var v4AddrMaskHandle = new SafeStructHandle<FWP_V4_ADDR_AND_MASK>(v4AddrMask);
                var nativeValue = new FWP_VALUE0(FWP_DATA_TYPE.FWP_V4_ADDR_MASK, v4AddrMaskHandle);
                return (nativeValue, v4AddrMaskHandle);
            }
            else
            {
                // IPV4 address only
                byte[] binaryAddress = address.GetAddressBytes();
                uint byteAddress = BitConverter.ToUInt32(binaryAddress, 0);
                var nativeValue = new FWP_VALUE0(byteAddress);
                return (nativeValue, null);
            }
        }
        else if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (mask.HasValue && mask.Value != FWP_V6_ADDR_AND_MASK.MaxIpv6PrefixLength)
            {
                // IPV6 address and mask
                var v6AddrMask = new FWP_V6_ADDR_AND_MASK(address, mask.Value);
                var v6AddrMaskHandle = new SafeStructHandle<FWP_V6_ADDR_AND_MASK>(v6AddrMask);
                var nativeValue = new FWP_VALUE0(FWP_DATA_TYPE.FWP_V6_ADDR_MASK, v6AddrMaskHandle);
                return (nativeValue, v6AddrMaskHandle);
            }
            else
            {
                // IPV6 address only
                byte[] binaryAddress = address.GetAddressBytes();
                (var nativeValue, var memoryHandle, _) = FWP_VALUE0.Allocate(binaryAddress);
                return (nativeValue, memoryHandle);
            }
        }
        else
        {
            throw new ArgumentException("Address must be IPv4 or IPv6.", nameof(address));
        }
    }

    public static (FWP_VALUE0 nativeValue, SafeHandle memoryHandle1, SafeHandle? memoryHandle2) Allocate(byte[] value)
    {
        if(value == null)
        {
            throw new ArgumentNullException(nameof(value));
        }

        var dataHandle = new SafeByteArrayHandle(value);

        if (value.Length == 6)
        {
            var array6Value = new FWP_VALUE0(FWP_DATA_TYPE.FWP_BYTE_ARRAY6_TYPE, dataHandle);
            return (array6Value, dataHandle, null);
        }
        else if(value.Length == 16)
        {
            var array16Value = new FWP_VALUE0(FWP_DATA_TYPE.FWP_BYTE_ARRAY16_TYPE, dataHandle);
            return (array16Value, dataHandle, null);
        }
        else
        {
            var blob = new FWP_BYTE_BLOB_PTR(dataHandle, (uint)value.Length);
            var blobHandle = new SafeStructHandle<FWP_BYTE_BLOB_PTR>(blob);
            var blobValue = new FWP_VALUE0(FWP_DATA_TYPE.FWP_BYTE_BLOB_TYPE, blobHandle);
            return (blobValue, dataHandle, blobHandle);
        }
    }
}
