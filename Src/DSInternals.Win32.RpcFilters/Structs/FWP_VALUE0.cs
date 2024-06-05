using System.Runtime.InteropServices;
using Windows.Win32.NetworkManagement.WindowsFilteringPlatform;

namespace DSInternals.Win32.RpcFilters
{
    /// <summary>
    /// Defines a data value that can be one of a number of different data types.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct FWP_VALUE0
    {
        /// <summary>
        /// The type of data for this value.
        /// </summary>
        public FWP_DATA_TYPE Type;

        /// <summary>
        /// Data value.
        /// </summary>
        public FWP_VALUE0_UNION Value;

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
            /// A pointer to an array of exactly 16 bytes.
            /// </summary>
            [FieldOffset(0)]
            public IntPtr byteArray16;

            /*
            /// <summary>
            /// A pointer to an array containing a variable number of bytes.
            /// </summary>
            [FieldOffset(0)]
            [MarshalAs(UnmanagedType.LPStruct)]
            public FWP_BYTE_BLOB byteBlob;

            /// <summary>
            /// /// A pointer to a SID blob.
            /// </summary>
            [FieldOffset(0)]
            [MarshalAs(UnmanagedType.LPStruct)]
            public FWP_BYTE_BLOB sid;

            /// <summary>
            /// A pointer to a security descriptor blob.
            /// </summary>
            [FieldOffset(0)]
            [MarshalAs(UnmanagedType.LPStruct)]
            public FWP_BYTE_BLOB sd;

            /// <summary>
            /// A pointer to a token information.
            /// </summary>
            [FieldOffset(0)]
            public IntPtr tokenInformation;

            /// <summary>
            /// A pointer to a token access information.
            /// </summary>
            [FieldOffset(0)]
            public IntPtr tokenAccessInformation;

            /// <summary>
            /// A pointer to a null-terminated unicode string.
            /// </summary>
            [FieldOffset(0)]
            [MarshalAs(UnmanagedType.LPWStr)]
            public string unicodeString;
            */
            /// <summary>
            /// Reserved.
            /// </summary>
            [FieldOffset(0)]
            public IntPtr byteArray6;
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

        public ulong? UIntValue => this.Type switch
        {
            FWP_DATA_TYPE.FWP_UINT8 => this.Value.uint8,
            FWP_DATA_TYPE.FWP_UINT16 => this.Value.uint16,
            FWP_DATA_TYPE.FWP_UINT32 => this.Value.uint32,
            FWP_DATA_TYPE.FWP_UINT64 => unchecked((ulong)Marshal.ReadInt64(this.Value.uint64)),
            FWP_DATA_TYPE.FWP_EMPTY => null,
            _ => null,
        };

        public byte? UInt8Value => this.Type switch
        {
            FWP_DATA_TYPE.FWP_UINT8 => this.Value.uint8,
            FWP_DATA_TYPE.FWP_EMPTY => null,
            _ => null,
        };

        public ushort? UInt16Value => this.Type switch
        {
            FWP_DATA_TYPE.FWP_UINT16 => this.Value.uint16,
            FWP_DATA_TYPE.FWP_EMPTY => null,
            _ => null,
        };

        public uint? UInt32Value => this.Type switch
        {
            FWP_DATA_TYPE.FWP_UINT32 => this.Value.uint32,
            FWP_DATA_TYPE.FWP_EMPTY => null,
            _ => null,
        };

        public ulong? UInt64Value => this.Type switch
        {
            FWP_DATA_TYPE.FWP_UINT64 => unchecked((ulong)Marshal.ReadInt64(this.Value.uint64)),
            FWP_DATA_TYPE.FWP_EMPTY => null,
            _ => null,
        };

        public long? IntValue => this.Type switch
        {
            FWP_DATA_TYPE.FWP_INT8 => this.Value.int8,
            FWP_DATA_TYPE.FWP_INT16 => this.Value.int16,
            FWP_DATA_TYPE.FWP_INT32 => this.Value.int32,
            FWP_DATA_TYPE.FWP_INT64 => Marshal.ReadInt64(this.Value.int64),
            FWP_DATA_TYPE.FWP_EMPTY => null,
            _ => null,
        };

        public sbyte? Int8Value => this.Type switch
        {
            FWP_DATA_TYPE.FWP_INT8 => this.Value.int8,
            FWP_DATA_TYPE.FWP_EMPTY => null,
            _ => null,
        };

        public short? Int16Value => this.Type switch
        {
            FWP_DATA_TYPE.FWP_INT16 => this.Value.int16,
            FWP_DATA_TYPE.FWP_EMPTY => null,
            _ => null,
        };

        public int? Int32Value => this.Type switch
        {
            FWP_DATA_TYPE.FWP_INT32 => this.Value.int32,
            FWP_DATA_TYPE.FWP_EMPTY => null,
            _ => null,
        };

        public long? Int64Value => this.Type switch
        {
            FWP_DATA_TYPE.FWP_INT64 => Marshal.ReadInt64(this.Value.int64),
            FWP_DATA_TYPE.FWP_EMPTY => null,
            _ => null,
        };

        public float? FloatValue => this.Type switch
        {
            FWP_DATA_TYPE.FWP_FLOAT => this.Value.float32,
            FWP_DATA_TYPE.FWP_EMPTY => null,
            _ => null,
        };

        public Guid? GuidValue => this.Type switch
        {
            FWP_DATA_TYPE.FWP_BYTE_ARRAY16_TYPE => Marshal.PtrToStructure<Guid>(this.Value.byteArray16),
            FWP_DATA_TYPE.FWP_EMPTY => null,
            _ => null,
        };

        public byte[]? ByteArrayValue
        {
            get
            {
                if(this.Type == FWP_DATA_TYPE.FWP_BYTE_ARRAY16_TYPE)
                {
                    byte[] byteArray = new byte[16];
                    Marshal.Copy(this.Value.byteArray16, byteArray, 0, 16);
                    return byteArray;
                }
                else if (this.Type == FWP_DATA_TYPE.FWP_BYTE_ARRAY6_TYPE)
                {
                    byte[] byteArray = new byte[6];
                    Marshal.Copy(this.Value.byteArray16, byteArray, 0, 6);
                    return byteArray;
                }
                else
                {
                    return null;
                }
            }
        }
    }
}
