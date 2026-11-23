using System.Runtime.InteropServices;

namespace HiddifyGuard.Core.Native;

public static class WfpConstants
{
    public static readonly Guid ConnectV4 = new("c38d57d1-05a7-4c33-904f-7fbceee60e82");
    public static readonly Guid ConnectV6 = new("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");
    public static readonly Guid LocalAddress = new("d9ee00de-c1ef-4617-bfe3-ffd8f5a08957");
    public static readonly Guid RemoteAddress = new("b235ae9a-1d64-49b8-a44c-5ff3d9095045");
    public static readonly Guid Protocol = new("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7");
    public static readonly Guid LocalPort = new("0c1ba1af-5765-453f-af22-a8f791ac775b");
    public static readonly Guid RemotePort = new("c35a604d-d22b-4e1a-91b4-68f674ee674b");
    public static readonly Guid ApplicationId = new("d78e1e87-8644-4ea5-9437-d809ecefc971");
    public static Guid Layer(bool v6) => v6 ? ConnectV6 : ConnectV4;
}

// Default Windows SDK pack=8. The unions must remain 8-byte aligned on x64.
[StructLayout(LayoutKind.Explicit, Size = 16)]
internal struct FwpValue
{
    [FieldOffset(0)] public uint Type;
    [FieldOffset(8)] public byte UInt8;
    [FieldOffset(8)] public ushort UInt16;
    [FieldOffset(8)] public uint UInt32;
    [FieldOffset(8)] public IntPtr Pointer;
}

[StructLayout(LayoutKind.Explicit, Size = 16)]
internal struct FwpConditionValue
{
    [FieldOffset(0)] public uint Type;
    [FieldOffset(8)] public byte UInt8;
    [FieldOffset(8)] public ushort UInt16;
    [FieldOffset(8)] public IntPtr Pointer;
}

[StructLayout(LayoutKind.Sequential)]
internal struct DisplayData { public IntPtr Name, Description; }
[StructLayout(LayoutKind.Sequential)]
internal struct ByteBlob { public uint Size; public IntPtr Data; }
[StructLayout(LayoutKind.Sequential)]
internal struct V4AddressMask { public uint Address, Mask; }
[StructLayout(LayoutKind.Sequential)]
internal struct V6AddressMask
{
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] Address;
    public byte PrefixLength;
}
[StructLayout(LayoutKind.Sequential)]
internal struct FilterCondition
{
    public Guid FieldKey;
    public uint MatchType; // FWP_MATCH_EQUAL = 0
    public FwpConditionValue Value;
}
[StructLayout(LayoutKind.Sequential)]
internal struct FilterAction { public uint Type; public Guid FilterType; }
[StructLayout(LayoutKind.Explicit, Size = 16)]
internal struct FilterContext
{
    [FieldOffset(0)] public ulong RawContext;
    [FieldOffset(0)] public Guid ProviderContextKey;
}
[StructLayout(LayoutKind.Sequential)]
internal struct NativeFilter
{
    public Guid Key;
    public DisplayData Display;
    public uint Flags;
    public IntPtr ProviderKey;
    public ByteBlob ProviderData;
    public Guid LayerKey, SubLayerKey;
    public FwpValue Weight;
    public uint ConditionCount;
    public IntPtr Conditions;
    public FilterAction Action;
    public FilterContext Context;
    public IntPtr Reserved;
    public ulong Id;
    public FwpValue EffectiveWeight;
}
[StructLayout(LayoutKind.Sequential)]
internal struct NativeProvider
{
    public Guid Key;
    public DisplayData Display;
    public uint Flags;
    public ByteBlob ProviderData;
    public IntPtr ServiceName;
}
[StructLayout(LayoutKind.Sequential)]
internal struct NativeSubLayer
{
    public Guid Key;
    public DisplayData Display;
    public uint Flags;
    public IntPtr ProviderKey;
    public ByteBlob ProviderData;
    public ushort Weight;
}
[StructLayout(LayoutKind.Sequential)]
internal struct FilterEnumTemplate
{
    public IntPtr ProviderKey;
    public Guid LayerKey;
    public uint EnumType, Flags;
    public IntPtr ProviderContextTemplate;
    public uint ConditionCount;
    public IntPtr Conditions;
    public uint ActionMask;
    public IntPtr CalloutKey;
}

public static class WfpAbi
{
    public static void Verify()
    {
        if (!OperatingSystem.IsWindows() || IntPtr.Size != 8)
            throw new PlatformNotSupportedException("Hiddify Guard requires 64-bit Windows.");
        Size<FwpValue>(16); Size<FwpConditionValue>(16); Size<FilterCondition>(40);
        Size<NativeFilter>(200); Size<NativeProvider>(64); Size<NativeSubLayer>(72);
        Size<FilterEnumTemplate>(72); Size<V4AddressMask>(8); Size<V6AddressMask>(17);
        Offset<FwpValue>(nameof(FwpValue.Pointer), 8);
        Offset<FwpConditionValue>(nameof(FwpConditionValue.Pointer), 8);
        Offset<FilterCondition>(nameof(FilterCondition.Value), 24);
        Offset<NativeFilter>(nameof(NativeFilter.ProviderKey), 40);
        Offset<NativeFilter>(nameof(NativeFilter.Weight), 96);
        Offset<NativeFilter>(nameof(NativeFilter.Conditions), 120);
        Offset<NativeFilter>(nameof(NativeFilter.Action), 128);
        Offset<NativeFilter>(nameof(NativeFilter.Context), 152);
        Offset<NativeFilter>(nameof(NativeFilter.Id), 176);
        Offset<NativeFilter>(nameof(NativeFilter.EffectiveWeight), 184);
    }
    private static void Size<T>(int expected) where T : struct
    {
        if (Marshal.SizeOf<T>() != expected)
            throw new TypeLoadException($"Invalid x64 ABI: {typeof(T).Name} size {Marshal.SizeOf<T>()}, expected {expected}.");
    }
    private static void Offset<T>(string name, int expected) where T : struct
    {
        if (Marshal.OffsetOf<T>(name).ToInt32() != expected)
            throw new TypeLoadException($"Invalid x64 ABI: {typeof(T).Name}.{name}.");
    }
}
