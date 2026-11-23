using System.Runtime.InteropServices;
using System.Text;
using HiddifyGuard.Core.Policy;

namespace HiddifyGuard.Core.Native;

public sealed class WfpSession : IWfpSession
{
    private readonly SafeEngineHandle engine;
    public WfpSession()
    {
        WfpAbi.Verify();
        WfpNative.Check(WfpNative.FwpmEngineOpen0(null, 10, IntPtr.Zero, IntPtr.Zero, out engine), "FwpmEngineOpen0");
    }
    public void Begin() => WfpNative.Check(WfpNative.FwpmTransactionBegin0(engine, 0), "FwpmTransactionBegin0");
    public void Commit() => WfpNative.Check(WfpNative.FwpmTransactionCommit0(engine), "FwpmTransactionCommit0");
    public void Abort() => WfpNative.Check(WfpNative.FwpmTransactionAbort0(engine), "FwpmTransactionAbort0");
    public void Dispose() => engine.Dispose(); // Static/persistent policy is NOT removed on handle close.

    public bool ProviderDisabled
    {
        get
        {
            var status = WfpNative.FwpmProviderGetByKey0(engine, GuardIds.Provider, out var pointer);
            try
            {
                if (status == 0x80320005) return true;
                WfpNative.Check(status, "FwpmProviderGetByKey0");
                return (Marshal.PtrToStructure<NativeProvider>(pointer).Flags & 2) != 0;
            }
            finally { if (pointer != IntPtr.Zero) WfpNative.FwpmFreeMemory0(ref pointer); }
        }
    }

    public IReadOnlyList<StoredFilter> Enumerate()
    {
        using var arena = new NativeArena();
        var template = new FilterEnumTemplate
        {
            ProviderKey = arena.Structure(GuardIds.Provider),
            Flags = 8 | 16, // INCLUDE_BOOTTIME | INCLUDE_DISABLED, not just runtime filters.
            ActionMask = uint.MaxValue
        };
        WfpNative.Check(WfpNative.FwpmFilterCreateEnumHandle0(engine, ref template, out var handle),
            "FwpmFilterCreateEnumHandle0");
        var records = new List<StoredFilter>();
        try
        {
            while (true)
            {
                var status = WfpNative.FwpmFilterEnum0(engine, handle, 128, out var entries, out var count);
                try
                {
                    WfpNative.Check(status, "FwpmFilterEnum0");
                    for (var i = 0; i < count; i++)
                    {
                        var pointer = Marshal.ReadIntPtr(entries, checked(i * IntPtr.Size));
                        var filter = Marshal.PtrToStructure<NativeFilter>(pointer);
                        if (filter.ProviderKey == IntPtr.Zero ||
                            Marshal.PtrToStructure<Guid>(filter.ProviderKey) != GuardIds.Provider)
                            throw new InvalidOperationException("WFP returned a filter outside our provider.");
                        var tag = "";
                        if (filter.ProviderData.Size is > 0 and <= 1024 && filter.ProviderData.Data != IntPtr.Zero)
                        {
                            var bytes = new byte[filter.ProviderData.Size];
                            Marshal.Copy(filter.ProviderData.Data, bytes, 0, bytes.Length);
                            tag = Encoding.UTF8.GetString(bytes);
                        }
                        records.Add(new(filter.Key, filter.LayerKey, filter.SubLayerKey, filter.Flags, filter.Action.Type, tag,
                            Marshal.PtrToStringUni(filter.Display.Name) ?? ""));
                    }
                    if (count == 0) break;
                }
                finally { if (entries != IntPtr.Zero) WfpNative.FwpmFreeMemory0(ref entries); }
            }
        }
        finally
        {
            WfpNative.Check(WfpNative.FwpmFilterDestroyEnumHandle0(engine, handle), "FwpmFilterDestroyEnumHandle0");
        }
        return records;
    }

    public void AddProviderAndSubLayer()
    {
        using var arena = new NativeArena();
        var display = new DisplayData
        {
            Name = arena.Unicode("Hiddify Guard"),
            Description = arena.Unicode("Persistent outbound kill switch; disable only by explicit user action.")
        };
        var provider = new NativeProvider
        {
            Key = GuardIds.Provider, Display = display, Flags = 1,
            ProviderData = arena.Blob(GuardIds.Tag), ServiceName = IntPtr.Zero
        };
        WfpNative.Check(WfpNative.FwpmProviderAdd0(engine, ref provider, IntPtr.Zero), "FwpmProviderAdd0");
        var subLayer = new NativeSubLayer
        {
            Key = GuardIds.SubLayer, Display = display, Flags = 1,
            ProviderKey = arena.Structure(GuardIds.Provider), Weight = ushort.MaxValue
        };
        WfpNative.Check(WfpNative.FwpmSubLayerAdd0(engine, ref subLayer, IntPtr.Zero), "FwpmSubLayerAdd0");
    }

    public void Add(FilterRule rule)
    {
        using var arena = new NativeArena();
        var conditions = new List<FilterCondition>();
        if (rule.Local is not null) conditions.Add(Address(WfpConstants.LocalAddress, rule.Local, arena));
        if (rule.Remote is not null) conditions.Add(Address(WfpConstants.RemoteAddress, rule.Remote, arena));
        if (rule.Protocol is { } protocol)
            conditions.Add(new() { FieldKey = WfpConstants.Protocol, Value = new() { Type = 1, UInt8 = protocol } });
        if (rule.LocalPort is { } localPort)
            conditions.Add(new() { FieldKey = WfpConstants.LocalPort, Value = new() { Type = 2, UInt16 = localPort } });
        if (rule.RemotePort is { } remotePort)
            conditions.Add(new() { FieldKey = WfpConstants.RemotePort, Value = new() { Type = 2, UInt16 = remotePort } });
        if (rule.Application is { } app)
            conditions.Add(new() { FieldKey = WfpConstants.ApplicationId, Value = new() { Type = 12, Pointer = arena.AppId(app) } });
        var filter = new NativeFilter
        {
            Key = rule.Id,
            Display = new() { Name = arena.Unicode($"Hiddify Guard / {rule.Key}") },
            Flags = rule.Flags,
            ProviderKey = arena.Structure(GuardIds.Provider),
            ProviderData = arena.Blob(GuardIds.Tag + rule.Fingerprint),
            LayerKey = WfpConstants.Layer(rule.IsV6), SubLayerKey = GuardIds.SubLayer,
            Weight = new() { Type = 4, Pointer = arena.Structure(rule.Weight) }, // FWP_UINT64 is a POINTER.
            ConditionCount = checked((uint)conditions.Count), Conditions = arena.Array(conditions),
            Action = new() { Type = rule.Permit ? 0x1002u : 0x1001u }
        };
        WfpNative.Check(WfpNative.FwpmFilterAdd0(engine, ref filter, IntPtr.Zero, out _),
            $"FwpmFilterAdd0({rule.Key})");
    }

    internal static FilterCondition Address(Guid field, IpNetwork network, NativeArena arena) => new()
    {
        FieldKey = field,
        Value = new()
        {
            Type = network.IsV6 ? 257u : 256u,
            Pointer = network.IsV6
                ? arena.Structure(new V6AddressMask { Address = network.Address.GetAddressBytes(), PrefixLength = network.PrefixLength })
                : arena.Structure(new V4AddressMask { Address = network.V4Address, Mask = network.V4Mask })
        }
    };
    public void DeleteFilter(Guid id) => WfpNative.DeleteCheck(WfpNative.FwpmFilterDeleteByKey0(engine, id), 0x80320003, "FwpmFilterDeleteByKey0");
    public void DeleteSubLayer() => WfpNative.DeleteCheck(WfpNative.FwpmSubLayerDeleteByKey0(engine, GuardIds.SubLayer), 0x80320007, "FwpmSubLayerDeleteByKey0");
    public void DeleteProvider() => WfpNative.DeleteCheck(WfpNative.FwpmProviderDeleteByKey0(engine, GuardIds.Provider), 0x80320005, "FwpmProviderDeleteByKey0");
}
