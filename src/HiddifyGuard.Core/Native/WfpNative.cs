using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace HiddifyGuard.Core.Native;

public sealed class WfpException(string operation, uint status)
    : Exception($"{operation}: 0x{status:X8} ({new Win32Exception(unchecked((int)status)).Message})")
{
    public uint Status { get; } = status;
}

internal sealed class SafeEngineHandle() : SafeHandleZeroOrMinusOneIsInvalid(true)
{
    protected override bool ReleaseHandle() => WfpNative.FwpmEngineClose0(handle) == 0;
}

internal static class WfpNative
{
    private const string Dll = "fwpuclnt.dll";
    internal static void Check(uint status, string operation)
    {
        if (status != 0) throw new WfpException(operation, status);
    }
    internal static void DeleteCheck(uint status, uint notFound, string operation)
    {
        if (status != notFound && status != 1168) Check(status, operation);
    }
    [DllImport(Dll, ExactSpelling = true, CharSet = CharSet.Unicode)]
    internal static extern uint FwpmEngineOpen0(string? server, uint authentication, IntPtr identity,
        IntPtr session, out SafeEngineHandle engine);
    [DllImport(Dll, ExactSpelling = true)]
    internal static extern uint FwpmEngineClose0(IntPtr engine);
    [DllImport(Dll, ExactSpelling = true)]
    internal static extern uint FwpmTransactionBegin0(SafeEngineHandle engine, uint flags);
    [DllImport(Dll, ExactSpelling = true)]
    internal static extern uint FwpmTransactionCommit0(SafeEngineHandle engine);
    [DllImport(Dll, ExactSpelling = true)]
    internal static extern uint FwpmTransactionAbort0(SafeEngineHandle engine);
    [DllImport(Dll, ExactSpelling = true)]
    internal static extern uint FwpmProviderAdd0(SafeEngineHandle engine, ref NativeProvider provider, IntPtr security);
    [DllImport(Dll, ExactSpelling = true)]
    internal static extern uint FwpmProviderGetByKey0(SafeEngineHandle engine, in Guid key, out IntPtr provider);
    [DllImport(Dll, ExactSpelling = true)]
    internal static extern uint FwpmProviderDeleteByKey0(SafeEngineHandle engine, in Guid key);
    [DllImport(Dll, ExactSpelling = true)]
    internal static extern uint FwpmSubLayerAdd0(SafeEngineHandle engine, ref NativeSubLayer subLayer, IntPtr security);
    [DllImport(Dll, ExactSpelling = true)]
    internal static extern uint FwpmSubLayerDeleteByKey0(SafeEngineHandle engine, in Guid key);
    [DllImport(Dll, ExactSpelling = true)]
    internal static extern uint FwpmFilterAdd0(SafeEngineHandle engine, ref NativeFilter filter, IntPtr security, out ulong id);
    [DllImport(Dll, ExactSpelling = true)]
    internal static extern uint FwpmFilterDeleteByKey0(SafeEngineHandle engine, in Guid key);
    [DllImport(Dll, ExactSpelling = true)]
    internal static extern uint FwpmFilterCreateEnumHandle0(SafeEngineHandle engine, ref FilterEnumTemplate template, out IntPtr enumeration);
    [DllImport(Dll, ExactSpelling = true)]
    internal static extern uint FwpmFilterEnum0(SafeEngineHandle engine, IntPtr enumeration,
        uint requested, out IntPtr entries, out uint returned);
    [DllImport(Dll, ExactSpelling = true)]
    internal static extern uint FwpmFilterDestroyEnumHandle0(SafeEngineHandle engine, IntPtr enumeration);
    [DllImport(Dll, ExactSpelling = true, CharSet = CharSet.Unicode)]
    internal static extern uint FwpmGetAppIdFromFileName0(string fileName, out IntPtr appId);
    [DllImport(Dll, ExactSpelling = true)]
    internal static extern void FwpmFreeMemory0(ref IntPtr pointer);
}
