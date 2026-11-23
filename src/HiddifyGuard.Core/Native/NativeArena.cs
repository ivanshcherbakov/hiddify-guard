using System.Runtime.InteropServices;
using System.Text;

namespace HiddifyGuard.Core.Native;

internal sealed class NativeArena : IDisposable
{
    private readonly List<IntPtr> allocations = [];
    private readonly List<IntPtr> appIds = [];
    public IntPtr Structure<T>(T value) where T : struct
    {
        var pointer = Marshal.AllocHGlobal(Marshal.SizeOf<T>());
        allocations.Add(pointer);
        Marshal.StructureToPtr(value, pointer, false);
        return pointer;
    }
    public IntPtr Unicode(string text)
    {
        var pointer = Marshal.StringToHGlobalUni(text);
        allocations.Add(pointer);
        return pointer;
    }
    public ByteBlob Blob(string text)
    {
        var bytes = Encoding.UTF8.GetBytes(text);
        var pointer = Marshal.AllocHGlobal(bytes.Length);
        allocations.Add(pointer);
        Marshal.Copy(bytes, 0, pointer, bytes.Length);
        return new() { Data = pointer, Size = checked((uint)bytes.Length) };
    }
    public IntPtr Array<T>(IReadOnlyList<T> values) where T : struct
    {
        if (values.Count == 0) return IntPtr.Zero;
        var size = Marshal.SizeOf<T>();
        var pointer = Marshal.AllocHGlobal(checked(size * values.Count));
        allocations.Add(pointer);
        for (var i = 0; i < values.Count; i++)
            Marshal.StructureToPtr(values[i], pointer + i * size, false);
        return pointer;
    }
    public IntPtr AppId(string path)
    {
        var status = WfpNative.FwpmGetAppIdFromFileName0(Path.GetFullPath(path), out var blob);
        if (blob != IntPtr.Zero) appIds.Add(blob);
        WfpNative.Check(status, "FwpmGetAppIdFromFileName0");
        return blob;
    }
    public void Dispose()
    {
        foreach (var blob in appIds)
        {
            var pointer = blob;
            WfpNative.FwpmFreeMemory0(ref pointer);
        }
        foreach (var pointer in allocations) Marshal.FreeHGlobal(pointer);
    }
}
