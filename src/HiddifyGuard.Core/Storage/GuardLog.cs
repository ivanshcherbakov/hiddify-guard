using System.Text;
using HiddifyGuard.Core.Native;

namespace HiddifyGuard.Core.Storage;

public sealed class GuardLog(ConfigStore store)
{
    public const long MaxBytes = 2 * 1024 * 1024;
    private readonly object sync = new();
    public void Write(string operation, Exception? error = null)
    {
        // Only fixed operation labels and error codes; never URLs, DNS queries or traffic.
        var line = $"{DateTimeOffset.UtcNow:O} {operation} " +
            (error is WfpException wfp ? $"0x{wfp.Status:X8}" : error?.GetType().Name ?? "OK") + Environment.NewLine;
        lock (sync)
        {
            try
            {
                store.PrepareDirectory();
                var folder = Path.Combine(store.Root, "logs");
                Directory.CreateDirectory(folder);
                if ((File.GetAttributes(folder) & FileAttributes.ReparsePoint) != 0) return;
                var path = Path.Combine(folder, "guard.log");
                if (File.Exists(path) && (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) return;
                if (File.Exists(path) && new FileInfo(path).Length + Encoding.UTF8.GetByteCount(line) > MaxBytes)
                    File.Move(path, path + ".1", true);
                File.AppendAllText(path, line, new UTF8Encoding(false));
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.Security.SecurityException)
            { /* Logging failure never changes the firewall policy. */ }
        }
    }
}
