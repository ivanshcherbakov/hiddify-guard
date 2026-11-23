using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using HiddifyGuard.Core;
using HiddifyGuard.Core.Native;
using HiddifyGuard.Core.Policy;
using HiddifyGuard.Core.Storage;
using HiddifyGuard.Core.Discovery;
using HiddifyGuard.Core.Diagnostics;

namespace HiddifyGuard.App;

internal static class Program
{
    internal static string InstanceSuffix => WindowsIdentity.GetCurrent().User?.Value ?? Environment.UserName;
    internal static string ShowEvent => $@"Local\HiddifyGuard.Show.{InstanceSuffix}";
    internal static string QuitEvent => $@"Local\HiddifyGuard.Quit.{InstanceSuffix}";

    [STAThread]
    public static int Main(string[] args)
    {
        var preview = args.SequenceEqual(["--preview"]);
        var minimized = args.SequenceEqual(["--minimized"]);
        if (args.Length > 0 && !preview && !minimized) return CommandLine(args);
        if (!preview && !GuardController.IsAdministrator())
        {
            System.Windows.MessageBox.Show("Запустите Hiddify Guard от имени администратора.\nRun Hiddify Guard as administrator.", "Hiddify Guard");
            return 5;
        }
        using var instance = new Mutex(true, $@"Local\HiddifyGuard.Gui.{InstanceSuffix}", out var first);
        if (!first)
        {
            Signal(ShowEvent);
            return 0;
        }
        using var show = new EventWaitHandle(false, EventResetMode.AutoReset, ShowEvent);
        using var quit = new EventWaitHandle(false, EventResetMode.AutoReset, QuitEvent);
        var app = new System.Windows.Application { ShutdownMode = System.Windows.ShutdownMode.OnExplicitShutdown };
        var window = new MainWindow(preview, show, quit, minimized);
        app.DispatcherUnhandledException += (_, eventArgs) =>
        {
            // No firewall cleanup here, on exit, or on process teardown.
            window.ReportError(eventArgs.Exception);
            eventArgs.Handled = true;
        };
        try { return app.Run(window); }
        finally { window.Dispose(); instance.ReleaseMutex(); }
    }

    private static int CommandLine(string[] args)
    {
        AttachOutput();
        try
        {
            if (args.Length != 1) throw new ArgumentException("Use --help for supported commands.");
            switch (args[0])
            {
                case "--help":
                    Console.WriteLine("""
                        Hiddify Guard 0.1.0 — Windows x64
                        No arguments       Open the elevated GUI
                        --status           Read WFP status as JSON (no policy changes)
                        --enable           Install/repair protection using saved settings
                        --disable          Explicitly remove all Hiddify Guard WFP objects
                        --uninstall-clean  Stop the current user's tray app and remove our WFP objects
                        --exit-tray        Close the current user's tray app; preserve protection
                        --self-test        Validate x64 ABI and baseline plan without opening WFP
                        --diagnostics      Read-only Hiddify/TUN discovery, without WFP access
                        --leak-test        Explicit TCP/DNS network probes (may take 12 seconds)
                        --minimized        Start the GUI hidden in the system tray
                        --preview          Preview the GUI without WFP access or writes
                        Exit codes: 0 success; 1 failure or possible leak; 2 invalid arguments;
                        3 inconclusive leak test; 5 elevation required.
                        """);
                    return 0;
                case "--self-test":
                case "--diagnostics":
                    WfpAbi.Verify();
                    var plan = PolicyBuilder.Build(true, DiscoverySnapshot.Empty);
                    var discovery = HiddifyDiscovery.Scan(new ConfigStore().Load());
                    Console.WriteLine(JsonSerializer.Serialize(new
                    {
                        x64Abi = "OK", baselineRules = plan.Count, hiddifyDirectory = discovery.Directory,
                        applications = discovery.Applications,
                        tunAddresses = discovery.TunAddresses.Select(n => n.ToString()),
                        lanNetworks = discovery.LanNetworks.Select(n => n.ToString()),
                        tunDetected = discovery.TunUp, hiddifyRunning = discovery.HiddifyRunning,
                        savedPathsValid = HiddifyDiscovery.ValidateSavedPaths(new ConfigStore().Load())
                    }, new JsonSerializerOptions { WriteIndented = true }));
                    return 0;
                case "--status":
                    var status = new GuardController().Status();
                    Console.WriteLine(JsonSerializer.Serialize(new
                    {
                        state = status.Protection.State.ToString(), filters = status.Protection.FilterCount,
                        persistentFilters = status.Protection.PersistentFilters,
                        bootTimeFilters = status.Protection.BootTimeFilters,
                        allowedApplications = status.Protection.AllowedApplications,
                        matchesConfiguration = status.Protection.MatchesPlan,
                        tunDetected = status.Discovery.TunUp, hiddifyRunning = status.Discovery.HiddifyRunning,
                        hiddifyDirectory = status.Discovery.Directory,
                        allowLan = status.Settings.AllowLan, language = status.Settings.Language
                    }, new JsonSerializerOptions { WriteIndented = true }));
                    return 0;
                case "--leak-test":
                    var before = new GuardController().Status();
                    var report = new LeakTester().RunAsync(before.Protection.State != ProtectionState.Off,
                        before.Discovery.TunUp).GetAwaiter().GetResult();
                    var after = new GuardController().Status();
                    if (before.Protection.State != after.Protection.State ||
                        before.Protection.FilterCount != after.Protection.FilterCount ||
                        before.Discovery.TunUp != after.Discovery.TunUp ||
                        after.Protection.State != ProtectionState.Off && !after.Protection.MatchesPlan)
                        report = report with { Verdict = LeakVerdict.Inconclusive };
                    Console.WriteLine(JsonSerializer.Serialize(report, new JsonSerializerOptions
                    {
                        WriteIndented = true, Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() }
                    }));
                    return report.Verdict == LeakVerdict.PossibleLeak ? 1 : report.Verdict == LeakVerdict.Inconclusive ? 3 : 0;
                case "--enable":
                    new GuardController().Enable();
                    Console.WriteLine("Protection enabled.");
                    return 0;
                case "--disable":
                    new GuardController().Disable();
                    Console.WriteLine("Protection disabled by explicit request.");
                    return 0;
                case "--uninstall-clean":
                    GuardController.RequireAdministrator();
                    StopGui();
                    new GuardController().Disable();
                    Console.WriteLine("All Hiddify Guard filters, sublayer and provider removed.");
                    return 0;
                case "--exit-tray":
                    GuardController.RequireAdministrator();
                    StopGui();
                    return 0;
                default: throw new ArgumentException("Unknown command. Use --help.");
            }
        }
        catch (Exception error)
        {
            Console.Error.WriteLine(error.Message);
            if (error is not ArgumentException) new GuardController().Log.Write("cli-error", error);
            return error is UnauthorizedAccessException or WfpException { Status: 5 } ? 5 :
                error is ArgumentException ? 2 : 1;
        }
    }
    private static void Signal(string name)
    {
        try { using var signal = EventWaitHandle.OpenExisting(name); signal.Set(); }
        catch (WaitHandleCannotBeOpenedException) { }
    }
    private static void StopGui()
    {
        Signal(QuitEvent);
        try
        {
            using var instance = Mutex.OpenExisting($@"Local\HiddifyGuard.Gui.{InstanceSuffix}");
            var owned = false;
            try { owned = instance.WaitOne(TimeSpan.FromSeconds(20)); }
            catch (AbandonedMutexException) { owned = true; }
            if (!owned) throw new TimeoutException("The tray app did not exit. Close it and retry.");
            instance.ReleaseMutex();
        }
        catch (WaitHandleCannotBeOpenedException) { }
    }
    private static void AttachOutput()
    {
        // WinExe avoids a console for GUI users. Preserve redirected streams for CLI callers.
        if (GetStdHandle(-11) is var output && (output == IntPtr.Zero || output == new IntPtr(-1)))
        {
            if (!AttachConsole(uint.MaxValue)) return;
            Console.SetOut(new StreamWriter(Console.OpenStandardOutput(), new UTF8Encoding(false)) { AutoFlush = true });
            Console.SetError(new StreamWriter(Console.OpenStandardError(), new UTF8Encoding(false)) { AutoFlush = true });
        }
    }
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AttachConsole(uint processId);
    [DllImport("kernel32.dll")]
    private static extern IntPtr GetStdHandle(int standardHandle);
}
