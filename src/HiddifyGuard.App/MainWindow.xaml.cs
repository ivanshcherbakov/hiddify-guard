using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using HiddifyGuard.Core;
using HiddifyGuard.Core.Policy;
using HiddifyGuard.Core.Storage;
using HiddifyGuard.Core.Discovery;
using HiddifyGuard.Core.Diagnostics;
using Forms = System.Windows.Forms;

namespace HiddifyGuard.App;

public partial class MainWindow : Window, IDisposable
{
    private readonly GuardController controller = new();
    private readonly Strings text = new();
    private readonly bool preview;
    private readonly EventWaitHandle showSignal, quitSignal;
    private readonly NetworkMonitor monitor = new();
    private readonly DispatcherTimer signals = new() { Interval = TimeSpan.FromMilliseconds(250) };
    private readonly Forms.NotifyIcon tray = new() { Text = "Hiddify Guard", Visible = true };
    private System.Drawing.Icon? trayIcon;
    private string? trayColor;
    private GuardStatus? status;
    private bool busy, allowExit, initializing = true, reportedPollError;
    public MainWindow(bool preview, EventWaitHandle showSignal, EventWaitHandle quitSignal, bool minimized = false)
    {
        this.preview = preview;
        this.showSignal = showSignal; this.quitSignal = quitSignal;
        InitializeComponent();
        var settings = new GuardSettings();
        try { if (!preview) settings = controller.Store.Load(); }
        catch (Exception error) { Loaded += (_, _) => ReportError(error); }
        text.Select(settings.Language);
        FolderBox.Text = settings.HiddifyDirectory ?? "";
        AllowLanBox.IsChecked = settings.AllowLan;
        LanguageBox.SelectedIndex = settings.Language == "ru" ? 1 : settings.Language == "en" ? 2 : 0;
        initializing = false;
        ApplyLanguage();
        tray.DoubleClick += (_, _) => ShowWindow();
        monitor.Changed += OnNetworkChanged;
        signals.Tick += (_, _) =>
        {
            if (showSignal.WaitOne(0)) ShowWindow();
            if (quitSignal.WaitOne(0)) Exit();
        };
        Loaded += async (_, _) =>
        {
            await RefreshStatus();
            if (!preview) monitor.Start();
            signals.Start();
            if (minimized) Hide();
        };
        SaveButton.IsEnabled = BrowseButton.IsEnabled = RepairButton.IsEnabled = !preview;
    }
    private void ApplyLanguage()
    {
        Subtitle.Text = text["Subtitle"]; Advanced.Header = text["Advanced"];
        LanguageLabel.Text = text["Language"]; FolderLabel.Text = text["Folder"];
        BrowseButton.Content = text["Browse"]; AllowLanBox.Content = text["AllowLan"];
        LanHelp.Text = text["LanHelp"]; SaveButton.Content = text["Save"]; RepairButton.Content = text["Repair"];
        Footer.Text = text["Footer"]; OpenHiddifyButton.Content = text["OpenHiddify"];
        AutoLanguage.Content = text["Auto"];
        RescanButton.Content = text["Rescan"]; LeakTestButton.Content = text["LeakTest"];
        LogsButton.Content = text["Logs"]; TechnicalNote.Text = text["TunNotice"] + "\n" + text["WifiNotice"];
        var menu = new Forms.ContextMenuStrip();
        menu.Items.Add(text["Show"], null, (_, _) => ShowWindow());
        menu.Items.Add(text["OpenHiddify"], null, (_, _) => OnOpenHiddify(this, new RoutedEventArgs()));
        var disable = menu.Items.Add(text["Disable"], null, async (_, _) => await DisableExplicitly());
        disable.Enabled = !preview;
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add(text["Exit"], null, (_, _) => Exit());
        var old = tray.ContextMenuStrip;
        tray.ContextMenuStrip = menu; old?.Dispose();
        Render();
    }
    private void Render()
    {
        var state = status?.Protection.State;
        var missing = status is not null && GuardVisualStates.Resolve(status) == GuardVisualState.HiddifyNotFound && !preview;
        var on = state is ProtectionState.On or ProtectionState.Degraded;
        var healthy = state == ProtectionState.On && status!.Discovery.TunUp;
        var key = state is null ? "Unknown" : missing ? "Missing" : state == ProtectionState.Off ? "Off" :
            state == ProtectionState.Degraded ? "Degraded" : healthy ? "On" : "Waiting";
        StatusTitle.Text = text[key];
        StatusDetail.Text = preview ? text["Preview"] : missing ? text["MissingDetail"] : state is null ? text["Error"].Trim() :
            text[state == ProtectionState.Off ? "OffDetail" : state == ProtectionState.Degraded ? "DegradedDetail" : healthy ? "OnDetail" : "WaitDetail"];
        var color = missing ? "#CB4444" : healthy ? "#169C68" : on || state is null ? "#D69924" : "#7F8B9D";
        StatusShield.Fill = new SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString(color));
        StatusBadge.Background = new SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString(
            healthy ? "#E2F6EC" : on || state is null ? "#FFF3D5" : "#EDF0F5"));
        ToggleButton.Content = busy ? text["Working"] : text[on ? "Disable" : "Enable"];
        ToggleButton.Background = new SolidColorBrush(on ? System.Windows.Media.Color.FromRgb(190, 61, 63) : System.Windows.Media.Color.FromRgb(37, 99, 235));
        ToggleButton.IsEnabled = !preview && !busy && status is not null;
        OpenHiddifyButton.Content = text[missing ? "Locate" : "OpenHiddify"];
        OpenHiddifyButton.Visibility = missing || on && !healthy ? Visibility.Visible : Visibility.Collapsed;
        ConnectionNote.Text = status is null ? "" :
            text[status.Settings.AllowLan ? "LanOn" : "LanOff"];
        tray.Text = "Hiddify Guard — " + text[key];
        if (trayColor != color)
        {
            var newIcon = ShieldIcon.Create(System.Drawing.ColorTranslator.FromHtml(color));
            tray.Icon = newIcon;
            Icon = System.Windows.Interop.Imaging.CreateBitmapSourceFromHIcon(newIcon.Handle,
                Int32Rect.Empty, System.Windows.Media.Imaging.BitmapSizeOptions.FromEmptyOptions());
            trayIcon?.Dispose(); trayIcon = newIcon; trayColor = color;
        }
        SaveButton.IsEnabled = RepairButton.IsEnabled = BrowseButton.IsEnabled = !preview && !busy;
        RescanButton.IsEnabled = LeakTestButton.IsEnabled = LogsButton.IsEnabled = !preview && !busy;
        AllowLanBox.IsEnabled = FolderBox.IsEnabled = !preview && !busy;
        LanguageBox.IsEnabled = !busy;
        DiscoveryDetail.Text = status is null ? "" : string.Join("\n",
            status.Discovery.Applications.Concat(status.Discovery.TunAddresses.Select(n => "TUN: " + n)));
    }
    private async Task RefreshStatus()
    {
        if (busy) return;
        busy = true;
        try
        {
            status = preview
                ? new(new GuardSettings(), DiscoverySnapshot.Empty, new(ProtectionState.Off, 0, false))
                : await Task.Run(() => controller.Status(refresh: true));
            reportedPollError = false;
        }
        catch (Exception error)
        {
            status = null;
            if (!reportedPollError) { if (!preview) controller.Log.Write("status-error", error); reportedPollError = true; }
        }
        finally { busy = false; Render(); }
    }
    private async Task Operate(Action action)
    {
        if (busy || preview) return;
        busy = true; Render();
        try { await Task.Run(action); }
        catch (Exception error) { ReportError(error); }
        finally { busy = false; await RefreshStatus(); }
    }
    private async void OnToggle(object sender, RoutedEventArgs args)
    {
        if (status is null) return;
        if (status.Protection.State != ProtectionState.Off) await DisableExplicitly();
        else await Operate(() => controller.Enable());
    }
    private async Task DisableExplicitly()
    {
        if (busy || preview) return;
        if (System.Windows.MessageBox.Show(this, text["ConfirmDisable"], "Hiddify Guard",
            MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) == MessageBoxResult.Yes)
            await Operate(controller.Disable);
    }
    private async void OnRepair(object sender, RoutedEventArgs args) => await Operate(() => controller.Enable());
    private async void OnSave(object sender, RoutedEventArgs args)
    {
        var settings = new GuardSettings
        {
            AllowLan = AllowLanBox.IsChecked == true,
            Language = (LanguageBox.SelectedItem as ComboBoxItem)?.Tag as string ?? "auto",
            HiddifyDirectory = string.IsNullOrWhiteSpace(FolderBox.Text) ? null : FolderBox.Text.Trim()
        };
        await Operate(() => controller.SaveSettings(settings));
    }
    private async void OnLanguageChanged(object sender, SelectionChangedEventArgs args)
    {
        if (initializing) return;
        text.Select((LanguageBox.SelectedItem as ComboBoxItem)?.Tag as string ?? "auto");
        ApplyLanguage();
        if (!preview && status is not null)
        {
            var settings = status.Settings with { Language = (LanguageBox.SelectedItem as ComboBoxItem)?.Tag as string ?? "auto" };
            await Operate(() => controller.SaveSettings(settings));
        }
    }
    private void OnBrowse(object sender, RoutedEventArgs args)
    {
        using var dialog = new Forms.FolderBrowserDialog { Description = text["Folder"], UseDescriptionForTitle = true };
        if (dialog.ShowDialog() == Forms.DialogResult.OK) FolderBox.Text = dialog.SelectedPath;
    }
    private async void OnOpenHiddify(object sender, RoutedEventArgs args)
    {
        try
        {
            var directory = status?.Discovery.Directory;
            if (directory is null)
            {
                using var dialog = new Forms.OpenFileDialog { Filter = "Hiddify.exe|Hiddify.exe", Title = text["Locate"] };
                if (dialog.ShowDialog() != Forms.DialogResult.OK) return;
                FolderBox.Text = Path.GetDirectoryName(dialog.FileName) ?? "";
                await Operate(() => controller.SaveSettings((status?.Settings ?? new()) with { HiddifyDirectory = Path.GetDirectoryName(dialog.FileName) }));
                return;
            }
            Process.Start(new ProcessStartInfo(Path.Combine(directory, "Hiddify.exe")) { UseShellExecute = true, WorkingDirectory = directory });
        }
        catch (Exception error) { ReportError(error); }
    }
    private void OnNetworkChanged(object? sender, EventArgs args)
    {
        if (!allowExit && !Dispatcher.HasShutdownStarted)
            Dispatcher.BeginInvoke(new Action(async () => await RefreshStatus()));
    }
    private async void OnLanChanged(object sender, RoutedEventArgs args)
    {
        if (initializing || preview || status is null) return;
        var settings = status.Settings with { AllowLan = AllowLanBox.IsChecked == true };
        await Operate(() => controller.SaveSettings(settings));
        initializing = true;
        AllowLanBox.IsChecked = status?.Settings.AllowLan ?? settings.AllowLan;
        initializing = false;
    }
    private async void OnRescan(object sender, RoutedEventArgs args)
    {
        if (status is null) return;
        var settings = status.Settings with { HiddifyDirectory = null };
        await Operate(() => controller.SaveSettings(settings));
        FolderBox.Text = status?.Discovery.Directory ?? "";
    }
    private async void OnLeakTest(object sender, RoutedEventArgs args)
    {
        if (busy || preview || status is null) return;
        busy = true; Render(); DiagnosticsOutput.Text = text["Testing"];
        try
        {
            var before = status;
            var report = await new LeakTester().RunAsync(before.Protection.State != ProtectionState.Off, before.Discovery.TunUp);
            var after = await Task.Run(() => controller.Status());
            if (before.Protection.State != after.Protection.State || before.Protection.FilterCount != after.Protection.FilterCount ||
                after.Protection.State != ProtectionState.Off && !after.Protection.MatchesPlan ||
                before.Discovery.TunUp != after.Discovery.TunUp)
                report = report with { Verdict = LeakVerdict.Inconclusive };
            DiagnosticsOutput.Text = text["Verdict" + report.Verdict] + "\n" +
                string.Join("\n", report.Probes.Select(p => $"{p.Name}: {text["Probe" + p.Outcome]} ({p.ElapsedMs} ms; {p.Reason})")) +
                (report.ExternalIp is null ? "" : "\n" + text["ExternalIp"] + ": " + report.ExternalIp);
        }
        catch (Exception error) { ReportError(error); }
        finally { busy = false; await RefreshStatus(); }
    }
    private void OnLogs(object sender, RoutedEventArgs args)
    {
        try
        {
            controller.Log.Write("open-logs");
            Process.Start(new ProcessStartInfo("explorer.exe", $"\"{Path.Combine(controller.Store.Root, "logs")}\"") { UseShellExecute = true });
        }
        catch (Exception error) { ReportError(error); }
    }
    private void ShowWindow()
    {
        Show(); WindowState = WindowState.Normal;
        Activate(); Topmost = true; Topmost = false; Focus();
    }
    private void OnClosing(object? sender, CancelEventArgs args)
    {
        if (allowExit) return;
        args.Cancel = true; Hide();
    }
    private void Exit()
    {
        allowExit = true;
        monitor.Dispose(); signals.Stop();
        System.Windows.Application.Current.Shutdown(); // Intentionally no Disable().
    }
    public void ReportError(Exception error)
    {
        if (!preview) controller.Log.Write("gui-error", error);
        System.Windows.MessageBox.Show(this, text["Error"] + error.Message, "Hiddify Guard", MessageBoxButton.OK, MessageBoxImage.Error);
    }
    public void Dispose() { monitor.Dispose(); signals.Stop(); tray.Visible = false; tray.Dispose(); trayIcon?.Dispose(); }
}
