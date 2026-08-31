using System.Diagnostics;
using System.Reflection;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
using UsbAudit.Shared;

namespace UsbAudit.App;

public partial class MainWindow : Window
{
    private readonly DispatcherTimer _timer;
    private bool _connectionSettingsLoaded;

    private static SolidColorBrush Brush(byte r, byte g, byte b) => new(Color.FromRgb(r, g, b));

    public MainWindow()
    {
        InitializeComponent();
        StoragePaths.EnsureDirectories();
        LoadConnectionSettings();
        RefreshData();

        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3) };
        _timer.Tick += (_, _) => RefreshData();
        _timer.Start();
    }

    private void RefreshData()
    {
        try
        {
            var status = JsonStorage.LoadTerminalStatus();
            var cloud = JsonStorage.LoadCloudState();
            var settings = JsonStorage.LoadSettings();
            var devices = JsonStorage.ReadConnectedDevices();

            var heartbeatFresh = DateTimeOffset.Now - status.LastHeartbeatAt < TimeSpan.FromSeconds(10);
            var running = status.AgentRunning && heartbeatFresh;
            AgentStatusText.Text = running ? "Monitoring" : "Agent offline";
            AgentDot.Fill = running ? Brush(0x12, 0xB7, 0x6A) : Brush(0xF0, 0x44, 0x38);
            AgentBadge.Background = running ? Brush(0xEC, 0xFD, 0xF3) : Brush(0xFE, 0xF3, 0xF2);

            UsbCountText.Text = devices.Count.ToString();
            CloudStateText.Text = settings.CloudSyncEnabled ? cloud.State : "Disabled";
            PendingEventsText.Text = cloud.PendingEvents.ToString();
            LastSyncText.Text = cloud.LastSuccessAt is null
                ? "Never"
                : cloud.LastSuccessAt.Value.LocalDateTime.ToString("dd MMM HH:mm:ss");

            LastActivityText.Text = string.IsNullOrWhiteSpace(status.LastEventSummary)
                ? "Waiting for USB activity"
                : status.LastEventSummary;
            LastActivityTimeText.Text = status.LastEventAt is null
                ? string.Empty
                : status.LastEventAt.Value.LocalDateTime.ToString("dd MMM yyyy HH:mm:ss");

            ConnectedDevicesList.ItemsSource = devices.Select(x => new DeviceRow
            {
                DriveLetter = x.DriveLetter,
                DeviceName = string.IsNullOrWhiteSpace(x.DeviceName) ? "USB storage" : x.DeviceName,
                Detail = $"{(string.IsNullOrWhiteSpace(x.VolumeLabel) ? "No label" : x.VolumeLabel)}  •  {(string.IsNullOrWhiteSpace(x.FileSystem) ? "Unknown format" : x.FileSystem)}  •  {Formatting.Bytes(x.TotalSizeBytes)}",
                Connected = x.ConnectedAt.LocalDateTime.ToString("HH:mm")
            }).ToList();
            DeviceListHint.Text = devices.Count == 0 ? "No USB storage connected" : $"{devices.Count} connected";

            TerminalIdText.Text = string.IsNullOrWhiteSpace(settings.TerminalId)
                ? $"Terminal: awaiting enrollment • {Environment.MachineName}"
                : $"Terminal: {settings.TerminalId}";
            var version = Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "unknown";
            VersionText.Text = $"Version {version} • {Environment.MachineName}";

            if (!_connectionSettingsLoaded) LoadConnectionSettings();
            if (!string.IsNullOrWhiteSpace(cloud.Message)) SettingsMessage.Text = cloud.Message;
        }
        catch (Exception ex)
        {
            AgentStatusText.Text = "Status unavailable";
            SettingsMessage.Text = ex.Message;
        }
    }

    private void LoadConnectionSettings()
    {
        var settings = JsonStorage.LoadSettings();
        CloudEnabledCheckBox.IsChecked = settings.CloudSyncEnabled;
        CloudApiTextBox.Text = settings.CloudApiUrl;
        WebConsoleTextBox.Text = settings.WebConsoleUrl;
        TerminalTokenBox.Password = settings.TerminalToken;
        _connectionSettingsLoaded = true;
    }

    private void Refresh_Click(object sender, RoutedEventArgs e) => RefreshData();

    private void SaveConnection_Click(object sender, RoutedEventArgs e)
    {
        var apiUrl = CloudApiTextBox.Text.Trim();
        var webUrl = WebConsoleTextBox.Text.Trim();
        var enabled = CloudEnabledCheckBox.IsChecked == true;

        if (enabled && !IsHttpUrl(apiUrl))
        {
            SettingsMessage.Foreground = Brush(0xB4, 0x23, 0x18);
            SettingsMessage.Text = "Enter a valid HTTPS ingest API URL before enabling cloud sync.";
            return;
        }
        if (!string.IsNullOrWhiteSpace(webUrl) && !IsHttpUrl(webUrl))
        {
            SettingsMessage.Foreground = Brush(0xB4, 0x23, 0x18);
            SettingsMessage.Text = "Enter a valid web console URL.";
            return;
        }
        if (enabled && string.IsNullOrWhiteSpace(TerminalTokenBox.Password))
        {
            SettingsMessage.Foreground = Brush(0xB4, 0x23, 0x18);
            SettingsMessage.Text = "An enrollment token is required for cloud sync.";
            return;
        }

        var settings = JsonStorage.LoadSettings();
        var endpointChanged = !string.Equals(settings.CloudApiUrl, apiUrl, StringComparison.OrdinalIgnoreCase) ||
                              !string.Equals(settings.TerminalToken, TerminalTokenBox.Password, StringComparison.Ordinal);
        settings.CloudSyncEnabled = enabled;
        settings.CloudApiUrl = apiUrl;
        settings.WebConsoleUrl = webUrl;
        settings.TerminalToken = TerminalTokenBox.Password;
        settings.CloudSyncSeconds = 10;
        JsonStorage.SaveSettings(settings);

        if (endpointChanged)
        {
            var state = JsonStorage.LoadCloudState();
            state.BackfillCompleted = false;
            state.State = enabled ? "Queued" : "Disabled";
            state.Message = enabled ? "Connection saved. Preparing audit records for sync." : "Cloud sync disabled.";
            JsonStorage.SaveCloudState(state);
        }

        SettingsMessage.Foreground = Brush(0x02, 0x7A, 0x48);
        SettingsMessage.Text = enabled ? "Connection saved. The background Agent will sync automatically." : "Connection saved. Cloud sync is disabled.";
        RefreshData();
    }

    private void OpenWebConsole_Click(object sender, RoutedEventArgs e)
    {
        var url = JsonStorage.LoadSettings().WebConsoleUrl?.Trim();
        if (!IsHttpUrl(url))
        {
            SettingsMessage.Foreground = Brush(0xB4, 0x23, 0x18);
            SettingsMessage.Text = "Configure the web console URL first.";
            return;
        }

        Process.Start(new ProcessStartInfo { FileName = url!, UseShellExecute = true });
    }

    private void CheckUpdates_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            File.WriteAllText(StoragePaths.UpdateRequestPath, DateTimeOffset.Now.ToString("O"));
            SettingsMessage.Foreground = Brush(0x17, 0x5C, 0xD3);
            SettingsMessage.Text = "Update check requested. The Agent will check GitHub Releases.";
        }
        catch (Exception ex)
        {
            SettingsMessage.Foreground = Brush(0xB4, 0x23, 0x18);
            SettingsMessage.Text = $"Could not request an update check: {ex.Message}";
        }
    }

    private static bool IsHttpUrl(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        return Uri.TryCreate(value, UriKind.Absolute, out var uri) &&
               (uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp);
    }

    protected override void OnClosed(EventArgs e)
    {
        _timer.Stop();
        base.OnClosed(e);
    }

    private sealed class DeviceRow
    {
        public string DriveLetter { get; init; } = string.Empty;
        public string DeviceName { get; init; } = string.Empty;
        public string Detail { get; init; } = string.Empty;
        public string Connected { get; init; } = string.Empty;
    }
}
