using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using UsbAudit.Shared;

namespace UsbAudit.App;

public partial class MainWindow : Window
{
    private readonly DispatcherTimer _timer;
    private bool _connectionUnlocked;
    private DateTimeOffset _connectionUnlockedUntil;
    private DateTimeOffset? _verifiedPasswordVersion;
    private string _loadedTerminalToken = string.Empty;
    private int _unlockFailures;
    private DateTimeOffset _unlockRetryAfter;
    private bool _sidebarCollapsed;

    private static SolidColorBrush Brush(byte r, byte g, byte b) => new(Color.FromRgb(r, g, b));

    public MainWindow()
    {
        InitializeComponent();
        StoragePaths.EnsureDirectories();
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
            var update = JsonStorage.LoadUpdateStatus();
            var devices = JsonStorage.ReadConnectedDevices();

            var heartbeatFresh = DateTimeOffset.Now - status.LastHeartbeatAt < TimeSpan.FromSeconds(10);
            var running = status.AgentRunning && heartbeatFresh;
            AgentStatusText.Text = running ? "Monitoring" : "Agent offline";
            AgentDot.Fill = running ? Brush(0x12, 0xB7, 0x6A) : Brush(0xF0, 0x44, 0x38);
            AgentBadge.Background = running ? Brush(0xEC, 0xFD, 0xF3) : Brush(0xFE, 0xF3, 0xF2);

            UsbCountText.Text = devices.Count.ToString();
            CloudStateText.Text = settings.CloudSyncEnabled ? cloud.State : "Disabled";
            CloudConnectionHint.Text = string.IsNullOrWhiteSpace(cloud.Message)
                ? "The agent synchronizes automatically while Windows is running."
                : cloud.Message;
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

            var deployments = JsonStorage.ReadPendingDeployments();
            PendingDeploymentsList.ItemsSource = deployments.Select(item => new DeploymentRow
            {
                CommandId = item.CommandId,
                AppName = string.IsNullOrWhiteSpace(item.AppVersion)
                    ? item.AppName
                    : $"{item.AppName} {item.AppVersion}",
                Status = item.State switch
                {
                    "install_requested" => "Installation queued",
                    "installing" => "Installing",
                    "failed" => "Installation failed — retry available",
                    _ => "Ready to install"
                },
                Detail = $"{(item.InstallMode.Equals("visible", StringComparison.OrdinalIgnoreCase) ? "User-assisted" : "Silent")} install" +
                         (item.FileSizeBytes is > 0 ? $"  •  {Formatting.Bytes(item.FileSizeBytes.Value)}" : string.Empty) +
                         (string.IsNullOrWhiteSpace(item.Message) ? string.Empty : $"  •  {item.Message}"),
                ActionLabel = item.State == "failed" ? "Retry install" :
                              item.State is "install_requested" or "installing" ? "Installing..." : "Install now",
                CanInstall = item.State is "ready" or "failed"
            }).ToList();
            DeploymentListHint.Text = deployments.Count == 0
                ? "No applications waiting"
                : $"{deployments.Count} ready or in progress";

            var received = JsonStorage.ReadReceivedApplications();
            foreach (var pending in deployments)
            {
                if (received.Any(item => item.CommandId == pending.CommandId)) continue;
                received.Add(new ReceivedApplicationRecord
                {
                    CommandId = pending.CommandId,
                    AppId = pending.AppId,
                    AppName = pending.AppName,
                    AppVersion = pending.AppVersion,
                    Publisher = pending.Publisher,
                    InstallMode = pending.InstallMode,
                    InstallTrigger = "manual",
                    Stage = pending.State switch
                    {
                        "install_requested" => "install_requested",
                        "installing" => "installing",
                        "failed" => "failed",
                        _ => "ready_to_install"
                    },
                    ProgressPercent = pending.State == "installing" ? 82 : 80,
                    Message = pending.Message,
                    ReceivedAt = pending.StagedAt,
                    LastUpdatedAt = pending.InstallRequestedAt ?? pending.StagedAt
                });
            }

            var receivedRows = received
                .GroupBy(item => item.AppId != Guid.Empty
                    ? $"app:{item.AppId:N}"
                    : $"name:{item.AppName}|{item.AppVersion}", StringComparer.OrdinalIgnoreCase)
                .Select(group => group.OrderByDescending(item => item.LastUpdatedAt).First())
                .OrderByDescending(item => item.LastUpdatedAt)
                .Take(30)
                .Select(item =>
                {
                    var (statusText, statusBrush) = ReceivedApplicationStatus(item);
                    var versionLabel = string.IsNullOrWhiteSpace(item.AppVersion)
                        ? $"Received {item.ReceivedAt.LocalDateTime:dd MMM HH:mm}"
                        : $"{item.AppVersion}  •  {item.ReceivedAt.LocalDateTime:dd MMM HH:mm}";
                    return new ReceivedApplicationRow
                    {
                        Initial = string.IsNullOrWhiteSpace(item.AppName)
                            ? "A"
                            : item.AppName.Trim()[0].ToString().ToUpperInvariant(),
                        AppName = string.IsNullOrWhiteSpace(item.AppName) ? "Application" : item.AppName,
                        Version = versionLabel,
                        Status = statusText,
                        StatusBrush = statusBrush
                    };
                })
                .ToList();

            ReceivedAppsSidebarList.ItemsSource = receivedRows;
            ReceivedAppsCountText.Text = receivedRows.Count.ToString();
            CollapsedReceivedAppsCountText.Text = receivedRows.Count.ToString();
            ReceivedAppsEmptyText.Visibility = !_sidebarCollapsed && receivedRows.Count == 0
                ? Visibility.Visible
                : Visibility.Collapsed;

            TerminalIdText.Text = string.IsNullOrWhiteSpace(settings.TerminalId)
                ? $"Terminal: awaiting enrollment • {Environment.MachineName}"
                : $"Terminal: {settings.TerminalId}";
            var version = Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "unknown";
            VersionText.Text = $"Version {version} • {Environment.MachineName}";
            SidebarComputerText.Text = Environment.MachineName;
            SidebarVersionText.Text = $"Smart Console {version}";
            var lastChecked = update.LastCheckedAt is null
                ? string.Empty
                : $" • checked {update.LastCheckedAt.Value.LocalDateTime:dd MMM HH:mm}";
            UpdateStatusText.Text = $"{update.State}{lastChecked}" +
                (string.IsNullOrWhiteSpace(update.LatestVersion) ? string.Empty : $" • latest {update.LatestVersion}");
            UpdateStatusText.Foreground = update.State.Contains("failed", StringComparison.OrdinalIgnoreCase) ||
                                          update.State.Contains("error", StringComparison.OrdinalIgnoreCase)
                ? Brush(0xB4, 0x23, 0x18)
                : update.State is "Downloading" or "Installing" or "Checking"
                    ? Brush(0x17, 0x5C, 0xD3)
                    : Brush(0x66, 0x70, 0x85);

            if (_connectionUnlocked &&
                (DateTimeOffset.UtcNow >= _connectionUnlockedUntil ||
                 ConnectionSettingsGuard.Version != _verifiedPasswordVersion))
                LockConnectionSettings();
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
        _loadedTerminalToken = settings.TerminalToken;
        TerminalTokenBox.Password = settings.TerminalToken;

    }

    private void Refresh_Click(object sender, RoutedEventArgs e) => RefreshData();

    private void ForceCloudSync_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var settings = JsonStorage.LoadSettings();
            if (!settings.CloudSyncEnabled || string.IsNullOrWhiteSpace(settings.TerminalToken) ||
                string.IsNullOrWhiteSpace(settings.CloudApiUrl))
            {
                SettingsMessage.Foreground = Brush(0xB4, 0x23, 0x18);
                SettingsMessage.Text = "Cloud sync is not configured. Contact a Smart Console administrator.";
                return;
            }

            File.WriteAllText(StoragePaths.CloudSyncRequestPath, DateTimeOffset.UtcNow.ToString("O"));
            SettingsMessage.Foreground = Brush(0x17, 0x5C, 0xD3);
            SettingsMessage.Text = "Cloud resync requested. The background agent will retry within a few seconds.";
        }
        catch (Exception ex)
        {
            SettingsMessage.Foreground = Brush(0xB4, 0x23, 0x18);
            SettingsMessage.Text = $"Unable to request cloud sync: {ex.Message}";
        }
    }

    private void ActivityExpander_Expanded(object sender, RoutedEventArgs e) => LoadRecentActivities();
    private void RefreshActivities_Click(object sender, RoutedEventArgs e) => LoadRecentActivities();

    private void LoadRecentActivities()
    {
        try
        {
            var rows = JsonStorage.ReadEvents(30)
                .Select(item => new ActivityRow
                {
                    Timestamp = item.Timestamp,
                    Title = item.Kind switch
                    {
                        AuditEventKind.DeviceConnected => "USB device connected",
                        AuditEventKind.DeviceDisconnected => "USB device disconnected",
                        AuditEventKind.UsbWrite => "USB file observed",
                        AuditEventKind.UsbRead => "USB read observed",
                        AuditEventKind.UsbDelete => "USB file deleted",
                        AuditEventKind.AgentStarted => "Monitoring service started",
                        AuditEventKind.AgentStopped => "Monitoring service stopped",
                        _ => "Endpoint warning"
                    },
                    Detail = string.Join(" • ", new[] { item.FileName, item.DeviceName, item.DriveLetter, item.Notes }
                        .Where(value => !string.IsNullOrWhiteSpace(value))),
                    StatusBrush = item.Kind == AuditEventKind.Warning
                        ? Brush(0xF7, 0x90, 0x09) : Brush(0x17, 0x5C, 0xD3)
                }).ToList();

            rows.AddRange(JsonStorage.ReadReceivedApplications().Take(20).Select(item => new ActivityRow
            {
                Timestamp = item.LastUpdatedAt,
                Title = $"Application: {item.AppName}",
                Detail = $"{item.Stage.Replace('_', ' ')}" +
                    (string.IsNullOrWhiteSpace(item.Message) ? string.Empty : $" • {item.Message}"),
                StatusBrush = item.Stage.Equals("failed", StringComparison.OrdinalIgnoreCase)
                    ? Brush(0xF0, 0x44, 0x38) : Brush(0x17, 0x5C, 0xD3)
            }));

            var cloud = JsonStorage.LoadCloudState();
            if (cloud.LastAttemptAt is { } attempted)
                rows.Add(new ActivityRow
                {
                    Timestamp = attempted,
                    Title = $"Cloud connection: {cloud.State}",
                    Detail = cloud.Message ?? string.Empty,
                    StatusBrush = cloud.State.Equals("Offline", StringComparison.OrdinalIgnoreCase)
                        ? Brush(0xF0, 0x44, 0x38) : Brush(0x12, 0xB7, 0x6A)
                });

            var latest = rows.OrderByDescending(item => item.Timestamp).Take(25).ToList();
            RecentActivityList.ItemsSource = latest;
            ActivityEmptyText.Visibility = latest.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        }
        catch (Exception ex)
        {
            RecentActivityList.ItemsSource = null;
            ActivityEmptyText.Text = $"The local activity history is temporarily unavailable: {ex.Message}";
            ActivityEmptyText.Visibility = Visibility.Visible;
        }
    }

    private void UnlockConnection_Click(object sender, RoutedEventArgs e)
    {
        if (DateTimeOffset.UtcNow < _unlockRetryAfter)
        {
            ConnectionAccessMessage.Text = $"Try again after {_unlockRetryAfter.LocalDateTime:HH:mm:ss}.";
            return;
        }

        if (!ConnectionSettingsGuard.IsProvisioned)
        {
            ConnectionAccessMessage.Text =
                "An administrator must set this endpoint's settings password from Managed Endpoints first.";
            ConnectionAccessPasswordBox.Clear();
            return;
        }

        if (!ConnectionSettingsGuard.Verify(ConnectionAccessPasswordBox.Password))
        {
            _unlockFailures++;
            if (_unlockFailures >= 5)
            {
                _unlockRetryAfter = DateTimeOffset.UtcNow.AddSeconds(30);
                _unlockFailures = 0;
            }
            ConnectionAccessMessage.Text = "Incorrect administrator password.";
            ConnectionAccessPasswordBox.Clear();
            return;
        }

        _unlockFailures = 0;
        _connectionUnlocked = true;
        _connectionUnlockedUntil = DateTimeOffset.UtcNow.AddMinutes(5);
        _verifiedPasswordVersion = ConnectionSettingsGuard.Version;
        ConnectionAccessPasswordBox.Clear();
        ConnectionAccessMessage.Text = string.Empty;
        LoadConnectionSettings();
        LockedConnectionPanel.Visibility = Visibility.Collapsed;
        UnlockedConnectionPanel.Visibility = Visibility.Visible;
    }

    private void LockConnection_Click(object sender, RoutedEventArgs e) => LockConnectionSettings();
    private void ConnectionSettings_Collapsed(object sender, RoutedEventArgs e) => LockConnectionSettings();

    private void LockConnectionSettings()
    {
        _connectionUnlocked = false;
        _verifiedPasswordVersion = null;
        CloudApiTextBox.Clear();
        WebConsoleTextBox.Clear();
        TerminalTokenBox.Clear();
        _loadedTerminalToken = string.Empty;
        ConnectionAccessPasswordBox.Clear();
        UnlockedConnectionPanel.Visibility = Visibility.Collapsed;
        LockedConnectionPanel.Visibility = Visibility.Visible;
    }


    private void ToggleSidebar_Click(object sender, RoutedEventArgs e)
    {
        _sidebarCollapsed = !_sidebarCollapsed;

        SidebarColumn.Width = new GridLength(_sidebarCollapsed ? 84 : 226);
        SidebarContentGrid.Margin = _sidebarCollapsed
            ? new Thickness(8, 18, 8, 16)
            : new Thickness(13, 16, 13, 14);

        SidebarBrandText.Visibility = _sidebarCollapsed ? Visibility.Collapsed : Visibility.Visible;
        OverviewLabel.Visibility = _sidebarCollapsed ? Visibility.Collapsed : Visibility.Visible;
        OverviewNav.Padding = _sidebarCollapsed
            ? new Thickness(0, 10, 0, 10)
            : new Thickness(12, 10, 12, 10);
        OverviewNavContent.HorizontalAlignment = _sidebarCollapsed
            ? HorizontalAlignment.Center
            : HorizontalAlignment.Left;

        ApplicationsHeaderGrid.Visibility = _sidebarCollapsed ? Visibility.Collapsed : Visibility.Visible;
        CollapsedAppsBadge.Visibility = _sidebarCollapsed ? Visibility.Visible : Visibility.Collapsed;
        ReceivedApplicationsPanel.Visibility = _sidebarCollapsed ? Visibility.Collapsed : Visibility.Visible;
        SidebarFooter.Visibility = _sidebarCollapsed ? Visibility.Collapsed : Visibility.Visible;

        SidebarToggleButton.Content = _sidebarCollapsed ? "›" : "‹";
        SidebarToggleButton.ToolTip = _sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar";

        if (!_sidebarCollapsed)
        {
            var hasReceivedApps = ReceivedAppsSidebarList.Items.Count > 0;
            ReceivedAppsEmptyText.Visibility = hasReceivedApps ? Visibility.Collapsed : Visibility.Visible;
        }
        else
        {
            ReceivedAppsEmptyText.Visibility = Visibility.Collapsed;
        }
    }

    private void InstallPendingDeployment_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            if (sender is not Button button || button.Tag is null ||
                !Guid.TryParse(button.Tag.ToString(), out var commandId))
                return;

            JsonStorage.RequestPendingDeploymentInstall(commandId);
            SettingsMessage.Foreground = Brush(0x17, 0x5C, 0xD3);
            SettingsMessage.Text = "Installation requested. The Smart Console Agent will start it from the local package cache.";
            RefreshData();
        }
        catch (Exception ex)
        {
            SettingsMessage.Foreground = Brush(0xB4, 0x23, 0x18);
            SettingsMessage.Text = $"Could not start the application installation: {ex.Message}";
        }
    }

    private void SaveConnection_Click(object sender, RoutedEventArgs e)
    {
        if (!_connectionUnlocked || DateTimeOffset.UtcNow >= _connectionUnlockedUntil ||
            ConnectionSettingsGuard.Version != _verifiedPasswordVersion)
        {
            LockConnectionSettings();
            SettingsMessage.Foreground = Brush(0xB4, 0x23, 0x18);
            SettingsMessage.Text = "Settings access has expired. Enter the administrator password again.";
            return;
        }
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
        // The service may rotate issued terminal credentials while this settings page is open.
        // Preserve that rotation unless the administrator actually entered a different token.
        var savedToken = string.Equals(TerminalTokenBox.Password, _loadedTerminalToken, StringComparison.Ordinal)
            ? settings.TerminalToken : TerminalTokenBox.Password;
        var endpointChanged = !string.Equals(settings.CloudApiUrl, apiUrl, StringComparison.OrdinalIgnoreCase) ||
                              !string.Equals(settings.TerminalToken, savedToken, StringComparison.Ordinal);
        settings.CloudSyncEnabled = enabled;
        settings.CloudApiUrl = apiUrl;
        settings.WebConsoleUrl = webUrl;
        settings.TerminalToken = savedToken;
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
        LockConnectionSettings();
        ConnectionSettingsExpander.IsExpanded = false;
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
            var currentVersion = Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "unknown";
            JsonStorage.SaveUpdateStatus(new UpdateStatus
            {
                LastCheckedAt = DateTimeOffset.Now,
                CurrentVersion = currentVersion,
                State = "Queued",
                Message = "Manual update check queued for the Smart Console Agent."
            });
            UpdateStatusText.Foreground = Brush(0x17, 0x5C, 0xD3);
            UpdateStatusText.Text = "Queued • the Agent will check within a few seconds";
            SettingsMessage.Foreground = Brush(0x17, 0x5C, 0xD3);
            SettingsMessage.Text = "Update check queued. Smart Console will download and install a newer managed release automatically.";
        }
        catch (Exception ex)
        {
            SettingsMessage.Foreground = Brush(0xB4, 0x23, 0x18);
            SettingsMessage.Text = $"Could not request an update check: {ex.Message}";
        }
    }

    private static (string Text, SolidColorBrush Brush) ReceivedApplicationStatus(ReceivedApplicationRecord item)
    {
        var stage = (item.Stage ?? string.Empty).Trim().ToLowerInvariant();
        return stage switch
        {
            "completed" => ("Installed", Brush(0x12, 0xB7, 0x6A)),
            "ready_to_install" => ("Ready to install", Brush(0x53, 0xB1, 0xFD)),
            "install_requested" => ("Install queued", Brush(0xF7, 0x90, 0x09)),
            "installing" or "visible_install" or "finalizing" => ("Installing", Brush(0xF7, 0x90, 0x09)),
            "downloading" => ($"Downloading {Math.Clamp(item.ProgressPercent, 0, 100)}%", Brush(0x53, 0xB1, 0xFD)),
            "defender_scan" or "verifying_hash" or "hash_verified" or "defender_clean" or "defender_cached" or "extracting" =>
                ("Verifying", Brush(0x7F, 0x56, 0xD9)),
            "failed" => ("Failed", Brush(0xF0, 0x44, 0x38)),
            "retrying" => ("Retrying download", Brush(0xF7, 0x90, 0x09)),
            _ => ("Received", Brush(0x98, 0xA2, 0xB3))
        };
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

    private sealed class ActivityRow
    {
        public DateTimeOffset Timestamp { get; init; }
        public string When => Timestamp.LocalDateTime.ToString("dd MMM HH:mm");
        public string Title { get; init; } = string.Empty;
        public string Detail { get; init; } = string.Empty;
        public SolidColorBrush StatusBrush { get; init; } = Brush(0x17, 0x5C, 0xD3);
    }

    private sealed class ReceivedApplicationRow
    {
        public string Initial { get; init; } = "A";
        public string AppName { get; init; } = string.Empty;
        public string Version { get; init; } = string.Empty;
        public string Status { get; init; } = string.Empty;
        public SolidColorBrush StatusBrush { get; init; } = Brush(0x98, 0xA2, 0xB3);
    }

    private sealed class DeploymentRow
    {
        public Guid CommandId { get; init; }
        public string AppName { get; init; } = string.Empty;
        public string Status { get; init; } = string.Empty;
        public string Detail { get; init; } = string.Empty;
        public string ActionLabel { get; init; } = "Install now";
        public bool CanInstall { get; init; }
    }

    private sealed class DeviceRow
    {
        public string DriveLetter { get; init; } = string.Empty;
        public string DeviceName { get; init; } = string.Empty;
        public string Detail { get; init; } = string.Empty;
        public string Connected { get; init; } = string.Empty;
    }
}
