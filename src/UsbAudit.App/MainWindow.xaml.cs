using System.IO;
using System.Diagnostics;
using System.Reflection;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Win32;
using UsbAudit.Shared;

namespace UsbAudit.App;

public partial class MainWindow : Window
{
    private readonly DispatcherTimer _timer;
    private List<AuditEvent> _events = [];
    private List<TransferRow> _transferRows = [];
    private DateTime _lastChainCheckUtc = DateTime.MinValue;

    private static SolidColorBrush Brush(byte r, byte g, byte b) =>
        new(Color.FromRgb(r, g, b));

    public MainWindow()
    {
        InitializeComponent();
        StoragePaths.EnsureDirectories();
        StoragePathText.Text = StoragePaths.BaseDirectory;
        LoadSettings();
        ShowView(DashboardView, DashboardNav, "Dashboard", "USB activity and transfer evidence");
        RefreshData();

        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(5) };
        _timer.Tick += (_, _) => RefreshData();
        _timer.Start();
    }

    private void RefreshData()
    {
        try
        {
            _events = JsonStorage.ReadEvents(10000);
            var devices = JsonStorage.ReadConnectedDevices();
            _transferRows = _events
                .Where(x => x.Kind == AuditEventKind.UsbWrite)
                .Select(ToTransferRow)
                .ToList();

            var today = DateTime.Today;
            var todayEvents = _events.Where(x => x.Kind == AuditEventKind.UsbWrite && x.Timestamp.LocalDateTime.Date == today).ToList();
            ConnectedCountText.Text = devices.Count.ToString();
            TransfersTodayText.Text = todayEvents.Count.ToString();
            BytesTodayText.Text = Formatting.Bytes(todayEvents.Sum(x => x.FileSizeBytes ?? 0));
            ArchivedCountText.Text = _events.Count(x => x.ArchiveCopyCreated).ToString();
            LastRefreshText.Text = $"Updated {DateTime.Now:HH:mm:ss}";

            RecentDataGrid.ItemsSource = _transferRows.Take(25).ToList();
            DevicesDataGrid.ItemsSource = devices.Select(x => new DeviceRow
            {
                DriveLetter = x.DriveLetter,
                DeviceName = x.DeviceName,
                DeviceSerial = string.IsNullOrWhiteSpace(x.DeviceSerial) ? "—" : x.DeviceSerial,
                VolumeLabel = string.IsNullOrWhiteSpace(x.VolumeLabel) ? "—" : x.VolumeLabel,
                FileSystem = string.IsNullOrWhiteSpace(x.FileSystem) ? "—" : x.FileSystem,
                Capacity = Formatting.Bytes(x.TotalSizeBytes),
                Free = Formatting.Bytes(x.AvailableFreeSpaceBytes),
                Connected = x.ConnectedAt.LocalDateTime.ToString("dd MMM yyyy HH:mm")
            }).ToList();

            DeviceHistoryDataGrid.ItemsSource = _events
                .Where(x => x.Kind is AuditEventKind.DeviceConnected or AuditEventKind.DeviceDisconnected)
                .Select(x => new DeviceHistoryRow
                {
                    Time = x.Timestamp.LocalDateTime.ToString("dd MMM yyyy HH:mm:ss"),
                    Status = x.Kind == AuditEventKind.DeviceConnected ? "Connected" : "Disconnected",
                    User = string.IsNullOrWhiteSpace(x.WindowsUser) ? "—" : x.WindowsUser,
                    Device = string.IsNullOrWhiteSpace(x.DeviceName) ? "USB storage" : x.DeviceName,
                    Serial = string.IsNullOrWhiteSpace(x.DeviceSerial) ? "—" : x.DeviceSerial,
                    Drive = string.IsNullOrWhiteSpace(x.DriveLetter) ? "—" : x.DriveLetter,
                    Volume = string.IsNullOrWhiteSpace(x.VolumeLabel) ? "—" : x.VolumeLabel
                })
                .Take(1000)
                .ToList();

            ArchiveDataGrid.ItemsSource = _events
                .Where(x => x.Kind == AuditEventKind.UsbWrite && x.ArchiveCopyCreated)
                .Select(ToTransferRow)
                .ToList();

            ApplyTransferFilter();
            UpdateAgentStatus();
            UpdateUpdateStatus();
            if (DateTime.UtcNow - _lastChainCheckUtc > TimeSpan.FromSeconds(60))
            {
                var chain = JsonStorage.VerifyAuditChain();
                ChainStatusText.Text = chain.Message;
                ChainStatusText.Foreground = chain.IsValid
                    ? Brush(0x75, 0xE0, 0xA7)
                    : Brush(0xFD, 0xA2, 0x9B);
                _lastChainCheckUtc = DateTime.UtcNow;
            }
        }
        catch (Exception ex)
        {
            LastRefreshText.Text = $"Refresh issue: {ex.Message}";
        }
    }

    private void UpdateUpdateStatus()
    {
        var status = JsonStorage.LoadUpdateStatus();
        var version = Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "1.1.0";
        CurrentVersionText.Text = $"Installed version: {version}";
        LatestVersionText.Text = string.IsNullOrWhiteSpace(status.LatestVersion)
            ? "Latest release: not checked"
            : $"Latest release: {status.LatestVersion}";
        UpdateStatusText.Text = string.IsNullOrWhiteSpace(status.Message)
            ? status.State
            : $"{status.State} — {status.Message}";
        LastUpdateCheckText.Text = status.LastCheckedAt is null
            ? "Last checked: never"
            : $"Last checked: {status.LastCheckedAt.Value.LocalDateTime:dd MMM yyyy HH:mm:ss}";
    }

    private void UpdateAgentStatus()
    {
        var running = false;
        try
        {
            if (File.Exists(StoragePaths.ConnectedDevicesPath))
            {
                running = DateTime.UtcNow - File.GetLastWriteTimeUtc(StoragePaths.ConnectedDevicesPath) < TimeSpan.FromSeconds(9);
            }
        }
        catch { }

        AgentStatusText.Text = running ? "Agent monitoring" : "Agent not detected";
        AgentDot.Fill = running
            ? Brush(0x12, 0xB7, 0x6A)
            : Brush(0xF0, 0x44, 0x38);
    }

    private static TransferRow ToTransferRow(AuditEvent x)
    {
        var direction = x.Direction switch
        {
            TransferDirection.PcToUsb => "PC → USB",
            TransferDirection.UsbToPc => "USB → PC",
            _ => "—"
        };
        var hashShort = string.IsNullOrWhiteSpace(x.Sha256) ? "—" : x.Sha256.Length > 16 ? x.Sha256[..16] + "…" : x.Sha256;
        return new TransferRow
        {
            Time = x.Timestamp.LocalDateTime.ToString("dd MMM yyyy HH:mm:ss"),
            User = string.IsNullOrWhiteSpace(x.WindowsUser) ? "—" : x.WindowsUser,
            Device = string.IsNullOrWhiteSpace(x.DeviceName) ? "USB storage" : x.DeviceName,
            Serial = string.IsNullOrWhiteSpace(x.DeviceSerial) ? "—" : x.DeviceSerial,
            Direction = direction,
            File = string.IsNullOrWhiteSpace(x.FileName) ? "—" : x.FileName,
            Size = Formatting.Bytes(x.FileSizeBytes),
            Archived = x.ArchiveCopyCreated ? "Yes" : "No",
            HashShort = hashShort,
            FullHash = x.Sha256 ?? string.Empty,
            Evidence = x.Evidence,
            ArchivePath = x.ArchivePath ?? "—",
            FilePath = x.FilePath ?? string.Empty,
            Event = x
        };
    }

    private void ApplyTransferFilter()
    {
        if (!IsLoaded || TransferSearchBox is null || DirectionFilter is null) return;
        var query = TransferSearchBox.Text?.Trim() ?? string.Empty;
        var directionIndex = DirectionFilter.SelectedIndex;
        IEnumerable<TransferRow> rows = _transferRows;

        if (directionIndex == 1) rows = rows.Where(x => x.Direction == "PC → USB");
        if (directionIndex == 2) rows = rows.Where(x => x.Direction == "USB → PC");
        if (!string.IsNullOrWhiteSpace(query))
        {
            rows = rows.Where(x =>
                x.File.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                x.User.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                x.Device.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                x.Serial.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                x.FilePath.Contains(query, StringComparison.OrdinalIgnoreCase));
        }
        TransfersDataGrid.ItemsSource = rows.ToList();
    }

    private void ShowView(UIElement view,
        Button activeButton,
        string title,
        string subtitle)
    {
        DashboardView.Visibility = view == DashboardView ? Visibility.Visible : Visibility.Collapsed;
        TransfersView.Visibility = view == TransfersView ? Visibility.Visible : Visibility.Collapsed;
        DevicesView.Visibility = view == DevicesView ? Visibility.Visible : Visibility.Collapsed;
        ArchiveView.Visibility = view == ArchiveView ? Visibility.Visible : Visibility.Collapsed;
        SettingsView.Visibility = view == SettingsView ? Visibility.Visible : Visibility.Collapsed;
        PageTitle.Text = title;
        PageSubtitle.Text = subtitle;

        foreach (var button in new Button[] { DashboardNav, TransfersNav, DevicesNav, ArchiveNav, SettingsNav })
        {
            button.Background = Brushes.Transparent;
            button.Foreground = Brush(0xD0, 0xD5, 0xDD);
        }
        activeButton.Background = Brush(0x1D, 0x29, 0x39);
        activeButton.Foreground = Brushes.White;
    }

    private void DashboardNav_Click(object sender, RoutedEventArgs e) => ShowView(DashboardView, DashboardNav, "Dashboard", "USB activity and transfer evidence");
    private void TransfersNav_Click(object sender, RoutedEventArgs e) => ShowView(TransfersView, TransfersNav, "Transfers", "Search, filter and export observed file transfers");
    private void DevicesNav_Click(object sender, RoutedEventArgs e) => ShowView(DevicesView, DevicesNav, "Devices", "Connected USB storage and connection history");
    private void ArchiveNav_Click(object sender, RoutedEventArgs e) => ShowView(ArchiveView, ArchiveNav, "Archive", "Retained audit copies of files written to USB");
    private void SettingsNav_Click(object sender, RoutedEventArgs e) => ShowView(SettingsView, SettingsNav, "Settings", "Administrator-controlled audit and retention policy");

    private void Filter_Changed(object sender, EventArgs e)
    {
        if (IsLoaded) ApplyTransferFilter();
    }

    private void LoadSettings()
    {
        var settings = JsonStorage.LoadSettings();
        RetainFilesCheckBox.IsChecked = settings.RetainTransferredFiles;
        MaxArchiveSizeTextBox.Text = settings.MaximumArchiveFileSizeMb.ToString();
        RetentionDaysTextBox.Text = settings.RetentionDays.ToString();
        ArchiveQuotaTextBox.Text = settings.ArchiveQuotaGb.ToString();
        LogDeletesCheckBox.IsChecked = settings.LogDeletes;
        AutoUpdatesCheckBox.IsChecked = settings.AutoUpdatesEnabled;
        AutoInstallUpdatesCheckBox.IsChecked = settings.AutoInstallUpdates;
        UpdateRepositoryTextBox.Text = settings.UpdateRepository;
        UpdateCheckHoursTextBox.Text = settings.UpdateCheckHours.ToString();
        SettingsMessage.Text = "Audit-copy retention is currently " + (settings.RetainTransferredFiles ? "enabled." : "disabled.");
    }

    private void SaveSettings_Click(object sender, RoutedEventArgs e)
    {
        if (!int.TryParse(MaxArchiveSizeTextBox.Text, out var maxMb) || maxMb < 1 || maxMb > 10240 ||
            !int.TryParse(RetentionDaysTextBox.Text, out var days) || days < 1 || days > 3650 ||
            !int.TryParse(ArchiveQuotaTextBox.Text, out var quotaGb) || quotaGb < 1 || quotaGb > 2048 ||
            !int.TryParse(UpdateCheckHoursTextBox.Text, out var updateHours) || updateHours < 1 || updateHours > 168)
        {
            SettingsMessage.Text = "Check the numeric values: file size 1–10240 MB, retention 1–3650 days, quota 1–2048 GB, update interval 1–168 hours.";
            SettingsMessage.Foreground = Brush(0xB4, 0x23, 0x18);
            return;
        }

        var repository = UpdateRepositoryTextBox.Text.Trim();
        if (AutoUpdatesCheckBox.IsChecked == true && !IsRepositoryNameValid(repository))
        {
            SettingsMessage.Text = "For automatic updates, enter the GitHub repository as owner/repository.";
            SettingsMessage.Foreground = Brush(0xB4, 0x23, 0x18);
            return;
        }

        var settings = JsonStorage.LoadSettings();
        settings.RetainTransferredFiles = RetainFilesCheckBox.IsChecked == true;
        settings.MaximumArchiveFileSizeMb = maxMb;
        settings.RetentionDays = days;
        settings.ArchiveQuotaGb = quotaGb;
        settings.LogDeletes = LogDeletesCheckBox.IsChecked == true;
        settings.AutoUpdatesEnabled = AutoUpdatesCheckBox.IsChecked == true;
        settings.AutoInstallUpdates = AutoInstallUpdatesCheckBox.IsChecked == true;
        settings.UpdateRepository = repository;
        settings.UpdateCheckHours = updateHours;
        JsonStorage.SaveSettings(settings);
        SettingsMessage.Foreground = Brush(0x02, 0x7A, 0x48);
        SettingsMessage.Text = "Settings saved. The background agent will use them for subsequent events.";
    }

    private void ReloadSettings_Click(object sender, RoutedEventArgs e)
    {
        LoadSettings();
        SettingsMessage.Foreground = Brush(0x66, 0x70, 0x85);
    }

    private void CheckForUpdates_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            StoragePaths.EnsureDirectories();
            File.WriteAllText(StoragePaths.UpdateRequestPath, DateTimeOffset.Now.ToString("O"));
            UpdateStatusText.Text = "Update check requested — the background agent will check GitHub Releases.";
        }
        catch (Exception ex)
        {
            UpdateStatusText.Text = $"Could not request an update check: {ex.Message}";
        }
    }

    private static bool IsRepositoryNameValid(string repository)
    {
        var parts = repository.Trim().Trim('/').Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 2) return false;
        return parts.All(part => part.Length > 0 && part.All(c => char.IsLetterOrDigit(c) || c is '-' or '_' or '.'));
    }

    private void OpenArchive_Click(object sender, RoutedEventArgs e)
    {
        StoragePaths.EnsureDirectories();
        Process.Start(new ProcessStartInfo
        {
            FileName = StoragePaths.ArchiveDirectory,
            UseShellExecute = true
        });
    }

    private void Export_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var dialog = new SaveFileDialog
            {
                Title = "Export USB Audit",
                Filter = "CSV file (*.csv)|*.csv",
                FileName = $"USB-Audit-{DateTime.Now:yyyy-MM-dd-HHmm}.csv",
                AddExtension = true,
                DefaultExt = ".csv"
            };
            if (dialog.ShowDialog(this) != true) return;

            var sb = new StringBuilder();
            sb.AppendLine("EventId,Timestamp,Kind,Direction,WindowsUser,Computer,Device,Serial,Drive,Volume,File,FilePath,SourcePath,DestinationPath,SizeBytes,SHA256,ArchiveCopy,ArchivePath,Evidence,Notes,PreviousRecordHash,RecordHash");
            foreach (var x in _events.OrderBy(x => x.Timestamp))
            {
                sb.AppendLine(string.Join(",", new string[]
                {
                    Csv(x.EventId), Csv(x.Timestamp.ToString("O")), Csv(x.Kind.ToString()), Csv(x.Direction.ToString()),
                    Csv(x.WindowsUser), Csv(x.ComputerName), Csv(x.DeviceName), Csv(x.DeviceSerial), Csv(x.DriveLetter), Csv(x.VolumeLabel),
                    Csv(x.FileName), Csv(x.FilePath), Csv(x.SourcePath), Csv(x.DestinationPath), Csv(x.FileSizeBytes?.ToString()), Csv(x.Sha256),
                    Csv(x.ArchiveCopyCreated ? "Yes" : "No"), Csv(x.ArchivePath), Csv(x.Evidence), Csv(x.Notes), Csv(x.PreviousRecordHash), Csv(x.RecordHash)
                }));
            }
            File.WriteAllText(dialog.FileName, sb.ToString(), new UTF8Encoding(true));
            MessageBox.Show(this, "USB Audit records were exported successfully.", "USB Audit", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"Could not export the audit: {ex.Message}", "USB Audit", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private static string Csv(string? value)
    {
        var text = value ?? string.Empty;
        return '"' + text.Replace("\"", "\"\"") + '"';
    }

    protected override void OnClosed(EventArgs e)
    {
        _timer.Stop();
        base.OnClosed(e);
    }

    private sealed class TransferRow
    {
        public string Time { get; init; } = "";
        public string User { get; init; } = "";
        public string Device { get; init; } = "";
        public string Serial { get; init; } = "";
        public string Direction { get; init; } = "";
        public string File { get; init; } = "";
        public string Size { get; init; } = "";
        public string Archived { get; init; } = "";
        public string HashShort { get; init; } = "";
        public string FullHash { get; init; } = "";
        public string Evidence { get; init; } = "";
        public string ArchivePath { get; init; } = "";
        public string FilePath { get; init; } = "";
        public AuditEvent Event { get; init; } = new();
    }

    private sealed class DeviceRow
    {
        public string DriveLetter { get; init; } = "";
        public string DeviceName { get; init; } = "";
        public string DeviceSerial { get; init; } = "";
        public string VolumeLabel { get; init; } = "";
        public string FileSystem { get; init; } = "";
        public string Capacity { get; init; } = "";
        public string Free { get; init; } = "";
        public string Connected { get; init; } = "";
    }

    private sealed class DeviceHistoryRow
    {
        public string Time { get; init; } = "";
        public string Status { get; init; } = "";
        public string User { get; init; } = "";
        public string Device { get; init; } = "";
        public string Serial { get; init; } = "";
        public string Drive { get; init; } = "";
        public string Volume { get; init; } = "";
    }
}
