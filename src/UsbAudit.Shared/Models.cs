namespace UsbAudit.Shared;

public enum AuditEventKind
{
    UsbWrite,
    UsbRead,
    UsbDelete,
    DeviceConnected,
    DeviceDisconnected,
    AgentStarted,
    AgentStopped,
    Warning
}

public enum TransferDirection
{
    PcToUsb,
    UsbToPc,
    Unknown
}

public sealed class AuditEvent
{
    public string EventId { get; set; } = Guid.NewGuid().ToString("N");
    public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.Now;
    public AuditEventKind Kind { get; set; }
    public TransferDirection Direction { get; set; } = TransferDirection.Unknown;
    public string? WindowsUser { get; set; }
    public string? ComputerName { get; set; }
    public string? DeviceName { get; set; }
    public string? DeviceSerial { get; set; }
    public string? DriveLetter { get; set; }
    public string? VolumeLabel { get; set; }
    public string? FileName { get; set; }
    public string? FilePath { get; set; }
    public string? SourcePath { get; set; }
    public string? DestinationPath { get; set; }
    public long? FileSizeBytes { get; set; }
    public string? Sha256 { get; set; }
    public bool ArchiveCopyCreated { get; set; }
    public string? ArchivePath { get; set; }
    public string Evidence { get; set; } = "Observed";
    public string? Notes { get; set; }
    public string? PreviousRecordHash { get; set; }
    public string? RecordHash { get; set; }
}

public sealed class ConnectedUsbDevice
{
    public string DeviceKey { get; set; } = string.Empty;
    public string DriveLetter { get; set; } = string.Empty;
    public string DeviceName { get; set; } = "USB storage";
    public string? DeviceSerial { get; set; }
    public string? VolumeLabel { get; set; }
    public string? FileSystem { get; set; }
    public long TotalSizeBytes { get; set; }
    public long AvailableFreeSpaceBytes { get; set; }
    public DateTimeOffset ConnectedAt { get; set; } = DateTimeOffset.Now;
}

public sealed class UsbAuditSettings
{
    public bool RetainTransferredFiles { get; set; } = false;
    public int MaximumArchiveFileSizeMb { get; set; } = 100;
    public int RetentionDays { get; set; } = 30;
    public int ArchiveQuotaGb { get; set; } = 10;
    public bool LogDeletes { get; set; } = true;
    public bool MonitorUsbToPcTransfers { get; set; } = true;

    public bool CloudSyncEnabled { get; set; } = false;
    public string CloudApiUrl { get; set; } = string.Empty;
    public string WebConsoleUrl { get; set; } = string.Empty;
    public string TerminalId { get; set; } = string.Empty;
    public string TerminalToken { get; set; } = string.Empty;
    public int CloudSyncSeconds { get; set; } = 10;

    public bool AutoUpdatesEnabled { get; set; } = true;
    public bool AutoInstallUpdates { get; set; } = true;
    public string UpdateRepository { get; set; } = "kabandam/usb-audit";
    public int UpdateCheckHours { get; set; } = 1;
    public string[] ExcludedExtensions { get; set; } = [".tmp", ".part", ".crdownload"];
    public string[] ExcludedDirectoryNames { get; set; } = ["System Volume Information", "$RECYCLE.BIN"];
}

public sealed class UpdateStatus
{
    public DateTimeOffset? LastCheckedAt { get; set; }
    public string CurrentVersion { get; set; } = "1.1.0";
    public string? LatestVersion { get; set; }
    public string State { get; set; } = "Not checked";
    public string? Message { get; set; }
    public string? ReleaseUrl { get; set; }
}
