namespace UsbAudit.Shared;

public sealed class TerminalStatus
{
    public DateTimeOffset LastHeartbeatAt { get; set; } = DateTimeOffset.Now;
    public bool AgentRunning { get; set; }
    public int ConnectedUsbCount { get; set; }
    public string? LastEventKind { get; set; }
    public DateTimeOffset? LastEventAt { get; set; }
    public string? LastEventSummary { get; set; }
    public int PendingCloudEvents { get; set; }
    public string CloudState { get; set; } = "Not configured";
    public DateTimeOffset? LastCloudSyncAt { get; set; }
    public string? CloudMessage { get; set; }
}

public sealed class CloudSyncState
{
    public string State { get; set; } = "Not configured";
    public DateTimeOffset? LastAttemptAt { get; set; }
    public DateTimeOffset? LastSuccessAt { get; set; }
    public string? Message { get; set; }
    public int PendingEvents { get; set; }
    public bool BackfillCompleted { get; set; }
}

public sealed class InstalledSoftwareItem
{
    public string Name { get; set; } = string.Empty;
    public string? Version { get; set; }
    public string? Publisher { get; set; }
    public string? InstallLocation { get; set; }
    public string? UninstallCommand { get; set; }
    public List<string> ExecutablePaths { get; set; } = [];
}

public sealed class NetworkSnapshot
{
    public string? NetworkName { get; set; }
    public string? ConnectionType { get; set; }
    public string? AdapterName { get; set; }
    public string? LocalIp { get; set; }
    public string? MacAddress { get; set; }
    public string? GatewayIp { get; set; }
    public List<string> DnsServers { get; set; } = [];
    // Negotiated adapter rate; not a measurement of Internet download/upload throughput.
    public double? LinkSpeedMbps { get; set; }
    public DateTimeOffset ObservedAt { get; set; } = DateTimeOffset.UtcNow;
}

// Permission is granted through the visible Smart Console Windows application.
// The background service only forwards the most recent consented reading.
public sealed class EndpointLocationSnapshot
{
    public bool Enabled { get; set; }
    public string Status { get; set; } = "not_enabled";
    public double? Latitude { get; set; }
    public double? Longitude { get; set; }
    public double? AccuracyMeters { get; set; }
    public string? Source { get; set; }
    public DateTimeOffset? CapturedAt { get; set; }
}

public sealed class EndpointSnapshot
{
    public string? OsName { get; set; }
    public string? OsVersion { get; set; }
    public string? Manufacturer { get; set; }
    public string? Model { get; set; }
    public string? SerialNumber { get; set; }
    public long? TotalMemoryBytes { get; set; }
    public string? ProcessorName { get; set; }
    public string DefenderStatus { get; set; } = "Unknown";
    public bool? FirewallEnabled { get; set; }
    public DateTimeOffset CapturedAt { get; set; } = DateTimeOffset.UtcNow;
    public List<InstalledSoftwareItem> InstalledSoftware { get; set; } = [];
}

public sealed class BlockedSoftwareRule
{
    public string SoftwareKey { get; set; } = string.Empty;
    public string SoftwareName { get; set; } = string.Empty;
    public bool ApprovalRequired { get; set; }
    public string? Publisher { get; set; }
    public string? InstallLocation { get; set; }
    public List<string> ExecutablePaths { get; set; } = [];
}

public sealed class EndpointControlPolicy
{
    public string Mode { get; set; } = "audit";
    public List<BlockedSoftwareRule> BlockedSoftware { get; set; } = [];
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
}

public sealed class ApplicationDeploymentPayload
{
    public Guid DeploymentTaskId { get; set; }
    public Guid DeploymentBatchId { get; set; }
    public Guid AppId { get; set; }
    public string AppName { get; set; } = string.Empty;
    public string AppVersion { get; set; } = string.Empty;
    public string? Publisher { get; set; }
    public string InstallerType { get; set; } = string.Empty;
    public string PackageType { get; set; } = string.Empty;
    public string? PackageUrl { get; set; }
    public string StorageProvider { get; set; } = "https";
    public string? StorageDriveId { get; set; }
    public string? StorageItemId { get; set; }
    public string? StorageWebUrl { get; set; }
    public string? StorageFileName { get; set; }
    public long? FileSizeBytes { get; set; }
    public string? InstallerEntry { get; set; }
    public string Sha256 { get; set; } = string.Empty;
    public string InstallArgs { get; set; } = string.Empty;
    public string InstallMode { get; set; } = "silent";
    public string InstallTrigger { get; set; } = "auto";
    public int InstallTimeoutMinutes { get; set; } = 15;
    public List<int> SuccessCodes { get; set; } = [0, 1641, 3010];
    public int Sequence { get; set; }
    public int Attempt { get; set; } = 1;
}

public sealed class ReceivedApplicationRecord
{
    public Guid CommandId { get; set; }
    public Guid AppId { get; set; }
    public string AppName { get; set; } = string.Empty;
    public string AppVersion { get; set; } = string.Empty;
    public string? Publisher { get; set; }
    public string InstallMode { get; set; } = "silent";
    public string InstallTrigger { get; set; } = "auto";
    public string Stage { get; set; } = "received";
    public int ProgressPercent { get; set; }
    public string? Message { get; set; }
    public DateTimeOffset ReceivedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset LastUpdatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? InstalledAt { get; set; }
}

public sealed class PendingApplicationDeployment
{
    public Guid CommandId { get; set; }
    public Guid DeploymentTaskId { get; set; }
    public Guid DeploymentBatchId { get; set; }
    public Guid AppId { get; set; }
    public string AppName { get; set; } = string.Empty;
    public string AppVersion { get; set; } = string.Empty;
    public string? Publisher { get; set; }
    public string InstallerType { get; set; } = string.Empty;
    public string PackageType { get; set; } = string.Empty;
    public string Sha256 { get; set; } = string.Empty;
    public string CachedPackagePath { get; set; } = string.Empty;
    public string? InstallerEntry { get; set; }
    public string InstallArgs { get; set; } = string.Empty;
    public string InstallMode { get; set; } = "silent";
    public int InstallTimeoutMinutes { get; set; } = 15;
    public List<int> SuccessCodes { get; set; } = [0, 1641, 3010];
    public int Attempt { get; set; } = 1;
    public string State { get; set; } = "ready";
    public string? Message { get; set; }
    public long? FileSizeBytes { get; set; }
    public DateTimeOffset StagedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? InstallRequestedAt { get; set; }
}

public sealed class EndpointCommandEnvelope
{
    public Guid CommandId { get; set; }
    public string CommandType { get; set; } = string.Empty;
    public Dictionary<string, object?> Payload { get; set; } = new();
}

public sealed class EndpointCommandResult
{
    public Guid CommandId { get; set; }
    public string Status { get; set; } = "completed";
    public string? Message { get; set; }
    public Guid? AppId { get; set; }
    public string? PackageSha256 { get; set; }
    public string? DefenderScanStatus { get; set; }
    // The inventory command's cloud result is acknowledged before starting a self-update.
    // Local-only control metadata is never trusted as an instruction from the server.
    [System.Text.Json.Serialization.JsonIgnore]
    public bool ForceManagedUpdateAfterAck { get; set; }
}

public sealed class DeploymentProgressReport
{
    public Guid CommandId { get; set; }
    public Guid DeploymentTaskId { get; set; }
    public int ProgressPercent { get; set; }
    public string Stage { get; set; } = "queued";
    public string? Message { get; set; }
    public int Attempt { get; set; } = 1;
    public string? DefenderScanStatus { get; set; }
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
}

public sealed class TerminalHeartbeat
{
    public string TerminalId { get; set; } = string.Empty;
    public string ComputerName { get; set; } = string.Empty;
    public string WindowsUser { get; set; } = string.Empty;
    public string AppVersion { get; set; } = string.Empty;
    public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.Now;
    public List<ConnectedUsbDevice> ConnectedDevices { get; set; } = [];
    public EndpointSnapshot? Endpoint { get; set; }
    public NetworkSnapshot? Network { get; set; }
    public EndpointLocationSnapshot? Location { get; set; }
    public UpdateStatus? ManagedUpdate { get; set; }
}

public sealed class CloudUploadBatch
{
    public TerminalHeartbeat Terminal { get; set; } = new();
    public List<AuditEvent> Events { get; set; } = [];
    public List<EndpointCommandResult> CommandResults { get; set; } = [];
    public List<DeploymentProgressReport> DeploymentProgress { get; set; } = [];
}

public sealed class CloudUploadResponse
{
    public bool Ok { get; set; }
    public int Accepted { get; set; }
    public string? TerminalId { get; set; }
    public string? ReceivedAt { get; set; }
    public string? IssuedToken { get; set; }
    public List<EndpointCommandEnvelope> Commands { get; set; } = [];
}
