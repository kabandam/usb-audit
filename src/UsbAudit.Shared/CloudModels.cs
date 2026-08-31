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

public sealed class TerminalHeartbeat
{
    public string TerminalId { get; set; } = string.Empty;
    public string ComputerName { get; set; } = string.Empty;
    public string WindowsUser { get; set; } = string.Empty;
    public string AppVersion { get; set; } = string.Empty;
    public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.Now;
    public List<ConnectedUsbDevice> ConnectedDevices { get; set; } = [];
}

public sealed class CloudUploadBatch
{
    public TerminalHeartbeat Terminal { get; set; } = new();
    public List<AuditEvent> Events { get; set; } = [];
}

public sealed class CloudUploadResponse
{
    public bool Ok { get; set; }
    public int Accepted { get; set; }
    public string? TerminalId { get; set; }
    public string? ReceivedAt { get; set; }
    public string? IssuedToken { get; set; }
}
