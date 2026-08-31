using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace UsbAudit.Shared;

public static class JsonStorage
{
    private static readonly object AppendLock = new();
    private static readonly object CloudQueueLock = new();
    private static string? _lastRecordHash;
    private static bool _hashInitialized;

    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };

    private static readonly JsonSerializerOptions CompactOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public static UsbAuditSettings LoadSettings()
    {
        StoragePaths.EnsureDirectories();
        if (!File.Exists(StoragePaths.SettingsPath))
        {
            var defaults = new UsbAuditSettings();
            SaveSettings(defaults);
            return defaults;
        }

        try
        {
            var json = File.ReadAllText(StoragePaths.SettingsPath, Encoding.UTF8);
            return JsonSerializer.Deserialize<UsbAuditSettings>(json, Options) ?? new UsbAuditSettings();
        }
        catch
        {
            return new UsbAuditSettings();
        }
    }

    public static void SaveSettings(UsbAuditSettings settings)
    {
        StoragePaths.EnsureDirectories();
        var temp = StoragePaths.SettingsPath + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(settings, Options), Encoding.UTF8);
        File.Move(temp, StoragePaths.SettingsPath, true);
    }

    public static void SaveUpdateStatus(UpdateStatus status) => WriteJsonAtomic(StoragePaths.UpdateStatusPath, status);

    public static UpdateStatus LoadUpdateStatus()
    {
        if (!File.Exists(StoragePaths.UpdateStatusPath)) return new UpdateStatus();
        try
        {
            return JsonSerializer.Deserialize<UpdateStatus>(File.ReadAllText(StoragePaths.UpdateStatusPath, Encoding.UTF8), Options)
                   ?? new UpdateStatus();
        }
        catch
        {
            return new UpdateStatus { State = "Status unavailable" };
        }
    }

    public static void SaveTerminalStatus(TerminalStatus status) => WriteJsonAtomic(StoragePaths.TerminalStatusPath, status);

    public static TerminalStatus LoadTerminalStatus()
    {
        if (!File.Exists(StoragePaths.TerminalStatusPath)) return new TerminalStatus();
        try
        {
            return JsonSerializer.Deserialize<TerminalStatus>(File.ReadAllText(StoragePaths.TerminalStatusPath, Encoding.UTF8), Options)
                   ?? new TerminalStatus();
        }
        catch
        {
            return new TerminalStatus { AgentRunning = false, CloudMessage = "Status unavailable" };
        }
    }

    public static void SaveCloudState(CloudSyncState state) => WriteJsonAtomic(StoragePaths.CloudStatePath, state);

    public static CloudSyncState LoadCloudState()
    {
        if (!File.Exists(StoragePaths.CloudStatePath)) return new CloudSyncState();
        try
        {
            return JsonSerializer.Deserialize<CloudSyncState>(File.ReadAllText(StoragePaths.CloudStatePath, Encoding.UTF8), Options)
                   ?? new CloudSyncState();
        }
        catch
        {
            return new CloudSyncState { State = "Status unavailable" };
        }
    }

    public static void AppendEvent(AuditEvent auditEvent)
    {
        StoragePaths.EnsureDirectories();
        lock (AppendLock)
        {
            InitializeLastHash();
            auditEvent.PreviousRecordHash = _lastRecordHash;
            auditEvent.RecordHash = null;
            auditEvent.RecordHash = ComputeRecordHash(auditEvent);

            var line = JsonSerializer.Serialize(auditEvent, CompactOptions);
            AppendLine(StoragePaths.EventLogPath, line);
            _lastRecordHash = auditEvent.RecordHash;

            var settings = LoadSettings();
            if (settings.CloudSyncEnabled || !string.IsNullOrWhiteSpace(settings.CloudApiUrl))
            {
                lock (CloudQueueLock) AppendLine(StoragePaths.CloudOutboxPath, line);
            }
        }
    }

    public static List<AuditEvent> ReadEvents(int maxCount = 5000)
    {
        StoragePaths.EnsureDirectories();
        if (!File.Exists(StoragePaths.EventLogPath)) return [];

        var queue = new Queue<AuditEvent>(Math.Min(maxCount, 5000));
        using var stream = new FileStream(StoragePaths.EventLogPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using var reader = new StreamReader(stream, Encoding.UTF8);
        while (reader.ReadLine() is { } line)
        {
            try
            {
                var item = JsonSerializer.Deserialize<AuditEvent>(line, CompactOptions);
                if (item is null) continue;
                if (queue.Count >= maxCount) queue.Dequeue();
                queue.Enqueue(item);
            }
            catch { }
        }

        return queue.OrderByDescending(x => x.Timestamp).ToList();
    }

    public static List<AuditEvent> ReadCloudOutbox(int maxCount = 250)
    {
        StoragePaths.EnsureDirectories();
        lock (CloudQueueLock)
        {
            if (!File.Exists(StoragePaths.CloudOutboxPath)) return [];
            var items = new List<AuditEvent>(maxCount);
            foreach (var line in File.ReadLines(StoragePaths.CloudOutboxPath, Encoding.UTF8))
            {
                if (items.Count >= maxCount) break;
                try
                {
                    var item = JsonSerializer.Deserialize<AuditEvent>(line, CompactOptions);
                    if (item is not null) items.Add(item);
                }
                catch { }
            }
            return items;
        }
    }

    public static int CloudOutboxCount()
    {
        StoragePaths.EnsureDirectories();
        lock (CloudQueueLock)
        {
            if (!File.Exists(StoragePaths.CloudOutboxPath)) return 0;
            try { return File.ReadLines(StoragePaths.CloudOutboxPath, Encoding.UTF8).Count(); }
            catch { return 0; }
        }
    }

    public static void AcknowledgeCloudOutbox(int count)
    {
        if (count <= 0) return;
        StoragePaths.EnsureDirectories();
        lock (CloudQueueLock)
        {
            if (!File.Exists(StoragePaths.CloudOutboxPath)) return;
            var remaining = File.ReadLines(StoragePaths.CloudOutboxPath, Encoding.UTF8).Skip(count).ToList();
            var temp = StoragePaths.CloudOutboxPath + ".tmp";
            File.WriteAllLines(temp, remaining, new UTF8Encoding(false));
            File.Move(temp, StoragePaths.CloudOutboxPath, true);
        }
    }

    public static void EnsureCloudBackfill(int maxEvents = 5000)
    {
        StoragePaths.EnsureDirectories();
        lock (CloudQueueLock)
        {
            if (File.Exists(StoragePaths.CloudOutboxPath) && new FileInfo(StoragePaths.CloudOutboxPath).Length > 0) return;
            var events = ReadEvents(maxEvents).OrderBy(x => x.Timestamp).ToList();
            if (events.Count == 0) return;
            using var stream = new FileStream(StoragePaths.CloudOutboxPath, FileMode.Create, FileAccess.Write, FileShare.Read);
            using var writer = new StreamWriter(stream, new UTF8Encoding(false));
            foreach (var item in events) writer.WriteLine(JsonSerializer.Serialize(item, CompactOptions));
        }
    }

    public static (bool IsValid, string Message) VerifyAuditChain()
    {
        StoragePaths.EnsureDirectories();
        if (!File.Exists(StoragePaths.EventLogPath)) return (true, "No audit records yet");

        string? expectedPrevious = null;
        var lineNumber = 0;
        try
        {
            using var stream = new FileStream(StoragePaths.EventLogPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var reader = new StreamReader(stream, Encoding.UTF8);
            while (reader.ReadLine() is { } line)
            {
                lineNumber++;
                if (string.IsNullOrWhiteSpace(line)) continue;
                var item = JsonSerializer.Deserialize<AuditEvent>(line, CompactOptions);
                if (item is null) return (false, $"Unreadable audit record at line {lineNumber}");
                if (string.IsNullOrWhiteSpace(item.RecordHash))
                {
                    expectedPrevious = null;
                    continue;
                }
                if (!string.Equals(item.PreviousRecordHash, expectedPrevious, StringComparison.OrdinalIgnoreCase))
                    return (false, $"Audit chain break at line {lineNumber}");

                var savedHash = item.RecordHash;
                item.RecordHash = null;
                var calculated = ComputeRecordHash(item);
                item.RecordHash = savedHash;
                if (!string.Equals(savedHash, calculated, StringComparison.OrdinalIgnoreCase))
                    return (false, $"Audit record hash mismatch at line {lineNumber}");

                expectedPrevious = savedHash;
            }
            return (true, "Audit chain verified");
        }
        catch (Exception ex)
        {
            return (false, $"Audit verification could not complete: {ex.Message}");
        }
    }

    public static void SaveConnectedDevices(IEnumerable<ConnectedUsbDevice> devices) =>
        WriteJsonAtomic(StoragePaths.ConnectedDevicesPath, devices);

    public static List<ConnectedUsbDevice> ReadConnectedDevices()
    {
        StoragePaths.EnsureDirectories();
        if (!File.Exists(StoragePaths.ConnectedDevicesPath)) return [];
        try
        {
            return JsonSerializer.Deserialize<List<ConnectedUsbDevice>>(File.ReadAllText(StoragePaths.ConnectedDevicesPath, Encoding.UTF8), Options) ?? [];
        }
        catch { return []; }
    }

    private static void InitializeLastHash()
    {
        if (_hashInitialized) return;
        _hashInitialized = true;
        _lastRecordHash = null;
        if (!File.Exists(StoragePaths.EventLogPath)) return;
        try
        {
            string? lastHash = null;
            foreach (var line in File.ReadLines(StoragePaths.EventLogPath))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                try
                {
                    var item = JsonSerializer.Deserialize<AuditEvent>(line, CompactOptions);
                    if (!string.IsNullOrWhiteSpace(item?.RecordHash)) lastHash = item.RecordHash;
                }
                catch { }
            }
            _lastRecordHash = lastHash;
        }
        catch { }
    }

    private static string ComputeRecordHash(AuditEvent auditEvent)
    {
        var canonical = JsonSerializer.Serialize(auditEvent, CompactOptions);
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
        return Convert.ToHexString(bytes);
    }

    private static void AppendLine(string path, string line)
    {
        using var stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
        using var writer = new StreamWriter(stream, new UTF8Encoding(false));
        writer.WriteLine(line);
    }

    private static void WriteJsonAtomic<T>(string path, T value)
    {
        StoragePaths.EnsureDirectories();
        var temp = path + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(value, Options), Encoding.UTF8);
        File.Move(temp, path, true);
    }
}
