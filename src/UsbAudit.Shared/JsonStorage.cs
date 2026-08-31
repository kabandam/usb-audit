using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace UsbAudit.Shared;

public static class JsonStorage
{
    private static readonly object AppendLock = new();
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


    public static void SaveUpdateStatus(UpdateStatus status)
    {
        StoragePaths.EnsureDirectories();
        var temp = StoragePaths.UpdateStatusPath + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(status, Options), Encoding.UTF8);
        File.Move(temp, StoragePaths.UpdateStatusPath, true);
    }

    public static UpdateStatus LoadUpdateStatus()
    {
        StoragePaths.EnsureDirectories();
        if (!File.Exists(StoragePaths.UpdateStatusPath)) return new UpdateStatus();
        try
        {
            var json = File.ReadAllText(StoragePaths.UpdateStatusPath, Encoding.UTF8);
            return JsonSerializer.Deserialize<UpdateStatus>(json, Options) ?? new UpdateStatus();
        }
        catch
        {
            return new UpdateStatus { State = "Status unavailable" };
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
            using var stream = new FileStream(StoragePaths.EventLogPath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
            using var writer = new StreamWriter(stream, new UTF8Encoding(false));
            writer.WriteLine(line);
            _lastRecordHash = auditEvent.RecordHash;
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
            catch
            {
                // Keep reading if a partially written or malformed line is encountered.
            }
        }

        return queue.OrderByDescending(x => x.Timestamp).ToList();
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

                // Legacy V1 records without chain fields are allowed before the first chained record.
                if (string.IsNullOrWhiteSpace(item.RecordHash))
                {
                    expectedPrevious = null;
                    continue;
                }

                if (!string.Equals(item.PreviousRecordHash, expectedPrevious, StringComparison.OrdinalIgnoreCase))
                {
                    return (false, $"Audit chain break at line {lineNumber}");
                }

                var savedHash = item.RecordHash;
                item.RecordHash = null;
                var calculated = ComputeRecordHash(item);
                item.RecordHash = savedHash;
                if (!string.Equals(savedHash, calculated, StringComparison.OrdinalIgnoreCase))
                {
                    return (false, $"Audit record hash mismatch at line {lineNumber}");
                }

                expectedPrevious = savedHash;
            }
            return (true, "Audit chain verified");
        }
        catch (Exception ex)
        {
            return (false, $"Audit verification could not complete: {ex.Message}");
        }
    }

    public static void SaveConnectedDevices(IEnumerable<ConnectedUsbDevice> devices)
    {
        StoragePaths.EnsureDirectories();
        var temp = StoragePaths.ConnectedDevicesPath + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(devices, Options), Encoding.UTF8);
        File.Move(temp, StoragePaths.ConnectedDevicesPath, true);
    }

    public static List<ConnectedUsbDevice> ReadConnectedDevices()
    {
        StoragePaths.EnsureDirectories();
        if (!File.Exists(StoragePaths.ConnectedDevicesPath)) return [];
        try
        {
            var json = File.ReadAllText(StoragePaths.ConnectedDevicesPath, Encoding.UTF8);
            return JsonSerializer.Deserialize<List<ConnectedUsbDevice>>(json, Options) ?? [];
        }
        catch
        {
            return [];
        }
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
}
