using System.Collections.Concurrent;
using System.Security.Cryptography;
using UsbAudit.Shared;

namespace UsbAudit.Agent;

internal sealed class UsbDriveMonitor : IDisposable
{
    private readonly ConnectedUsbDevice _device;
    private readonly FileSystemWatcher _watcher;
    private readonly CancellationToken _serviceToken;
    private readonly ConcurrentDictionary<string, CancellationTokenSource> _pending = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, string> _recentFingerprints = new(StringComparer.OrdinalIgnoreCase);
    private volatile bool _disposed;

    public UsbDriveMonitor(ConnectedUsbDevice device, CancellationToken serviceToken)
    {
        _device = device;
        _serviceToken = serviceToken;
        var root = device.DriveLetter + "\\";
        _watcher = new FileSystemWatcher(root)
        {
            IncludeSubdirectories = true,
            NotifyFilter = NotifyFilters.FileName | NotifyFilters.DirectoryName | NotifyFilters.LastWrite | NotifyFilters.Size,
            InternalBufferSize = 64 * 1024,
            EnableRaisingEvents = true
        };
        _watcher.Created += (_, e) => QueueCandidate(e.FullPath);
        _watcher.Changed += (_, e) => QueueCandidate(e.FullPath);
        _watcher.Renamed += (_, e) => QueueCandidate(e.FullPath);
        _watcher.Deleted += (_, e) => LogDelete(e.FullPath);
        _watcher.Error += (_, e) => LogWarning($"Watcher error on {_device.DriveLetter}: {e.GetException()?.Message}");
    }

    private void QueueCandidate(string path)
    {
        if (_disposed || ShouldIgnore(path)) return;

        var cts = CancellationTokenSource.CreateLinkedTokenSource(_serviceToken);
        if (_pending.AddOrUpdate(path, cts, (_, previous) =>
        {
            try { previous.Cancel(); previous.Dispose(); } catch { }
            return cts;
        }) != cts)
        {
            return;
        }

        _ = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(1200, cts.Token);
                await ProcessCandidateAsync(path, cts.Token);
            }
            catch (OperationCanceledException) { }
            catch (Exception ex) { LogWarning($"Could not inspect {path}: {ex.Message}"); }
            finally
            {
                if (_pending.TryGetValue(path, out var current) && ReferenceEquals(current, cts))
                {
                    _pending.TryRemove(path, out _);
                    cts.Dispose();
                }
            }
        }, cts.Token);
    }

    private async Task ProcessCandidateAsync(string path, CancellationToken cancellationToken)
    {
        if (!File.Exists(path) || Directory.Exists(path)) return;
        if (!await WaitForStableFileAsync(path, cancellationToken)) return;

        var info = new FileInfo(path);
        var hash = await ComputeSha256Async(path, cancellationToken);
        if (hash is null) return;

        var fingerprint = $"{info.Length}|{info.LastWriteTimeUtc.Ticks}|{hash}";
        if (_recentFingerprints.TryGetValue(path, out var previous) && previous == fingerprint) return;
        _recentFingerprints[path] = fingerprint;

        var settings = JsonStorage.LoadSettings();
        string? archivePath = null;
        try
        {
            archivePath = await ArchiveManager.TryArchiveAsync(path, _device, settings, cancellationToken);
        }
        catch (Exception ex)
        {
            LogWarning($"Audit-copy failed for {path}: {ex.Message}");
        }

        JsonStorage.AppendEvent(new AuditEvent
        {
            Timestamp = DateTimeOffset.Now,
            Kind = AuditEventKind.UsbWrite,
            Direction = TransferDirection.PcToUsb,
            WindowsUser = UsbDeviceDiscovery.GetInteractiveUser(),
            ComputerName = Environment.MachineName,
            DeviceName = _device.DeviceName,
            DeviceSerial = _device.DeviceSerial,
            DriveLetter = _device.DriveLetter,
            VolumeLabel = _device.VolumeLabel,
            FileName = info.Name,
            FilePath = path,
            DestinationPath = path,
            FileSizeBytes = info.Length,
            Sha256 = hash,
            ArchiveCopyCreated = archivePath is not null,
            ArchivePath = archivePath,
            Evidence = "Confirmed write observed on removable USB volume",
            Notes = "V1 confirms the USB-side write. The original PC source path is not inferred unless a later capture engine supplies it."
        });
    }

    private void LogDelete(string path)
    {
        var settings = JsonStorage.LoadSettings();
        if (!settings.LogDeletes || ShouldIgnore(path)) return;
        JsonStorage.AppendEvent(new AuditEvent
        {
            Timestamp = DateTimeOffset.Now,
            Kind = AuditEventKind.UsbDelete,
            Direction = TransferDirection.Unknown,
            WindowsUser = UsbDeviceDiscovery.GetInteractiveUser(),
            ComputerName = Environment.MachineName,
            DeviceName = _device.DeviceName,
            DeviceSerial = _device.DeviceSerial,
            DriveLetter = _device.DriveLetter,
            VolumeLabel = _device.VolumeLabel,
            FileName = Path.GetFileName(path),
            FilePath = path,
            Evidence = "Deletion observed on removable USB volume"
        });
    }

    private bool ShouldIgnore(string path)
    {
        var settings = JsonStorage.LoadSettings();
        var extension = Path.GetExtension(path);
        if (settings.ExcludedExtensions.Any(x => string.Equals(x, extension, StringComparison.OrdinalIgnoreCase))) return true;
        var parts = path.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return parts.Any(part => settings.ExcludedDirectoryNames.Any(x => string.Equals(x, part, StringComparison.OrdinalIgnoreCase)));
    }

    private static async Task<bool> WaitForStableFileAsync(string path, CancellationToken token)
    {
        for (var attempt = 0; attempt < 5; attempt++)
        {
            token.ThrowIfCancellationRequested();
            try
            {
                var before = new FileInfo(path);
                if (!before.Exists) return false;
                var length = before.Length;
                var writeTime = before.LastWriteTimeUtc;
                await Task.Delay(650, token);
                var after = new FileInfo(path);
                if (after.Exists && after.Length == length && after.LastWriteTimeUtc == writeTime)
                {
                    using var probe = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                    return true;
                }
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { return false; }
            await Task.Delay(500, token);
        }
        return false;
    }

    private static async Task<string?> ComputeSha256Async(string path, CancellationToken token)
    {
        for (var attempt = 0; attempt < 3; attempt++)
        {
            try
            {
                await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1024 * 128, true);
                var hash = await SHA256.HashDataAsync(stream, token);
                return Convert.ToHexString(hash);
            }
            catch (IOException) when (attempt < 2)
            {
                await Task.Delay(500, token);
            }
        }
        return null;
    }

    private void LogWarning(string message)
    {
        JsonStorage.AppendEvent(new AuditEvent
        {
            Kind = AuditEventKind.Warning,
            Timestamp = DateTimeOffset.Now,
            ComputerName = Environment.MachineName,
            DeviceName = _device.DeviceName,
            DeviceSerial = _device.DeviceSerial,
            DriveLetter = _device.DriveLetter,
            Evidence = "Agent warning",
            Notes = message
        });
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _watcher.EnableRaisingEvents = false;
        _watcher.Dispose();
        foreach (var item in _pending.Values)
        {
            try { item.Cancel(); item.Dispose(); } catch { }
        }
        _pending.Clear();
    }
}
