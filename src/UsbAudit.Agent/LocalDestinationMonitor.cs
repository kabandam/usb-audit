using System.Collections.Concurrent;
using System.Security.Cryptography;
using UsbAudit.Shared;

namespace UsbAudit.Agent;

internal sealed class LocalDestinationMonitor : IDisposable
{
    private readonly List<FileSystemWatcher> _watchers = [];
    private readonly ConcurrentDictionary<string, CancellationTokenSource> _pending = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, string> _recentFingerprints = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, UsbSourceIndex> _usbIndexes = new(StringComparer.OrdinalIgnoreCase);
    private readonly CancellationTokenSource _lifetime;
    private readonly Task _indexTask;
    private volatile bool _disposed;

    private static readonly HashSet<string> ExcludedSystemTopLevel = new(StringComparer.OrdinalIgnoreCase)
    {
        "Windows",
        "Program Files",
        "Program Files (x86)",
        "ProgramData",
        "Recovery",
        "$Recycle.Bin",
        "System Volume Information",
        "PerfLogs"
    };

    public LocalDestinationMonitor(CancellationToken serviceToken)
    {
        _lifetime = CancellationTokenSource.CreateLinkedTokenSource(serviceToken);

        foreach (var root in DiscoverMonitorRoots())
        {
            TryStartWatcher(root);
        }

        _indexTask = Task.Run(() => UsbIndexLoopAsync(_lifetime.Token), _lifetime.Token);
    }

    private static IReadOnlyList<string> DiscoverMonitorRoots()
    {
        var roots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var systemRoot = Path.GetPathRoot(Environment.SystemDirectory) ?? "C:\\";

        // User profiles cover Desktop, Documents, Downloads and the usual Explorer copy targets.
        var usersRoot = Path.Combine(systemRoot, "Users");
        if (Directory.Exists(usersRoot)) roots.Add(Path.GetFullPath(usersRoot));

        // Also cover organization-created top-level data folders on the system drive while avoiding
        // Windows and application trees that generate large amounts of unrelated file activity.
        try
        {
            foreach (var directory in Directory.EnumerateDirectories(systemRoot, "*", SearchOption.TopDirectoryOnly))
            {
                var name = Path.GetFileName(directory.TrimEnd(Path.DirectorySeparatorChar));
                if (string.IsNullOrWhiteSpace(name) || ExcludedSystemTopLevel.Contains(name)) continue;
                if (directory.StartsWith(usersRoot, StringComparison.OrdinalIgnoreCase)) continue;
                roots.Add(Path.GetFullPath(directory));
            }
        }
        catch { }

        // Non-system fixed disks are commonly server/data volumes. Watching the root gives visibility
        // without placing a recursive watcher on the Windows system volume itself.
        foreach (var drive in DriveInfo.GetDrives())
        {
            try
            {
                if (!drive.IsReady || drive.DriveType != DriveType.Fixed) continue;
                var root = Path.GetFullPath(drive.RootDirectory.FullName);
                if (string.Equals(root, Path.GetFullPath(systemRoot), StringComparison.OrdinalIgnoreCase)) continue;
                roots.Add(root);
            }
            catch { }
        }

        var auditRoot = Path.GetFullPath(StoragePaths.BaseDirectory).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        return roots
            .Where(root => !Path.GetFullPath(root).StartsWith(auditRoot, StringComparison.OrdinalIgnoreCase))
            .OrderBy(root => root, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private void TryStartWatcher(string root)
    {
        try
        {
            if (!Directory.Exists(root)) return;
            var watcher = new FileSystemWatcher(root)
            {
                IncludeSubdirectories = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.CreationTime,
                InternalBufferSize = 64 * 1024,
                EnableRaisingEvents = true
            };
            watcher.Created += (_, e) => QueueCandidate(e.FullPath);
            watcher.Changed += (_, e) => QueueCandidate(e.FullPath);
            watcher.Renamed += (_, e) => QueueCandidate(e.FullPath);
            watcher.Error += (_, e) => LogWarning($"PC destination watcher error on {root}: {e.GetException()?.Message}");
            _watchers.Add(watcher);
        }
        catch (Exception ex)
        {
            LogWarning($"Could not monitor PC destination root {root}: {ex.Message}");
        }
    }

    private void QueueCandidate(string path)
    {
        if (_disposed || ShouldIgnoreLocal(path)) return;

        var settings = JsonStorage.LoadSettings();
        if (!settings.MonitorUsbToPcTransfers) return;
        if (JsonStorage.ReadConnectedDevices().Count == 0) return;

        var cts = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token);
        _pending.AddOrUpdate(path, cts, (_, previous) =>
        {
            try { previous.Cancel(); previous.Dispose(); } catch { }
            return cts;
        });

        _ = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(1400, cts.Token);
                await ProcessCandidateAsync(path, cts.Token);
            }
            catch (OperationCanceledException) { }
            catch (Exception ex) { LogWarning($"Could not inspect PC destination {path}: {ex.Message}"); }
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

    private async Task ProcessCandidateAsync(string path, CancellationToken token)
    {
        if (!File.Exists(path) || Directory.Exists(path)) return;
        if (!await WaitForStableFileAsync(path, token)) return;

        var destination = new FileInfo(path);
        if (!destination.Exists) return;

        var connected = JsonStorage.ReadConnectedDevices();
        if (connected.Count == 0) return;

        var sourceCandidates = await GetSourceCandidatesAsync(destination.Name, destination.Length, connected, token);
        if (sourceCandidates.Count == 0) return;

        var destinationHash = await ComputeSha256Async(path, token);
        if (destinationHash is null) return;

        var matches = new List<UsbSourceCandidate>();
        foreach (var candidate in sourceCandidates)
        {
            token.ThrowIfCancellationRequested();
            try
            {
                var sourceInfo = new FileInfo(candidate.Path);
                if (!sourceInfo.Exists || sourceInfo.Length != destination.Length) continue;
                var sourceHash = await ComputeSha256Async(candidate.Path, token);
                if (sourceHash is not null && string.Equals(sourceHash, destinationHash, StringComparison.OrdinalIgnoreCase))
                {
                    matches.Add(candidate);
                }
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }

        if (matches.Count == 0) return;

        var selected = matches[0];
        var fingerprint = $"{destination.Length}|{destination.LastWriteTimeUtc.Ticks}|{destinationHash}|{selected.Device.DeviceKey}|{selected.Path}";
        if (_recentFingerprints.TryGetValue(path, out var previous) && previous == fingerprint) return;
        _recentFingerprints[path] = fingerprint;

        var settings = JsonStorage.LoadSettings();
        string? archivePath = null;
        try
        {
            archivePath = await ArchiveManager.TryArchiveAsync(path, selected.Device, settings, token);
        }
        catch (Exception ex)
        {
            LogWarning($"Audit-copy failed for USB to PC transfer {path}: {ex.Message}");
        }

        var uniqueSource = matches.Count == 1;
        JsonStorage.AppendEvent(new AuditEvent
        {
            Timestamp = DateTimeOffset.Now,
            Kind = AuditEventKind.UsbRead,
            Direction = TransferDirection.UsbToPc,
            WindowsUser = UsbDeviceDiscovery.GetInteractiveUser(),
            ComputerName = Environment.MachineName,
            DeviceName = selected.Device.DeviceName,
            DeviceSerial = selected.Device.DeviceSerial,
            DriveLetter = selected.Device.DriveLetter,
            VolumeLabel = selected.Device.VolumeLabel,
            FileName = destination.Name,
            FilePath = path,
            SourcePath = selected.Path,
            DestinationPath = path,
            FileSizeBytes = destination.Length,
            Sha256 = destinationHash,
            ArchiveCopyCreated = archivePath is not null,
            ArchivePath = archivePath,
            Evidence = uniqueSource
                ? "USB to PC confirmed by destination write plus SHA-256 match to a unique connected USB source"
                : "USB to PC confirmed by destination write plus SHA-256 match to connected USB content",
            Notes = uniqueSource
                ? "The destination file was written while the USB was connected and exactly matched the indexed USB source by size and SHA-256."
                : $"The destination matched {matches.Count} identical USB source files. The first matching source path is shown; file content and direction are confirmed, but the identical source instance is ambiguous."
        });
    }

    private async Task<List<UsbSourceCandidate>> GetSourceCandidatesAsync(
        string fileName,
        long length,
        IReadOnlyList<ConnectedUsbDevice> connected,
        CancellationToken token)
    {
        var key = BuildIndexKey(fileName, length);

        // A copy can start immediately after USB insertion. Give the background indexer a short
        // opportunity to finish before deciding that no source candidate exists.
        for (var attempt = 0; attempt < 10; attempt++)
        {
            token.ThrowIfCancellationRequested();
            var results = new List<UsbSourceCandidate>();
            var missingIndex = false;

            foreach (var device in connected)
            {
                if (!_usbIndexes.TryGetValue(device.DeviceKey, out var index))
                {
                    missingIndex = true;
                    continue;
                }

                if (!index.Files.TryGetValue(key, out var paths)) continue;
                results.AddRange(paths.Select(path => new UsbSourceCandidate(index.Device, path)));
            }

            if (results.Count > 0 || !missingIndex) return results;
            await Task.Delay(500, token);
        }

        return [];
    }

    private async Task UsbIndexLoopAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try
            {
                var settings = JsonStorage.LoadSettings();
                var connected = JsonStorage.ReadConnectedDevices();
                var connectedKeys = connected.Select(x => x.DeviceKey).ToHashSet(StringComparer.OrdinalIgnoreCase);

                foreach (var stale in _usbIndexes.Keys.Where(key => !connectedKeys.Contains(key)).ToList())
                {
                    _usbIndexes.TryRemove(stale, out _);
                }

                if (settings.MonitorUsbToPcTransfers)
                {
                    foreach (var device in connected)
                    {
                        token.ThrowIfCancellationRequested();
                        if (_usbIndexes.TryGetValue(device.DeviceKey, out var existing) &&
                            DateTime.UtcNow - existing.BuiltAtUtc < TimeSpan.FromMinutes(2))
                        {
                            continue;
                        }

                        var index = await Task.Run(() => BuildUsbIndex(device, settings, token), token);
                        if (index is not null) _usbIndexes[device.DeviceKey] = index;
                    }
                }
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                LogWarning($"USB source indexing warning: {ex.Message}");
            }

            await Task.Delay(TimeSpan.FromSeconds(10), token);
        }
    }

    private static UsbSourceIndex? BuildUsbIndex(ConnectedUsbDevice device, UsbAuditSettings settings, CancellationToken token)
    {
        var root = device.DriveLetter + "\\";
        if (!Directory.Exists(root)) return null;

        var files = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        var stack = new Stack<string>();
        stack.Push(root);

        while (stack.Count > 0)
        {
            token.ThrowIfCancellationRequested();
            var directory = stack.Pop();

            try
            {
                foreach (var file in Directory.EnumerateFiles(directory, "*", SearchOption.TopDirectoryOnly))
                {
                    token.ThrowIfCancellationRequested();
                    if (ShouldIgnorePath(file, settings)) continue;
                    try
                    {
                        var info = new FileInfo(file);
                        if (!info.Exists) continue;
                        var key = BuildIndexKey(info.Name, info.Length);
                        if (!files.TryGetValue(key, out var paths))
                        {
                            paths = [];
                            files[key] = paths;
                        }
                        paths.Add(info.FullName);
                    }
                    catch { }
                }

                foreach (var child in Directory.EnumerateDirectories(directory, "*", SearchOption.TopDirectoryOnly))
                {
                    token.ThrowIfCancellationRequested();
                    if (ShouldIgnorePath(child, settings)) continue;
                    stack.Push(child);
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        return new UsbSourceIndex(device, files, DateTime.UtcNow);
    }

    private bool ShouldIgnoreLocal(string path)
    {
        var settings = JsonStorage.LoadSettings();
        if (ShouldIgnorePath(path, settings)) return true;

        try
        {
            var full = Path.GetFullPath(path);
            var auditRoot = Path.GetFullPath(StoragePaths.BaseDirectory).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            return full.StartsWith(auditRoot, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return true;
        }
    }

    private static bool ShouldIgnorePath(string path, UsbAuditSettings settings)
    {
        var extension = Path.GetExtension(path);
        if (settings.ExcludedExtensions.Any(x => string.Equals(x, extension, StringComparison.OrdinalIgnoreCase))) return true;
        var parts = path.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return parts.Any(part => settings.ExcludedDirectoryNames.Any(x => string.Equals(x, part, StringComparison.OrdinalIgnoreCase)));
    }

    private static string BuildIndexKey(string fileName, long length) =>
        fileName.ToUpperInvariant() + "\u001f" + length;

    private static async Task<bool> WaitForStableFileAsync(string path, CancellationToken token)
    {
        for (var attempt = 0; attempt < 7; attempt++)
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
            await Task.Delay(450, token);
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
            catch (UnauthorizedAccessException)
            {
                return null;
            }
        }
        return null;
    }

    private static void LogWarning(string message)
    {
        JsonStorage.AppendEvent(new AuditEvent
        {
            Kind = AuditEventKind.Warning,
            Timestamp = DateTimeOffset.Now,
            ComputerName = Environment.MachineName,
            Evidence = "USB to PC monitor warning",
            Notes = message
        });
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        try { _lifetime.Cancel(); } catch { }
        foreach (var watcher in _watchers)
        {
            try
            {
                watcher.EnableRaisingEvents = false;
                watcher.Dispose();
            }
            catch { }
        }
        _watchers.Clear();

        foreach (var pending in _pending.Values)
        {
            try { pending.Cancel(); pending.Dispose(); } catch { }
        }
        _pending.Clear();
        _usbIndexes.Clear();
        _lifetime.Dispose();
    }

    private sealed record UsbSourceCandidate(ConnectedUsbDevice Device, string Path);
    private sealed record UsbSourceIndex(
        ConnectedUsbDevice Device,
        Dictionary<string, List<string>> Files,
        DateTime BuiltAtUtc);
}
