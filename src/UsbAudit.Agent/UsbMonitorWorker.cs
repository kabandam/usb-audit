using Microsoft.Extensions.Hosting;
using UsbAudit.Shared;

namespace UsbAudit.Agent;

internal sealed class UsbMonitorWorker : BackgroundService
{
    private readonly Dictionary<string, UsbDriveMonitor> _monitors = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, ConnectedUsbDevice> _known = new(StringComparer.OrdinalIgnoreCase);
    private DateTime _lastRetentionCheck = DateTime.MinValue;
    private DateTime _lastUpdateCheck = DateTime.MinValue;
    private Task? _updateTask;
    private LocalDestinationMonitor? _localDestinationMonitor;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        StoragePaths.EnsureDirectories();
        JsonStorage.LoadSettings();
        _localDestinationMonitor = new LocalDestinationMonitor(stoppingToken);

        JsonStorage.AppendEvent(new AuditEvent
        {
            Kind = AuditEventKind.AgentStarted,
            Timestamp = DateTimeOffset.Now,
            ComputerName = Environment.MachineName,
            WindowsUser = UsbDeviceDiscovery.GetInteractiveUser(),
            Evidence = "USB Audit Agent started"
        });

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                RefreshDevices(stoppingToken);
                if ((DateTime.UtcNow - _lastRetentionCheck).TotalHours >= 1)
                {
                    ArchiveManager.EnforceRetention(JsonStorage.LoadSettings());
                    _lastRetentionCheck = DateTime.UtcNow;
                }

                StartUpdateCheckIfDue(stoppingToken);
            }
            catch (Exception ex)
            {
                JsonStorage.AppendEvent(new AuditEvent
                {
                    Kind = AuditEventKind.Warning,
                    Timestamp = DateTimeOffset.Now,
                    ComputerName = Environment.MachineName,
                    Evidence = "Agent polling warning",
                    Notes = ex.Message
                });
            }

            await Task.Delay(TimeSpan.FromSeconds(2), stoppingToken);
        }
    }

    private void StartUpdateCheckIfDue(CancellationToken token)
    {
        if (_updateTask is { IsCompleted: false }) return;
        var settings = JsonStorage.LoadSettings();
        var requested = File.Exists(StoragePaths.UpdateRequestPath);
        var due = settings.AutoUpdatesEnabled &&
                  (DateTime.UtcNow - _lastUpdateCheck).TotalHours >= Math.Clamp(settings.UpdateCheckHours, 1, 168);
        if (!requested && !due) return;

        try
        {
            if (requested) File.Delete(StoragePaths.UpdateRequestPath);
        }
        catch { }

        _lastUpdateCheck = DateTime.UtcNow;
        _updateTask = Task.Run(() => GitHubUpdateManager.CheckAndApplyAsync(settings, token, requested), token);
    }

    private void RefreshDevices(CancellationToken token)
    {
        var current = UsbDeviceDiscovery.Discover();
        var currentMap = current.ToDictionary(x => x.DeviceKey, StringComparer.OrdinalIgnoreCase);

        foreach (var device in current)
        {
            if (_known.ContainsKey(device.DeviceKey))
            {
                device.ConnectedAt = _known[device.DeviceKey].ConnectedAt;
                continue;
            }

            _known[device.DeviceKey] = device;
            try
            {
                _monitors[device.DeviceKey] = new UsbDriveMonitor(device, token);
            }
            catch (Exception ex)
            {
                JsonStorage.AppendEvent(new AuditEvent
                {
                    Kind = AuditEventKind.Warning,
                    Timestamp = DateTimeOffset.Now,
                    ComputerName = Environment.MachineName,
                    DeviceName = device.DeviceName,
                    DeviceSerial = device.DeviceSerial,
                    DriveLetter = device.DriveLetter,
                    Evidence = "Failed to start USB watcher",
                    Notes = ex.Message
                });
            }

            JsonStorage.AppendEvent(new AuditEvent
            {
                Kind = AuditEventKind.DeviceConnected,
                Timestamp = DateTimeOffset.Now,
                WindowsUser = UsbDeviceDiscovery.GetInteractiveUser(),
                ComputerName = Environment.MachineName,
                DeviceName = device.DeviceName,
                DeviceSerial = device.DeviceSerial,
                DriveLetter = device.DriveLetter,
                VolumeLabel = device.VolumeLabel,
                Evidence = "Removable USB volume detected"
            });
        }

        foreach (var removedKey in _known.Keys.Where(key => !currentMap.ContainsKey(key)).ToList())
        {
            var device = _known[removedKey];
            if (_monitors.Remove(removedKey, out var monitor)) monitor.Dispose();
            _known.Remove(removedKey);
            JsonStorage.AppendEvent(new AuditEvent
            {
                Kind = AuditEventKind.DeviceDisconnected,
                Timestamp = DateTimeOffset.Now,
                WindowsUser = UsbDeviceDiscovery.GetInteractiveUser(),
                ComputerName = Environment.MachineName,
                DeviceName = device.DeviceName,
                DeviceSerial = device.DeviceSerial,
                DriveLetter = device.DriveLetter,
                VolumeLabel = device.VolumeLabel,
                Evidence = "Previously monitored removable USB volume is no longer present"
            });
        }

        var snapshot = _known.Values.OrderBy(x => x.DriveLetter).ToList();
        JsonStorage.SaveConnectedDevices(snapshot);
    }

    public override Task StopAsync(CancellationToken cancellationToken)
    {
        _localDestinationMonitor?.Dispose();
        _localDestinationMonitor = null;

        foreach (var monitor in _monitors.Values) monitor.Dispose();
        _monitors.Clear();
        _known.Clear();
        JsonStorage.SaveConnectedDevices([]);
        JsonStorage.AppendEvent(new AuditEvent
        {
            Kind = AuditEventKind.AgentStopped,
            Timestamp = DateTimeOffset.Now,
            ComputerName = Environment.MachineName,
            Evidence = "USB Audit Agent stopped"
        });
        return base.StopAsync(cancellationToken);
    }
}
