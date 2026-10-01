using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Hosting;
using UsbAudit.Shared;

namespace UsbAudit.Agent;

internal sealed class CloudSyncWorker : BackgroundService
{
    // Refresh pooled connections periodically; stale sockets/DNS must not strand an online terminal.
    private static readonly HttpClient Http = new(new SocketsHttpHandler
    {
        PooledConnectionLifetime = TimeSpan.FromMinutes(2),
        PooledConnectionIdleTimeout = TimeSpan.FromSeconds(30)
    }) { Timeout = TimeSpan.FromSeconds(25) };

    // Keep presence reasonably fresh without turning every endpoint into a high-frequency
    // database client. Heavy telemetry is change-driven and periodically reconciled.
    private static readonly TimeSpan MinimumHeartbeatInterval = TimeSpan.FromSeconds(60);

    private static DateTimeOffset _lastEndpointProbeAt = DateTimeOffset.MinValue;
    private static DateTimeOffset _lastEndpointSentAt = DateTimeOffset.MinValue;
    private static DateTimeOffset _lastNetworkProbeAt = DateTimeOffset.MinValue;
    private static DateTimeOffset _lastNetworkSentAt = DateTimeOffset.MinValue;
    private static DateTimeOffset _lastDevicesSentAt = DateTimeOffset.MinValue;
    private static DateTimeOffset _lastLocationSentAt = DateTimeOffset.MinValue;
    private static DateTimeOffset _lastUpdateStatusSentAt = DateTimeOffset.MinValue;
    private static string? _lastEndpointFingerprint;
    private static string? _lastNetworkFingerprint;
    private static string? _lastDevicesFingerprint;
    private static string? _lastLocationFingerprint;
    private static string? _lastUpdateStatusFingerprint;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        StoragePaths.EnsureDirectories();

        while (!stoppingToken.IsCancellationRequested)
        {
            var forced = ConsumeManualSyncRequest();
            var settings = JsonStorage.LoadSettings();
            var interval = TimeSpan.FromSeconds(Math.Clamp(settings.CloudSyncSeconds, (int)MinimumHeartbeatInterval.TotalSeconds, 300));

            try
            {
                if (!settings.CloudSyncEnabled || string.IsNullOrWhiteSpace(settings.CloudApiUrl) || string.IsNullOrWhiteSpace(settings.TerminalToken))
                {
                    SaveState("Not configured", "Cloud sync is disabled or enrollment details are missing.", null);
                    await WaitForNextCycleAsync(interval, stoppingToken);
                    continue;
                }

                if (forced)
                    SaveState("Connecting", "Manual cloud synchronization in progress.", DateTimeOffset.Now);
                EnsureTerminalId(settings);
                var state = JsonStorage.LoadCloudState();
                if (!state.BackfillCompleted)
                {
                    JsonStorage.EnsureCloudBackfill(5000);
                    state.BackfillCompleted = true;
                    state.PendingEvents = JsonStorage.CloudOutboxCount();
                    state.State = "Queued";
                    state.Message = "Existing local audit records queued for first cloud sync.";
                    JsonStorage.SaveCloudState(state);
                }

                var events = JsonStorage.ReadCloudOutbox(250);
                var commandResults = EndpointCommandProcessor.GetPendingResults();
                var deploymentProgress = EndpointCommandProcessor.GetDeploymentProgress();

                var telemetryAt = DateTimeOffset.UtcNow;
                var inventoryRequested = File.Exists(StoragePaths.InventorySyncRequestPath);
                var endpoint = PrepareEndpointTelemetry(telemetryAt, inventoryRequested, settings, out var endpointFingerprint);
                var connectedDevices = PrepareDeviceTelemetry(telemetryAt, forced, settings, out var devicesFingerprint);
                var network = PrepareNetworkTelemetry(telemetryAt, forced, settings, out var networkFingerprint);
                var location = PrepareLocationTelemetry(telemetryAt, forced, settings, out var locationFingerprint);
                var managedUpdate = PrepareUpdateStatusTelemetry(telemetryAt, forced, settings, out var updateStatusFingerprint);

                var payload = new CloudUploadBatch
                {
                    Terminal = new TerminalHeartbeat
                    {
                        TerminalId = settings.TerminalId,
                        ComputerName = Environment.MachineName,
                        WindowsUser = UsbDeviceDiscovery.GetInteractiveUser(),
                        AppVersion = Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "unknown",
                        Timestamp = DateTimeOffset.Now,
                        ConnectedDevices = connectedDevices,
                        Endpoint = endpoint,
                        Network = network,
                        Location = location,
                        ManagedUpdate = managedUpdate
                    },
                    Events = events,
                    CommandResults = commandResults,
                    DeploymentProgress = deploymentProgress
                };

                using var request = new HttpRequestMessage(HttpMethod.Post, settings.CloudApiUrl.Trim());
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", settings.TerminalToken.Trim());
                if (forced) request.Headers.ConnectionClose = true;
                request.Headers.Add("X-UsbAudit-Terminal", settings.TerminalId);
                request.Content = JsonContent.Create(payload);

                var attemptAt = DateTimeOffset.Now;
                using var response = await Http.SendAsync(request, stoppingToken);
                var body = await response.Content.ReadAsStringAsync(stoppingToken);
                if (!response.IsSuccessStatusCode)
                {
                    SaveState("Offline", $"Cloud returned {(int)response.StatusCode}: {TrimMessage(body)}", attemptAt);
                    await WaitForNextCycleAsync(interval, stoppingToken);
                    continue;
                }

                CloudUploadResponse? result;
                try
                {
                    result = System.Text.Json.JsonSerializer.Deserialize<CloudUploadResponse>(body,
                        new System.Text.Json.JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                }
                catch (System.Text.Json.JsonException)
                {
                    SaveState("Offline", "Cloud response was not valid JSON; no events were acknowledged.", attemptAt);
                    await WaitForNextCycleAsync(interval, stoppingToken);
                    continue;
                }

                if (result?.Ok != true)
                {
                    SaveState("Offline", "Cloud did not confirm the upload; local events are retained for retry.", attemptAt);
                    await WaitForNextCycleAsync(interval, stoppingToken);
                    continue;
                }

                if (!string.IsNullOrWhiteSpace(result.IssuedToken))
                {
                    settings.TerminalToken = result.IssuedToken;
                    JsonStorage.SaveSettings(settings);
                }

                if (result.ResourcePolicy is not null && ApplyResourcePolicy(settings, result.ResourcePolicy))
                {
                    JsonStorage.SaveSettings(settings);
                    interval = TimeSpan.FromSeconds(Math.Clamp(
                        settings.CloudSyncSeconds,
                        (int)MinimumHeartbeatInterval.TotalSeconds,
                        300));
                }

                CommitTelemetry(
                    telemetryAt,
                    endpoint, endpointFingerprint,
                    connectedDevices, devicesFingerprint,
                    network, networkFingerprint,
                    location, locationFingerprint,
                    managedUpdate, updateStatusFingerprint);

                if (endpoint is not null && inventoryRequested)
                    TryDeleteFlag(StoragePaths.InventorySyncRequestPath);

                if (events.Count > 0) JsonStorage.AcknowledgeCloudOutbox(events.Count);
                if (commandResults.Count > 0)
                {
                    // The ingest function has now persisted the inventory completion result.
                    // Trigger the update only AFTER that acknowledgment: its installer stops the
                    // service and desktop app, so doing this earlier could strand the command.
                    // If the flag cannot be written, keep the local result for a cloud retry.
                    if (commandResults.Any(x => x.Status == "completed" && x.ForceManagedUpdateAfterAck))
                    {
                        File.WriteAllText(StoragePaths.InventoryUpdateRequestPath, DateTimeOffset.UtcNow.ToString("O"));
                    }
                    EndpointCommandProcessor.AcknowledgeResults(commandResults.Select(x => x.CommandId));
                }
                EndpointCommandProcessor.Process(result?.Commands);

                var pending = JsonStorage.CloudOutboxCount();
                var success = JsonStorage.LoadCloudState();
                success.State = pending == 0 ? "Synced" : "Syncing";
                success.LastAttemptAt = attemptAt;
                success.LastSuccessAt = DateTimeOffset.Now;
                success.PendingEvents = pending;
                success.Message = result?.Commands?.Count > 0
                    ? $"Synchronized and received {result.Commands.Count} endpoint command(s)."
                    : pending == 0 ? "Terminal is synchronized with the web console." : $"Uploaded {events.Count} events; {pending} still queued.";
                success.BackfillCompleted = true;
                JsonStorage.SaveCloudState(success);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception ex) { SaveState("Offline", ex.Message, DateTimeOffset.Now); }

            // Deliver command results promptly, especially before a managed self-update.
            var nextInterval = EndpointCommandProcessor.HasActiveDeployment ||
                               EndpointCommandProcessor.GetPendingResults().Count > 0
                ? TimeSpan.FromSeconds(15)
                : interval;
            try { await WaitForNextCycleAsync(nextInterval, stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
        }
    }

    private static EndpointSnapshot? PrepareEndpointTelemetry(
        DateTimeOffset now, bool force, UsbAuditSettings settings, out string? fingerprint)
    {
        fingerprint = null;
        var probeInterval = TimeSpan.FromMinutes(Math.Clamp(settings.InventoryProbeMinutes, 5, 1440));
        var resendInterval = TimeSpan.FromHours(Math.Clamp(settings.InventoryResendHours, 1, 72));
        var resendDue = now - _lastEndpointSentAt >= resendInterval;
        var probeDue = force || _lastEndpointFingerprint is null || resendDue ||
                       now - _lastEndpointProbeAt >= probeInterval;
        if (!probeDue) return null;

        _lastEndpointProbeAt = now;
        var snapshot = EndpointInventory.Capture();
        fingerprint = FingerprintEndpoint(snapshot);
        if (force || _lastEndpointFingerprint is null || resendDue ||
            !string.Equals(fingerprint, _lastEndpointFingerprint, StringComparison.Ordinal))
            return snapshot;

        return null;
    }

    private static List<ConnectedUsbDevice>? PrepareDeviceTelemetry(
        DateTimeOffset now, bool force, UsbAuditSettings settings, out string? fingerprint)
    {
        var devices = JsonStorage.ReadConnectedDevices();
        fingerprint = Fingerprint(devices.OrderBy(item => item.DeviceKey, StringComparer.OrdinalIgnoreCase)
            .Select(item => new
            {
                item.DeviceKey, item.DriveLetter, item.DeviceName, item.DeviceSerial,
                item.VolumeLabel, item.FileSystem, item.TotalSizeBytes,
                item.AvailableFreeSpaceBytes, item.ConnectedAt
            }).ToArray());

        var resendInterval = TimeSpan.FromMinutes(Math.Clamp(settings.DeviceResendMinutes, 15, 1440));
        if (force || _lastDevicesFingerprint is null ||
            now - _lastDevicesSentAt >= resendInterval ||
            !string.Equals(fingerprint, _lastDevicesFingerprint, StringComparison.Ordinal))
            return devices;

        return null;
    }

    private static NetworkSnapshot? PrepareNetworkTelemetry(
        DateTimeOffset now, bool force, UsbAuditSettings settings, out string? fingerprint)
    {
        fingerprint = null;
        if (!settings.NetworkTelemetryEnabled) return null;

        var probeInterval = TimeSpan.FromMinutes(Math.Clamp(settings.NetworkProbeMinutes, 5, 1440));
        var resendInterval = TimeSpan.FromMinutes(Math.Clamp(settings.NetworkResendMinutes, 15, 1440));
        var resendDue = now - _lastNetworkSentAt >= resendInterval;
        var probeDue = force || _lastNetworkFingerprint is null || resendDue ||
                       now - _lastNetworkProbeAt >= probeInterval;
        if (!probeDue) return null;

        _lastNetworkProbeAt = now;
        var snapshot = NetworkInventory.Capture();
        fingerprint = Fingerprint(new
        {
            snapshot.NetworkName, snapshot.ConnectionType, snapshot.AdapterName,
            snapshot.LocalIp, snapshot.MacAddress, snapshot.GatewayIp,
            DnsServers = snapshot.DnsServers.OrderBy(value => value, StringComparer.OrdinalIgnoreCase).ToArray(),
            snapshot.LinkSpeedMbps
        });

        if (force || _lastNetworkFingerprint is null || resendDue ||
            !string.Equals(fingerprint, _lastNetworkFingerprint, StringComparison.Ordinal))
            return snapshot;

        return null;
    }

    private static EndpointLocationSnapshot? PrepareLocationTelemetry(
        DateTimeOffset now, bool force, UsbAuditSettings settings, out string? fingerprint)
    {
        fingerprint = null;
        if (!settings.LocationTelemetryEnabled) return null;

        var snapshot = PrepareAuthorizedLocation();
        fingerprint = Fingerprint(new
        {
            snapshot.Enabled, snapshot.Status, snapshot.Latitude, snapshot.Longitude,
            snapshot.AccuracyMeters, snapshot.Source, snapshot.CapturedAt
        });

        var resendInterval = TimeSpan.FromMinutes(Math.Clamp(settings.LocationResendMinutes, 15, 1440));
        if (force || _lastLocationFingerprint is null ||
            now - _lastLocationSentAt >= resendInterval ||
            !string.Equals(fingerprint, _lastLocationFingerprint, StringComparison.Ordinal))
            return snapshot;

        return null;
    }

    private static UpdateStatus? PrepareUpdateStatusTelemetry(
        DateTimeOffset now, bool force, UsbAuditSettings settings, out string? fingerprint)
    {
        var snapshot = JsonStorage.LoadUpdateStatus();
        fingerprint = Fingerprint(new
        {
            snapshot.LastCheckedAt, snapshot.CurrentVersion, snapshot.LatestVersion,
            snapshot.State, snapshot.Message, snapshot.ReleaseUrl
        });

        var resendInterval = TimeSpan.FromMinutes(Math.Clamp(settings.UpdateStatusResendMinutes, 15, 1440));
        if (force || _lastUpdateStatusFingerprint is null ||
            now - _lastUpdateStatusSentAt >= resendInterval ||
            !string.Equals(fingerprint, _lastUpdateStatusFingerprint, StringComparison.Ordinal))
            return snapshot;

        return null;
    }

    private static bool ApplyResourcePolicy(UsbAuditSettings settings, ResourceUsagePolicy policy)
    {
        var changed = false;

        void Set<T>(T current, T next, Action<T> apply) where T : IEquatable<T>
        {
            if (current.Equals(next)) return;
            apply(next);
            changed = true;
        }

        Set(settings.CloudSyncSeconds, Math.Clamp(policy.HeartbeatSeconds, 60, 300),
            value => settings.CloudSyncSeconds = value);
        Set(settings.NetworkTelemetryEnabled, policy.NetworkEnabled,
            value => settings.NetworkTelemetryEnabled = value);
        Set(settings.LocationTelemetryEnabled, policy.LocationEnabled,
            value => settings.LocationTelemetryEnabled = value);
        Set(settings.InventoryProbeMinutes, Math.Clamp(policy.InventoryProbeMinutes, 5, 1440),
            value => settings.InventoryProbeMinutes = value);
        Set(settings.InventoryResendHours, Math.Clamp(policy.InventoryResendHours, 1, 72),
            value => settings.InventoryResendHours = value);
        Set(settings.NetworkProbeMinutes, Math.Clamp(policy.NetworkProbeMinutes, 5, 1440),
            value => settings.NetworkProbeMinutes = value);
        Set(settings.NetworkResendMinutes, Math.Clamp(policy.NetworkResendMinutes, 15, 1440),
            value => settings.NetworkResendMinutes = value);
        Set(settings.DeviceResendMinutes, Math.Clamp(policy.DeviceResendMinutes, 15, 1440),
            value => settings.DeviceResendMinutes = value);
        Set(settings.LocationResendMinutes, Math.Clamp(policy.LocationResendMinutes, 15, 1440),
            value => settings.LocationResendMinutes = value);
        Set(settings.UpdateStatusResendMinutes, Math.Clamp(policy.UpdateStatusResendMinutes, 15, 1440),
            value => settings.UpdateStatusResendMinutes = value);

        return changed;
    }

    private static string FingerprintEndpoint(EndpointSnapshot snapshot)
    {
        var software = snapshot.InstalledSoftware
            .OrderBy(item => item.Name, StringComparer.OrdinalIgnoreCase)
            .ThenBy(item => item.Version, StringComparer.OrdinalIgnoreCase)
            .ThenBy(item => item.Publisher, StringComparer.OrdinalIgnoreCase)
            .Select(item => new
            {
                item.Name, item.Version, item.Publisher, item.VerifiedMicrosoftPublisher,
                item.InstallLocation, item.UninstallCommand,
                ExecutablePaths = item.ExecutablePaths
                    .OrderBy(path => path, StringComparer.OrdinalIgnoreCase).ToArray()
            }).ToArray();

        return Fingerprint(new
        {
            snapshot.OsName, snapshot.OsVersion, snapshot.Manufacturer, snapshot.Model,
            snapshot.SerialNumber, snapshot.TotalMemoryBytes, snapshot.ProcessorName,
            snapshot.DefenderStatus, snapshot.FirewallEnabled, Software = software
        });
    }

    private static string Fingerprint<T>(T value)
    {
        var json = JsonSerializer.Serialize(value);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(json)));
    }

    private static void CommitTelemetry(
        DateTimeOffset sentAt,
        EndpointSnapshot? endpoint, string? endpointFingerprint,
        List<ConnectedUsbDevice>? devices, string? devicesFingerprint,
        NetworkSnapshot? network, string? networkFingerprint,
        EndpointLocationSnapshot? location, string? locationFingerprint,
        UpdateStatus? updateStatus, string? updateStatusFingerprint)
    {
        if (endpoint is not null && endpointFingerprint is not null)
        {
            _lastEndpointFingerprint = endpointFingerprint;
            _lastEndpointSentAt = sentAt;
        }

        if (devices is not null && devicesFingerprint is not null)
        {
            _lastDevicesFingerprint = devicesFingerprint;
            _lastDevicesSentAt = sentAt;
        }

        if (network is not null && networkFingerprint is not null)
        {
            _lastNetworkFingerprint = networkFingerprint;
            _lastNetworkSentAt = sentAt;
        }

        if (location is not null && locationFingerprint is not null)
        {
            _lastLocationFingerprint = locationFingerprint;
            _lastLocationSentAt = sentAt;
        }

        if (updateStatus is not null && updateStatusFingerprint is not null)
        {
            _lastUpdateStatusFingerprint = updateStatusFingerprint;
            _lastUpdateStatusSentAt = sentAt;
        }
    }

    private static void TryDeleteFlag(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private static EndpointLocationSnapshot PrepareAuthorizedLocation()
    {
        var state = JsonStorage.LoadLocationState();
        if (!state.Enabled) return new EndpointLocationSnapshot { Enabled = false, Status = state.Status };
        // Never present a cached reading as live; the server retains its last approved sample.
        if (state.CapturedAt is null || DateTimeOffset.UtcNow - state.CapturedAt.Value > TimeSpan.FromMinutes(20))
            return new EndpointLocationSnapshot { Enabled = true, Status = state.Status == "permission_denied" ? "permission_denied" : "awaiting_position" };
        return state;
    }

    private static bool ConsumeManualSyncRequest()
    {
        try
        {
            if (!File.Exists(StoragePaths.CloudSyncRequestPath)) return false;
            File.Delete(StoragePaths.CloudSyncRequestPath);
            return true;
        }
        catch (IOException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
    }

    // Short checks make Force sync responsive; wall-clock deadline also catches up right after resume.
    private static async Task WaitForNextCycleAsync(TimeSpan interval, CancellationToken token)
    {
        var deadline = DateTimeOffset.UtcNow + interval;
        while (DateTimeOffset.UtcNow < deadline)
        {
            if (File.Exists(StoragePaths.CloudSyncRequestPath)) return;
            var remaining = deadline - DateTimeOffset.UtcNow;
            await Task.Delay(remaining < TimeSpan.FromSeconds(1) ? remaining : TimeSpan.FromSeconds(1), token);
        }
    }

    private static void EnsureTerminalId(UsbAuditSettings settings)
    {
        if (!string.IsNullOrWhiteSpace(settings.TerminalId)) return;
        settings.TerminalId = $"{Environment.MachineName}-{Guid.NewGuid():N}";
        JsonStorage.SaveSettings(settings);
    }

    private static void SaveState(string stateName, string message, DateTimeOffset? attemptAt)
    {
        var state = JsonStorage.LoadCloudState();
        state.State = stateName;
        state.Message = message;
        state.LastAttemptAt = attemptAt ?? state.LastAttemptAt;
        state.PendingEvents = JsonStorage.CloudOutboxCount();
        JsonStorage.SaveCloudState(state);
    }

    private static string TrimMessage(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return "No response body";
        value = value.Replace('\r', ' ').Replace('\n', ' ').Trim();
        return value.Length <= 220 ? value : value[..220] + "…";
    }
}
