using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Reflection;
using Microsoft.Extensions.Hosting;
using UsbAudit.Shared;

namespace UsbAudit.Agent;

internal sealed class CloudSyncWorker : BackgroundService
{
    private static readonly HttpClient Http = new()
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        StoragePaths.EnsureDirectories();

        while (!stoppingToken.IsCancellationRequested)
        {
            var settings = JsonStorage.LoadSettings();
            var interval = TimeSpan.FromSeconds(Math.Clamp(settings.CloudSyncSeconds, 5, 300));

            try
            {
                if (!settings.CloudSyncEnabled ||
                    string.IsNullOrWhiteSpace(settings.CloudApiUrl) ||
                    string.IsNullOrWhiteSpace(settings.TerminalToken))
                {
                    SaveState("Not configured", "Cloud sync is disabled or enrollment details are missing.", null);
                    await Task.Delay(interval, stoppingToken);
                    continue;
                }

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
                var payload = new CloudUploadBatch
                {
                    Terminal = new TerminalHeartbeat
                    {
                        TerminalId = settings.TerminalId,
                        ComputerName = Environment.MachineName,
                        WindowsUser = UsbDeviceDiscovery.GetInteractiveUser(),
                        AppVersion = Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "unknown",
                        Timestamp = DateTimeOffset.Now,
                        ConnectedDevices = JsonStorage.ReadConnectedDevices()
                    },
                    Events = events
                };

                var request = new HttpRequestMessage(HttpMethod.Post, settings.CloudApiUrl.Trim());
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", settings.TerminalToken.Trim());
                request.Headers.Add("X-UsbAudit-Terminal", settings.TerminalId);
                request.Content = JsonContent.Create(payload);

                var attemptAt = DateTimeOffset.Now;
                using var response = await Http.SendAsync(request, stoppingToken);
                var body = await response.Content.ReadAsStringAsync(stoppingToken);
                if (!response.IsSuccessStatusCode)
                {
                    SaveState("Offline", $"Cloud returned {(int)response.StatusCode}: {TrimMessage(body)}", attemptAt);
                    await Task.Delay(interval, stoppingToken);
                    continue;
                }

                if (events.Count > 0) JsonStorage.AcknowledgeCloudOutbox(events.Count);
                var pending = JsonStorage.CloudOutboxCount();
                var success = JsonStorage.LoadCloudState();
                success.State = pending == 0 ? "Synced" : "Syncing";
                success.LastAttemptAt = attemptAt;
                success.LastSuccessAt = DateTimeOffset.Now;
                success.PendingEvents = pending;
                success.Message = pending == 0
                    ? "Terminal is synchronized with the web console."
                    : $"Uploaded {events.Count} events; {pending} still queued.";
                success.BackfillCompleted = true;
                JsonStorage.SaveCloudState(success);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                SaveState("Offline", ex.Message, DateTimeOffset.Now);
            }

            try { await Task.Delay(interval, stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
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
