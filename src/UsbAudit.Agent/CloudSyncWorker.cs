using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Reflection;
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

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        StoragePaths.EnsureDirectories();

        while (!stoppingToken.IsCancellationRequested)
        {
            var forced = ConsumeManualSyncRequest();
            var settings = JsonStorage.LoadSettings();
            var interval = TimeSpan.FromSeconds(Math.Clamp(settings.CloudSyncSeconds, 5, 300));

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
                var payload = new CloudUploadBatch
                {
                    Terminal = new TerminalHeartbeat
                    {
                        TerminalId = settings.TerminalId,
                        ComputerName = Environment.MachineName,
                        WindowsUser = UsbDeviceDiscovery.GetInteractiveUser(),
                        AppVersion = Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "unknown",
                        Timestamp = DateTimeOffset.Now,
                        ConnectedDevices = JsonStorage.ReadConnectedDevices(),
                        Endpoint = EndpointInventory.Capture(),
                        Network = NetworkInventory.Capture()
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

                if (events.Count > 0) JsonStorage.AcknowledgeCloudOutbox(events.Count);
                if (commandResults.Count > 0) EndpointCommandProcessor.AcknowledgeResults(commandResults.Select(x => x.CommandId));
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

            var nextInterval = EndpointCommandProcessor.HasActiveDeployment
                ? TimeSpan.FromSeconds(5)
                : interval;
            try { await WaitForNextCycleAsync(nextInterval, stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
        }
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
