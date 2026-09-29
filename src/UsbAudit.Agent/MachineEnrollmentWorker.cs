using System.Net.Http.Json;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Hosting;
using UsbAudit.Shared;

namespace UsbAudit.Agent;

internal sealed class MachineEnrollmentWorker : BackgroundService
{
    private const string EnrollmentUrl =
        "https://pgbipustotixwahmotvu.supabase.co/functions/v1/machine-terminal-enroll";
    private const string IngestUrl =
        "https://pgbipustotixwahmotvu.supabase.co/functions/v1/usb-audit-ingest";
    private const string WebConsoleUrl = "https://secure.creccommw.org";

    private static readonly HttpClient Http = new()
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        StoragePaths.EnsureDirectories();

        while (!stoppingToken.IsCancellationRequested)
        {
            var delay = TimeSpan.FromSeconds(20);

            try
            {
                var settings = JsonStorage.LoadSettings();
                EnsureManagedDefaults(settings);

                if (!string.IsNullOrWhiteSpace(settings.TerminalToken))
                {
                    var changed = false;
                    if (!settings.CloudSyncEnabled)
                    {
                        settings.CloudSyncEnabled = true;
                        changed = true;
                    }
                    if (settings.CloudSyncSeconds != 10)
                    {
                        settings.CloudSyncSeconds = 10;
                        changed = true;
                    }
                    if (changed) JsonStorage.SaveSettings(settings);

                    delay = TimeSpan.FromMinutes(5);
                }
                else
                {
                    if (string.IsNullOrWhiteSpace(settings.MachineEnrollmentSecret))
                    {
                        settings.MachineEnrollmentSecret =
                            Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
                        JsonStorage.SaveSettings(settings);
                    }

                    var snapshot = EndpointInventory.Capture();
                    var payload = new
                    {
                        terminalId = settings.TerminalId,
                        computerName = Environment.MachineName,
                        machineSecret = settings.MachineEnrollmentSecret,
                        appVersion =
                            Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "unknown",
                        serialNumber = snapshot.SerialNumber ?? string.Empty,
                        manufacturer = snapshot.Manufacturer ?? string.Empty,
                        model = snapshot.Model ?? string.Empty
                    };

                    using var response = await Http.PostAsJsonAsync(
                        EnrollmentUrl,
                        payload,
                        stoppingToken);

                    var body = await response.Content.ReadAsStringAsync(stoppingToken);
                    MachineEnrollmentResponse? result = null;
                    try
                    {
                        result = JsonSerializer.Deserialize<MachineEnrollmentResponse>(
                            body,
                            new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                    }
                    catch { }

                    if (!string.IsNullOrWhiteSpace(result?.RequestId) &&
                        !string.Equals(settings.MachineEnrollmentRequestId, result.RequestId,
                            StringComparison.OrdinalIgnoreCase))
                    {
                        settings.MachineEnrollmentRequestId = result.RequestId;
                        JsonStorage.SaveSettings(settings);
                    }

                    if (response.StatusCode == System.Net.HttpStatusCode.Accepted ||
                        string.Equals(result?.Status, "pending", StringComparison.OrdinalIgnoreCase))
                    {
                        SaveCloudState(
                            "Pending approval",
                            "Smart Console connected from the Windows service. Waiting for one-time CRECCOM IT approval.");
                        delay = TimeSpan.FromSeconds(20);
                    }
                    else if (response.StatusCode == System.Net.HttpStatusCode.Forbidden ||
                             string.Equals(result?.Status, "denied", StringComparison.OrdinalIgnoreCase))
                    {
                        SaveCloudState(
                            "Enrollment denied",
                            result?.Error ?? "CRECCOM IT denied this machine enrollment request.");
                        delay = TimeSpan.FromMinutes(5);
                    }
                    else if (response.IsSuccessStatusCode &&
                             string.Equals(result?.Status, "enrolled", StringComparison.OrdinalIgnoreCase) &&
                             !string.IsNullOrWhiteSpace(result.TerminalToken) &&
                             result.TerminalToken.StartsWith("csc_", StringComparison.Ordinal))
                    {
                        settings.TerminalToken = result.TerminalToken;
                        settings.CloudApiUrl = string.IsNullOrWhiteSpace(result.IngestUrl)
                            ? IngestUrl
                            : result.IngestUrl;
                        settings.WebConsoleUrl = string.IsNullOrWhiteSpace(result.WebConsoleUrl)
                            ? WebConsoleUrl
                            : result.WebConsoleUrl;
                        settings.CloudSyncEnabled = true;
                        settings.CloudSyncSeconds = 10;
                        JsonStorage.SaveSettings(settings);

                        var state = JsonStorage.LoadCloudState();
                        state.BackfillCompleted = false;
                        state.State = "Enrolled";
                        state.Message =
                            "Machine enrollment completed. Smart Console now connects at Windows boot without a user sign-in.";
                        JsonStorage.SaveCloudState(state);

                        JsonStorage.AppendEvent(new AuditEvent
                        {
                            Kind = AuditEventKind.Warning,
                            Timestamp = DateTimeOffset.Now,
                            ComputerName = Environment.MachineName,
                            Evidence = "Machine self-enrollment",
                            Notes =
                                "CRECCOM IT approved this endpoint. The Windows service now owns the cloud connection."
                        });

                        delay = TimeSpan.FromSeconds(5);
                    }
                    else
                    {
                        SaveCloudState(
                            "Enrollment unavailable",
                            result?.Error ?? $"Machine enrollment returned HTTP {(int)response.StatusCode}.");
                        delay = TimeSpan.FromSeconds(45);
                    }
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                SaveCloudState(
                    "Enrollment offline",
                    $"Machine enrollment will retry automatically: {ex.Message}");
                delay = TimeSpan.FromSeconds(45);
            }

            try
            {
                await Task.Delay(delay, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
        }
    }

    private static void EnsureManagedDefaults(UsbAuditSettings settings)
    {
        var changed = false;

        if (string.IsNullOrWhiteSpace(settings.TerminalId))
        {
            settings.TerminalId = $"{Environment.MachineName}-{Guid.NewGuid():N}";
            changed = true;
        }
        if (!string.Equals(settings.CloudApiUrl, IngestUrl, StringComparison.OrdinalIgnoreCase))
        {
            settings.CloudApiUrl = IngestUrl;
            changed = true;
        }
        if (!string.Equals(settings.WebConsoleUrl, WebConsoleUrl, StringComparison.OrdinalIgnoreCase))
        {
            settings.WebConsoleUrl = WebConsoleUrl;
            changed = true;
        }

        if (changed) JsonStorage.SaveSettings(settings);
    }

    private static void SaveCloudState(string stateName, string message)
    {
        var state = JsonStorage.LoadCloudState();
        state.State = stateName;
        state.Message = message;
        state.LastAttemptAt = DateTimeOffset.Now;
        JsonStorage.SaveCloudState(state);
    }

    private sealed class MachineEnrollmentResponse
    {
        public string? Status { get; set; }
        public string? RequestId { get; set; }
        public string? TerminalToken { get; set; }
        public string? IngestUrl { get; set; }
        public string? WebConsoleUrl { get; set; }
        public string? Error { get; set; }
    }
}
