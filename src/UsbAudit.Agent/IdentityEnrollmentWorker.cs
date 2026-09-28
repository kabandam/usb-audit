using System.IO.Pipes;
using System.Net.Http.Json;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Hosting;
using UsbAudit.Shared;

namespace UsbAudit.Agent;

internal sealed class IdentityEnrollmentWorker : BackgroundService
{
    private const string PipeName = "CRECCOM.UsbAudit.Identity";
    private const string EnrollmentUrl = "https://pgbipustotixwahmotvu.supabase.co/functions/v1/m365-terminal-enroll";
    private const string IngestUrl = "https://pgbipustotixwahmotvu.supabase.co/functions/v1/usb-audit-ingest";
    private const string WebConsoleUrl = "https://secure.creccommw.org";
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(30) };

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        EnsureManagedDefaults();

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var pipe = CreatePipe();
                await pipe.WaitForConnectionAsync(stoppingToken);
                await HandleClientAsync(pipe, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                WriteWarning("Microsoft 365 enrollment pipe warning", ex.Message);
                try { await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken); }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            }
        }
    }

    private static NamedPipeServerStream CreatePipe()
    {
        var security = new PipeSecurity();
        var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var adminsSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var authenticatedSid = new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null);

        security.SetOwner(systemSid);
        security.AddAccessRule(new PipeAccessRule(systemSid, PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(adminsSid, PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(authenticatedSid, PipeAccessRights.ReadWrite, AccessControlType.Allow));

        return NamedPipeServerStreamAcl.Create(
            PipeName,
            PipeDirection.InOut,
            2,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous,
            8192,
            8192,
            security);
    }

    private static async Task HandleClientAsync(NamedPipeServerStream pipe, CancellationToken token)
    {
        using var reader = new StreamReader(pipe, Encoding.UTF8, false, 4096, leaveOpen: true);
        using var writer = new StreamWriter(pipe, new UTF8Encoding(false), 4096, leaveOpen: true) { AutoFlush = true };

        var settings = EnsureManagedDefaults();
        if (!string.IsNullOrWhiteSpace(settings.TerminalToken))
        {
            await writer.WriteLineAsync(JsonSerializer.Serialize(new { ok = true, alreadyEnrolled = true }));
            return;
        }

        var line = await reader.ReadLineAsync(token);
        if (string.IsNullOrWhiteSpace(line))
        {
            await writer.WriteLineAsync(JsonSerializer.Serialize(new { ok = false, error = "No Microsoft identity received." }));
            return;
        }

        string? idToken;
        try
        {
            using var payload = JsonDocument.Parse(line);
            idToken = payload.RootElement.TryGetProperty("idToken", out var tokenElement)
                ? tokenElement.GetString()
                : null;
        }
        catch
        {
            idToken = null;
        }

        if (string.IsNullOrWhiteSpace(idToken) || idToken.Length > 20000)
        {
            await writer.WriteLineAsync(JsonSerializer.Serialize(new { ok = false, error = "Microsoft identity payload is invalid." }));
            return;
        }

        var body = new
        {
            terminalId = settings.TerminalId,
            computerName = Environment.MachineName,
            windowsUser = UsbDeviceDiscovery.GetInteractiveUser(),
            appVersion = Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "unknown",
            idToken
        };

        using var response = await Http.PostAsJsonAsync(EnrollmentUrl, body, token);
        var responseText = await response.Content.ReadAsStringAsync(token);

        if (!response.IsSuccessStatusCode)
        {
            var message = "Automatic Microsoft 365 enrollment was rejected.";
            try
            {
                using var json = JsonDocument.Parse(responseText);
                if (json.RootElement.TryGetProperty("error", out var error))
                    message = error.GetString() ?? message;
            }
            catch { }

            await writer.WriteLineAsync(JsonSerializer.Serialize(new { ok = false, error = message }));
            WriteWarning("Microsoft 365 automatic enrollment failed", message);
            return;
        }

        string? terminalToken = null;
        string? account = null;
        try
        {
            using var json = JsonDocument.Parse(responseText);
            terminalToken = json.RootElement.GetProperty("terminalToken").GetString();
            account = json.RootElement.TryGetProperty("account", out var accountElement)
                ? accountElement.GetString()
                : null;
        }
        catch { }

        if (string.IsNullOrWhiteSpace(terminalToken) || !terminalToken.StartsWith("csc_", StringComparison.Ordinal))
        {
            await writer.WriteLineAsync(JsonSerializer.Serialize(new { ok = false, error = "Enrollment server returned an invalid terminal credential." }));
            return;
        }

        settings.TerminalToken = terminalToken;
        settings.CloudApiUrl = IngestUrl;
        settings.WebConsoleUrl = WebConsoleUrl;
        settings.CloudSyncEnabled = true;
        settings.CloudSyncSeconds = 10;
        JsonStorage.SaveSettings(settings);

        var cloud = JsonStorage.LoadCloudState();
        cloud.BackfillCompleted = false;
        cloud.State = "Enrolled";
        cloud.Message = string.IsNullOrWhiteSpace(account)
            ? "Microsoft 365 automatic enrollment completed."
            : $"Automatically enrolled with CRECCOM Microsoft 365 account {account}.";
        JsonStorage.SaveCloudState(cloud);

        JsonStorage.AppendEvent(new AuditEvent
        {
            Kind = AuditEventKind.Warning,
            Timestamp = DateTimeOffset.Now,
            ComputerName = Environment.MachineName,
            WindowsUser = UsbDeviceDiscovery.GetInteractiveUser(),
            Evidence = "Microsoft 365 automatic enrollment",
            Notes = string.IsNullOrWhiteSpace(account) ? "CRECCOM account verified." : $"Verified CRECCOM account: {account}"
        });

        await writer.WriteLineAsync(JsonSerializer.Serialize(new { ok = true, account }));
    }

    private static UsbAuditSettings EnsureManagedDefaults()
    {
        var settings = JsonStorage.LoadSettings();
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
        return settings;
    }

    private static void WriteWarning(string evidence, string message)
    {
        try
        {
            JsonStorage.AppendEvent(new AuditEvent
            {
                Kind = AuditEventKind.Warning,
                Timestamp = DateTimeOffset.Now,
                ComputerName = Environment.MachineName,
                Evidence = evidence,
                Notes = message
            });
        }
        catch { }
    }
}
