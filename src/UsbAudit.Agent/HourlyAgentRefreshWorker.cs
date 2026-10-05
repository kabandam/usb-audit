using System.Diagnostics;
using System.Text;
using Microsoft.Extensions.Hosting;
using UsbAudit.Shared;

namespace UsbAudit.Agent;

internal sealed class HourlyAgentRefreshWorker : BackgroundService
{
    private static readonly TimeSpan RefreshInterval = TimeSpan.FromHours(1);
    private static readonly TimeSpan BusyRetryDelay = TimeSpan.FromMinutes(10);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(RefreshInterval, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    if (EndpointCommandProcessor.HasActiveDeployment || ManagedUpdateBusy())
                    {
                        await Task.Delay(BusyRetryDelay, stoppingToken);
                        continue;
                    }

                    ScheduleSilentServiceRestart();
                    return; // The restarted Windows service creates a fresh hourly timer.
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    return;
                }
                catch (Exception ex)
                {
                    TryAudit("Hourly Smart Console Agent refresh could not be scheduled: " + ex.Message);
                    try { await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken); }
                    catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { return; }
                }
            }
        }
    }

    private static bool ManagedUpdateBusy()
    {
        var state = JsonStorage.LoadUpdateStatus().State ?? string.Empty;
        return state.Equals("Downloading", StringComparison.OrdinalIgnoreCase)
               || state.Equals("Installing", StringComparison.OrdinalIgnoreCase);
    }

    private static void ScheduleSilentServiceRestart()
    {
        const string script = "Start-Sleep -Seconds 5; Restart-Service -Name 'UsbAuditAgent' -Force -ErrorAction Stop";
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));

        var process = Process.Start(new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand {encoded}",
            UseShellExecute = false,
            CreateNoWindow = true
        });

        if (process is null)
            throw new InvalidOperationException("Windows could not start the silent service refresh helper.");

        TryAudit("Hourly Smart Console Agent refresh scheduled.");
    }

    private static void TryAudit(string message)
    {
        try
        {
            JsonStorage.AppendEvent(new AuditEvent
            {
                Kind = AuditEventKind.Warning,
                Timestamp = DateTimeOffset.Now,
                ComputerName = Environment.MachineName,
                Evidence = "Agent self-refresh",
                Notes = message
            });
        }
        catch { }
    }
}
