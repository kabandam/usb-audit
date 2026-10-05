using Microsoft.Extensions.Hosting;
using UsbAudit.Shared;

namespace UsbAudit.Agent;

internal sealed class ManagedUpdateWorker : BackgroundService
{
    private static readonly TimeSpan RequestPollInterval = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan InitialDelay = TimeSpan.FromSeconds(20);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        StoragePaths.EnsureDirectories();

        try
        {
            await Task.Delay(InitialDelay, stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            return;
        }

        DateTimeOffset? lastAutomaticCheck = null;
        DateTimeOffset? retryAfter = null;

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var settings = JsonStorage.LoadSettings();
                // Preserve requests until the updater gate has actually been acquired.
                // Another scheduled/manual check may currently own that gate.
                var forced = File.Exists(StoragePaths.UpdateRequestPath);
                var forceInventoryInstall = File.Exists(StoragePaths.InventoryUpdateRequestPath);
                var intervalHours = Math.Clamp(settings.UpdateCheckHours, 1, 24);
                var automaticDue = settings.AutoUpdatesEnabled &&
                    (lastAutomaticCheck is null ||
                     DateTimeOffset.UtcNow - lastAutomaticCheck.Value >= TimeSpan.FromHours(intervalHours));

                var retryAllowed = retryAfter is null || DateTimeOffset.UtcNow >= retryAfter.Value;
                if ((forced || forceInventoryInstall || automaticDue) && retryAllowed)
                {
                    var started = await GitHubUpdateManager.CheckAndApplyAsync(
                        settings,
                        stoppingToken,
                        forceCheck: forced || forceInventoryInstall,
                        forceInstall: forceInventoryInstall);

                    // A contending update must not discard an admin-requested installation.
                    // Transient download/check failures also keep the request flags so the
                    // agent can retry automatically and resume the partial package.
                    if (started)
                    {
                        var update = JsonStorage.LoadUpdateStatus();
                        var failed = update.State.Contains("failed", StringComparison.OrdinalIgnoreCase)
                                     || update.State.Contains("error", StringComparison.OrdinalIgnoreCase);

                        if (failed)
                        {
                            retryAfter = DateTimeOffset.UtcNow.AddMinutes(1);
                        }
                        else
                        {
                            retryAfter = null;
                            if (forced) ConsumeManualRequest();
                            if (forceInventoryInstall) ConsumeInventoryUpdateRequest();
                            lastAutomaticCheck = DateTimeOffset.UtcNow;
                        }
                    }
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                JsonStorage.SaveUpdateStatus(new UpdateStatus
                {
                    LastCheckedAt = DateTimeOffset.Now,
                    CurrentVersion = typeof(ManagedUpdateWorker).Assembly.GetName().Version?.ToString(3) ?? "unknown",
                    State = "Update worker error",
                    Message = ex.Message
                });

                try
                {
                    JsonStorage.AppendEvent(new AuditEvent
                    {
                        Kind = AuditEventKind.Warning,
                        Timestamp = DateTimeOffset.Now,
                        ComputerName = Environment.MachineName,
                        Evidence = "Managed update worker warning",
                        Notes = ex.Message
                    });
                }
                catch { }
            }

            try
            {
                await Task.Delay(RequestPollInterval, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
        }
    }

    private static bool ConsumeInventoryUpdateRequest()
    {
        try
        {
            if (!File.Exists(StoragePaths.InventoryUpdateRequestPath)) return false;
            File.Delete(StoragePaths.InventoryUpdateRequestPath);
            return true;
        }
        catch (IOException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
    }

    private static bool ConsumeManualRequest()
    {
        try
        {
            if (!File.Exists(StoragePaths.UpdateRequestPath)) return false;
            File.Delete(StoragePaths.UpdateRequestPath);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
