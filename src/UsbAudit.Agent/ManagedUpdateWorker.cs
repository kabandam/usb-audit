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

                if (forced || forceInventoryInstall || automaticDue)
                {
                    var started = await GitHubUpdateManager.CheckAndApplyAsync(
                        settings,
                        stoppingToken,
                        forceCheck: forced || forceInventoryInstall,
                        forceInstall: forceInventoryInstall);

                    // A contending update must not discard an admin-requested installation.
                    // Retry on the next poll if the gate was already busy.
                    if (started)
                    {
                        if (forced) ConsumeManualRequest();
                        if (forceInventoryInstall) ConsumeInventoryUpdateRequest();
                        lastAutomaticCheck = DateTimeOffset.UtcNow;
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
