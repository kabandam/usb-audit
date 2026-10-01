using Microsoft.Extensions.Hosting;
using UsbAudit.Shared;

namespace UsbAudit.Agent;

internal sealed class PendingDeploymentWorker : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        StoragePaths.EnsureDirectories();

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                if (JsonStorage.LoadSettings().DeploymentServiceEnabled)
                {
                    foreach (var commandId in JsonStorage.ReadPendingDeploymentInstallRequests())
                        EndpointCommandProcessor.QueuePendingInstall(commandId);
                }

                await Task.Delay(TimeSpan.FromSeconds(2), stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch
            {
                try { await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken); }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            }
        }
    }
}
