using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using UsbAudit.Agent;
using UsbAudit.Shared;

// The signed, verified release carries this tiny diagnostic entry point. It is invoked
// only by the update installer on failure, including when the CURRENT running agent
// is too old to send managed-update telemetry. It logs through the existing hash chain.
if (args.Length > 0 && string.Equals(args[0], "--record-update-failure", StringComparison.OrdinalIgnoreCase))
{
    try
    {
        var reason = args.Length > 1 ? args[1] : "Installer failed without an error message.";
        JsonStorage.AppendEvent(new AuditEvent
        {
            Kind = AuditEventKind.Warning,
            Timestamp = DateTimeOffset.UtcNow,
            ComputerName = Environment.MachineName,
            Evidence = "Managed Smart Console update failed",
            Notes = reason.Length > 600 ? reason[..600] : reason
        });
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine("Could not persist managed-update failure: " + ex.Message);
        Environment.ExitCode = 1;
    }
    return;
}

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "Smart Console Agent";
});
builder.Services.AddHostedService<UsbMonitorWorker>();
builder.Services.AddHostedService<CloudSyncWorker>();
builder.Services.AddHostedService<MachineEnrollmentWorker>();
builder.Services.AddHostedService<ManagedUpdateWorker>();
builder.Services.AddHostedService<IdentityEnrollmentWorker>();
builder.Services.AddHostedService<SoftwareControlWorker>();
builder.Services.AddHostedService<PendingDeploymentWorker>();

var host = builder.Build();
await host.RunAsync();
