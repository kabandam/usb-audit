using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using UsbAudit.Agent;

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

var host = builder.Build();
await host.RunAsync();
