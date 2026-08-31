using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using UsbAudit.Agent;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "USB Audit Agent";
});
builder.Services.AddHostedService<UsbMonitorWorker>();

var host = builder.Build();
await host.RunAsync();
