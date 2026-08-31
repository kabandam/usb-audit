using System.Collections.Concurrent;
using System.Diagnostics;
using UsbAudit.Shared;

namespace UsbAudit.Agent;

internal static class EndpointCommandProcessor
{
    private static readonly ConcurrentQueue<EndpointCommandResult> Results = new();

    public static List<EndpointCommandResult> DrainResults()
    {
        var items = new List<EndpointCommandResult>();
        while (Results.TryDequeue(out var item)) items.Add(item);
        return items;
    }

    public static void Process(IEnumerable<EndpointCommandEnvelope>? commands)
    {
        if (commands is null) return;
        foreach (var command in commands.Take(20))
        {
            try
            {
                switch (command.CommandType)
                {
                    case "inventory":
                        _ = EndpointInventory.Capture();
                        Results.Enqueue(new EndpointCommandResult
                        {
                            CommandId = command.CommandId,
                            Status = "completed",
                            Message = "Endpoint inventory refreshed successfully."
                        });
                        break;

                    case "remote_support":
                        ShowRemoteSupportNotice();
                        Results.Enqueue(new EndpointCommandResult
                        {
                            CommandId = command.CommandId,
                            Status = "completed",
                            Message = "Remote support notice displayed to the signed-in user. User action is required to start a support session."
                        });
                        break;

                    default:
                        Results.Enqueue(new EndpointCommandResult
                        {
                            CommandId = command.CommandId,
                            Status = "failed",
                            Message = "Command type is not enabled on this agent."
                        });
                        break;
                }
            }
            catch (Exception ex)
            {
                Results.Enqueue(new EndpointCommandResult
                {
                    CommandId = command.CommandId,
                    Status = "failed",
                    Message = ex.Message
                });
            }
        }
    }

    private static void ShowRemoteSupportNotice()
    {
        var message = "CRECCOM IT has requested a remote support session. No remote access has started. Please contact IT and open Windows Quick Assist only when you are ready to continue.";
        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = "msg.exe",
            Arguments = $"* /TIME:120 \"{message}\"",
            UseShellExecute = false,
            CreateNoWindow = true
        });
        process?.WaitForExit(5000);
    }
}
