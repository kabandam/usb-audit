using System.Collections.Concurrent;
using System.Diagnostics;
using UsbAudit.Shared;

namespace UsbAudit.Agent;

internal static class EndpointCommandProcessor
{
    private static readonly ConcurrentDictionary<Guid, EndpointCommandResult> Results = new();

    public static List<EndpointCommandResult> GetPendingResults() => Results.Values.ToList();

    public static void AcknowledgeResults(IEnumerable<Guid> commandIds)
    {
        foreach (var id in commandIds) Results.TryRemove(id, out _);
    }

    public static void Process(IEnumerable<EndpointCommandEnvelope>? commands)
    {
        if (commands is null) return;
        foreach (var command in commands.Take(20))
        {
            if (Results.ContainsKey(command.CommandId)) continue;
            try
            {
                switch (command.CommandType)
                {
                    case "inventory":
                        _ = EndpointInventory.Capture();
                        Results[command.CommandId] = new EndpointCommandResult
                        {
                            CommandId = command.CommandId,
                            Status = "completed",
                            Message = "Endpoint inventory refreshed successfully."
                        };
                        break;

                    case "remote_support":
                        ShowRemoteSupportNotice();
                        Results[command.CommandId] = new EndpointCommandResult
                        {
                            CommandId = command.CommandId,
                            Status = "completed",
                            Message = "Remote support notice displayed to the signed-in user. User action is required to start a support session."
                        };
                        break;

                    default:
                        Results[command.CommandId] = new EndpointCommandResult
                        {
                            CommandId = command.CommandId,
                            Status = "failed",
                            Message = "Command type is not enabled on this agent."
                        };
                        break;
                }
            }
            catch (Exception ex)
            {
                Results[command.CommandId] = new EndpointCommandResult
                {
                    CommandId = command.CommandId,
                    Status = "failed",
                    Message = ex.Message
                };
            }
        }
    }

    private static void ShowRemoteSupportNotice()
    {
        var message = "CRECCOM IT has requested a remote support session. No remote access has started. Please contact IT and open Windows Quick Assist only when you are ready to continue.";
        using var process = System.Diagnostics.Process.Start(new ProcessStartInfo
        {
            FileName = "msg.exe",
            Arguments = $"* /TIME:120 \"{message}\"",
            UseShellExecute = false,
            CreateNoWindow = true
        });
        process?.WaitForExit(5000);
    }
}
