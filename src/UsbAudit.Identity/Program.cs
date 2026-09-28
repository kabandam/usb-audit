using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Broker;

namespace UsbAudit.Identity;

internal static class Program
{
    private const string TenantId = "4d9d354c-4cb5-48d5-93ba-ea4db8c5206e";
    private const string ClientId = "f06469cb-12ab-467c-a2d1-58f2c7750f29";
    private const string PipeName = "CRECCOM.UsbAudit.Identity";
    private static readonly string[] Scopes = ["User.Read"];

    [STAThread]
    private static async Task Main()
    {
        // This helper is intentionally silent. It runs in the interactive user's
        // Windows session so WAM can reuse an existing CRECCOM work/school account.
        // It never stores Microsoft access, refresh, or ID tokens on disk.
        for (var attempt = 0; attempt < 12; attempt++)
        {
            try
            {
                if (await TryEnrollAsync()) return;
            }
            catch (Exception ex)
            {
                WriteDiagnostic(ex.Message);
            }

            await Task.Delay(TimeSpan.FromMinutes(5));
        }
    }

    private static async Task<bool> TryEnrollAsync()
    {
        var brokerOptions = new BrokerOptions(BrokerOptions.OperatingSystems.Windows)
        {
            Title = "CRECCOM USB Audit"
        };

        var app = PublicClientApplicationBuilder
            .Create(ClientId)
            .WithAuthority(AzureCloudInstance.AzurePublic, TenantId)
            .WithRedirectUri($"ms-appx-web://Microsoft.AAD.BrokerPlugin/{ClientId}")
            .WithBroker(brokerOptions)
            .Build();

        var accounts = await app.GetAccountsAsync();
        var account = accounts.FirstOrDefault(item =>
            item.Username?.EndsWith("@creccommw.org", StringComparison.OrdinalIgnoreCase) == true)
            ?? PublicClientApplication.OperatingSystemAccount;

        AuthenticationResult result;
        try
        {
            result = await app.AcquireTokenSilent(Scopes, account).ExecuteAsync();
        }
        catch (MsalUiRequiredException)
        {
            // Zero-touch enrollment must stay silent. If tenant consent/MFA is ever
            // required, no password prompt is forced by this background helper.
            WriteDiagnostic("Microsoft 365 silent SSO requires user interaction or tenant consent.");
            return false;
        }

        var username = result.Account?.Username ?? result.ClaimsPrincipal?.FindFirst("preferred_username")?.Value ?? string.Empty;
        if (!username.EndsWith("@creccommw.org", StringComparison.OrdinalIgnoreCase))
        {
            WriteDiagnostic("The Windows account returned by WAM is not a CRECCOM Microsoft 365 account.");
            return false;
        }
        if (string.IsNullOrWhiteSpace(result.IdToken))
        {
            WriteDiagnostic("Microsoft 365 silent SSO returned no identity token.");
            return false;
        }

        using var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(8));
        await pipe.ConnectAsync(timeout.Token);

        using var reader = new StreamReader(pipe, Encoding.UTF8, false, 4096, leaveOpen: true);
        using var writer = new StreamWriter(pipe, new UTF8Encoding(false), 4096, leaveOpen: true) { AutoFlush = true };

        var message = JsonSerializer.Serialize(new
        {
            idToken = result.IdToken,
            account = username
        });
        await writer.WriteLineAsync(message);

        var responseLine = await reader.ReadLineAsync(timeout.Token);
        if (string.IsNullOrWhiteSpace(responseLine)) return false;

        using var response = JsonDocument.Parse(responseLine);
        var ok = response.RootElement.TryGetProperty("ok", out var okValue) && okValue.GetBoolean();
        if (ok)
        {
            WriteDiagnostic($"Automatic Microsoft 365 enrollment confirmed for {username}.");
            return true;
        }

        var error = response.RootElement.TryGetProperty("error", out var errorValue)
            ? errorValue.GetString()
            : "Unknown enrollment response";
        WriteDiagnostic(error ?? "Unknown enrollment response");
        return false;
    }

    private static void WriteDiagnostic(string message)
    {
        try
        {
            var root = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "CRECCOM", "UsbAudit");
            Directory.CreateDirectory(root);
            File.AppendAllText(
                Path.Combine(root, "identity.log"),
                $"{DateTimeOffset.Now:O}  {message}{Environment.NewLine}",
                Encoding.UTF8);
        }
        catch { }
    }
}
