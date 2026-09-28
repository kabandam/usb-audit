using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Broker;

namespace UsbAudit.Identity;

internal static class Program
{
    private const string TenantId = "4d9d354c-4cb5-48d5-93ba-ea4db8c5206e";
    private const string ClientId = "f06469cb-12ab-467c-a2d1-58f2c7750f29";
    private const string EnrollmentPipeName = "CRECCOM.UsbAudit.Identity";
    private const string GraphTokenPipeName = "CRECCOM.SmartConsole.GraphToken";
    private static readonly string[] EnrollmentScopes = ["User.Read"];
    private static readonly string[] GraphScopes = ["User.Read", "Files.ReadWrite.All"];

    [STAThread]
    private static async Task Main()
    {
        var app = BuildApplication();

        for (var attempt = 0; attempt < 12; attempt++)
        {
            try
            {
                if (await TryEnrollAsync(app)) break;
            }
            catch (Exception ex)
            {
                WriteDiagnostic(ex.Message);
            }

            await Task.Delay(TimeSpan.FromMinutes(5));
        }

        await RunGraphTokenBrokerAsync(app);
    }

    private static IPublicClientApplication BuildApplication()
    {
        var brokerOptions = new BrokerOptions(BrokerOptions.OperatingSystems.Windows)
        {
            Title = "CRECCOM Smart Console"
        };

        return PublicClientApplicationBuilder
            .Create(ClientId)
            .WithAuthority(AzureCloudInstance.AzurePublic, TenantId)
            .WithRedirectUri($"ms-appx-web://Microsoft.AAD.BrokerPlugin/{ClientId}")
            .WithBroker(brokerOptions)
            .Build();
    }

    private static async Task<IAccount> GetCreccomAccountAsync(IPublicClientApplication app)
    {
        var accounts = await app.GetAccountsAsync();
        return accounts.FirstOrDefault(item =>
                   item.Username?.EndsWith("@creccommw.org", StringComparison.OrdinalIgnoreCase) == true)
               ?? PublicClientApplication.OperatingSystemAccount;
    }

    private static async Task<bool> TryEnrollAsync(IPublicClientApplication app)
    {
        var account = await GetCreccomAccountAsync(app);
        AuthenticationResult result;
        try
        {
            result = await app.AcquireTokenSilent(EnrollmentScopes, account).ExecuteAsync();
        }
        catch (MsalUiRequiredException)
        {
            WriteDiagnostic("Microsoft 365 silent SSO requires user interaction or tenant consent.");
            return false;
        }

        var username = result.Account?.Username
                       ?? result.ClaimsPrincipal?.FindFirst("preferred_username")?.Value
                       ?? string.Empty;
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

        using var pipe = new NamedPipeClientStream(
            ".", EnrollmentPipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(8));
        await pipe.ConnectAsync(timeout.Token);

        using var reader = new StreamReader(pipe, Encoding.UTF8, false, 4096, leaveOpen: true);
        using var writer = new StreamWriter(pipe, new UTF8Encoding(false), 4096, leaveOpen: true)
        {
            AutoFlush = true
        };

        await writer.WriteLineAsync(JsonSerializer.Serialize(new
        {
            idToken = result.IdToken,
            account = username
        }));

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

    private static async Task RunGraphTokenBrokerAsync(IPublicClientApplication app)
    {
        WriteDiagnostic("Smart Console Microsoft 365 package broker is running.");

        while (true)
        {
            try
            {
                using var pipe = CreateGraphTokenPipe();
                await pipe.WaitForConnectionAsync();
                await HandleGraphTokenRequestAsync(app, pipe);
            }
            catch (Exception ex)
            {
                WriteDiagnostic("Package broker warning: " + ex.Message);
                await Task.Delay(TimeSpan.FromSeconds(3));
            }
        }
    }

    private static NamedPipeServerStream CreateGraphTokenPipe()
    {
        var security = new PipeSecurity();
        var currentSid = WindowsIdentity.GetCurrent().User;
        var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);

        if (currentSid is not null)
            security.AddAccessRule(new PipeAccessRule(
                currentSid, PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(
            systemSid, PipeAccessRights.FullControl, AccessControlType.Allow));

        return NamedPipeServerStreamAcl.Create(
            GraphTokenPipeName,
            PipeDirection.InOut,
            2,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous,
            8192,
            8192,
            security);
    }

    private static async Task HandleGraphTokenRequestAsync(
        IPublicClientApplication app,
        NamedPipeServerStream pipe)
    {
        using var reader = new StreamReader(pipe, Encoding.UTF8, false, 4096, leaveOpen: true);
        using var writer = new StreamWriter(pipe, new UTF8Encoding(false), 4096, leaveOpen: true)
        {
            AutoFlush = true
        };

        var line = await reader.ReadLineAsync();
        if (string.IsNullOrWhiteSpace(line))
        {
            await writer.WriteLineAsync(JsonSerializer.Serialize(new
            {
                ok = false,
                error = "Empty package broker request."
            }));
            return;
        }

        try
        {
            using var request = JsonDocument.Parse(line);
            var action = request.RootElement.TryGetProperty("action", out var actionValue)
                ? actionValue.GetString()
                : null;

            if (!string.Equals(action, "graph_token", StringComparison.Ordinal))
            {
                await writer.WriteLineAsync(JsonSerializer.Serialize(new
                {
                    ok = false,
                    error = "Unsupported package broker request."
                }));
                return;
            }
        }
        catch
        {
            await writer.WriteLineAsync(JsonSerializer.Serialize(new
            {
                ok = false,
                error = "Invalid package broker request."
            }));
            return;
        }

        try
        {
            var account = await GetCreccomAccountAsync(app);
            var result = await app.AcquireTokenSilent(GraphScopes, account).ExecuteAsync();
            var username = result.Account?.Username ?? string.Empty;

            if (!username.EndsWith("@creccommw.org", StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Microsoft account is not a CRECCOM account.");

            await writer.WriteLineAsync(JsonSerializer.Serialize(new
            {
                ok = true,
                accessToken = result.AccessToken,
                expiresOn = result.ExpiresOn,
                account = username
            }));
        }
        catch (MsalUiRequiredException)
        {
            await writer.WriteLineAsync(JsonSerializer.Serialize(new
            {
                ok = false,
                error = "Microsoft 365 storage access requires sign-in or consent in Smart Console."
            }));
        }
        catch (Exception ex)
        {
            await writer.WriteLineAsync(JsonSerializer.Serialize(new
            {
                ok = false,
                error = ex.Message
            }));
        }
    }

    private static void WriteDiagnostic(string message)
    {
        try
        {
            var root = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "CRECCOM", "SmartConsole");
            Directory.CreateDirectory(root);
            File.AppendAllText(
                Path.Combine(root, "identity.log"),
                $"{DateTimeOffset.Now:O}  {message}{Environment.NewLine}",
                Encoding.UTF8);
        }
        catch { }
    }
}
