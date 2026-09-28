using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO.Compression;
using System.IO.Pipes;
using System.Net.Http.Headers;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using UsbAudit.Shared;

namespace UsbAudit.Agent;

internal static class EndpointCommandProcessor
{
    private const uint NoActiveSession = 0xFFFFFFFF;
    private const int MbOk = 0x00000000;
    private const int MbIconInformation = 0x00000040;
    private const string GraphTokenPipeName = "CRECCOM.SmartConsole.GraphToken";

    private static readonly ConcurrentDictionary<Guid, EndpointCommandResult> Results = new();
    private static readonly HttpClient DeploymentHttp = new()
    {
        Timeout = TimeSpan.FromMinutes(30)
    };

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

                    case "sync_policy":
                        var policyJson = JsonSerializer.Serialize(command.Payload);
                        var policy = JsonSerializer.Deserialize<EndpointControlPolicy>(
                            policyJson,
                            new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                        if (policy is null)
                            throw new InvalidOperationException("Endpoint policy payload was empty.");

                        JsonStorage.SaveEndpointControlPolicy(policy);
                        Results[command.CommandId] = new EndpointCommandResult
                        {
                            CommandId = command.CommandId,
                            Status = "completed",
                            Message = policy.Mode.Equals("enforce", StringComparison.OrdinalIgnoreCase)
                                ? $"Control policy synchronized with {policy.BlockedSoftware.Count} blocked software rule(s)."
                                : "Audit policy synchronized. Software blocking is not active."
                        };
                        break;

                    case "deploy_application":
                        var deploymentJson = JsonSerializer.Serialize(command.Payload);
                        var deployment = JsonSerializer.Deserialize<ApplicationDeploymentPayload>(
                            deploymentJson,
                            new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                        if (deployment is null)
                            throw new InvalidOperationException("Application deployment payload was empty.");

                        var deploymentMessage = DeployApplication(command.CommandId, deployment);
                        Results[command.CommandId] = new EndpointCommandResult
                        {
                            CommandId = command.CommandId,
                            Status = "completed",
                            Message = deploymentMessage
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

                TryWriteDeploymentAudit(command.CommandId, "Application deployment failed", ex.Message);
            }
        }
    }

    private static string DeployApplication(Guid commandId, ApplicationDeploymentPayload deployment)
    {
        if (string.IsNullOrWhiteSpace(deployment.AppName))
            throw new InvalidOperationException("Application name is missing.");

        if (!new[] { "msi", "exe" }.Contains(deployment.InstallerType, StringComparer.OrdinalIgnoreCase))
            throw new InvalidOperationException("Only MSI and EXE installers are supported.");

        var packageType = string.IsNullOrWhiteSpace(deployment.PackageType)
            ? deployment.InstallerType
            : deployment.PackageType;

        if (!new[] { "msi", "exe", "zip" }.Contains(packageType, StringComparer.OrdinalIgnoreCase))
            throw new InvalidOperationException("Package type must be MSI, EXE or ZIP.");

        if (string.IsNullOrWhiteSpace(deployment.Sha256) ||
            deployment.Sha256.Length != 64 ||
            !deployment.Sha256.All(Uri.IsHexDigit))
            throw new InvalidOperationException("Application package SHA-256 is invalid.");

        var root = Path.Combine(StoragePaths.DataDirectory, "Deployments", commandId.ToString("N"));
        Directory.CreateDirectory(root);

        var packageExtension = packageType.Equals("zip", StringComparison.OrdinalIgnoreCase)
            ? ".zip"
            : packageType.Equals("msi", StringComparison.OrdinalIgnoreCase) ? ".msi" : ".exe";
        var packagePath = Path.Combine(root, "package" + packageExtension);

        try
        {
            DownloadDeploymentPackage(deployment, packagePath);
            VerifySha256(packagePath, deployment.Sha256);

            var installerPath = packagePath;
            if (packageType.Equals("zip", StringComparison.OrdinalIgnoreCase))
            {
                var extractRoot = Path.Combine(root, "expanded");
                Directory.CreateDirectory(extractRoot);
                ZipFile.ExtractToDirectory(packagePath, extractRoot, overwriteFiles: true);
                installerPath = ResolveZipInstaller(extractRoot, deployment);
            }

            using var process = new Process();
            process.StartInfo = BuildInstallerStartInfo(installerPath, deployment);

            if (!process.Start())
                throw new InvalidOperationException("Windows could not start the application installer.");

            if (!process.WaitForExit((int)TimeSpan.FromMinutes(45).TotalMilliseconds))
            {
                try { process.Kill(entireProcessTree: true); } catch { }
                throw new TimeoutException(
                    $"Installation of {deployment.AppName} exceeded 45 minutes and was stopped.");
            }

            var successCodes = deployment.SuccessCodes.Count > 0
                ? deployment.SuccessCodes
                : [0, 1641, 3010];

            if (!successCodes.Contains(process.ExitCode))
                throw new InvalidOperationException(
                    $"{deployment.AppName} installer exited with code {process.ExitCode}.");

            var restartRequired = process.ExitCode is 1641 or 3010;
            var message = restartRequired
                ? $"{deployment.AppName} {deployment.AppVersion} installed successfully. Windows reports that a restart is required."
                : $"{deployment.AppName} {deployment.AppVersion} installed successfully.";

            TryWriteDeploymentAudit(commandId, "Application deployed", message);
            return message;
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { }
        }
    }

    private static void DownloadDeploymentPackage(
        ApplicationDeploymentPayload deployment,
        string packagePath)
    {
        if (deployment.StorageProvider.Equals("onedrive", StringComparison.OrdinalIgnoreCase))
        {
            DownloadOneDrivePackage(deployment, packagePath);
            return;
        }

        if (!Uri.TryCreate(deployment.PackageUrl, UriKind.Absolute, out var packageUri) ||
            packageUri.Scheme != Uri.UriSchemeHttps)
            throw new InvalidOperationException("Application package must use HTTPS.");

        using var response = DeploymentHttp.GetAsync(
            packageUri,
            HttpCompletionOption.ResponseHeadersRead).GetAwaiter().GetResult();
        response.EnsureSuccessStatusCode();

        using var source = response.Content.ReadAsStream();
        using var destination = File.Create(packagePath);
        source.CopyTo(destination);
    }

    private static void DownloadOneDrivePackage(
        ApplicationDeploymentPayload deployment,
        string packagePath)
    {
        var accessToken = GetGraphAccessToken();
        var driveId = deployment.StorageDriveId;
        var itemId = deployment.StorageItemId;

        if (!string.IsNullOrWhiteSpace(deployment.StorageWebUrl))
        {
            var encoded = Convert.ToBase64String(
                    Encoding.UTF8.GetBytes(deployment.StorageWebUrl))
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
            var shareId = "u!" + encoded;
            var resolveUrl =
                $"https://graph.microsoft.com/v1.0/shares/{Uri.EscapeDataString(shareId)}/driveItem";

            using var resolveRequest = new HttpRequestMessage(HttpMethod.Get, resolveUrl);
            resolveRequest.Headers.Authorization =
                new AuthenticationHeaderValue("Bearer", accessToken);

            using var resolveResponse = DeploymentHttp.Send(resolveRequest);
            if (resolveResponse.StatusCode == System.Net.HttpStatusCode.Unauthorized ||
                resolveResponse.StatusCode == System.Net.HttpStatusCode.Forbidden)
                throw new InvalidOperationException(
                    "The signed-in CRECCOM Microsoft 365 account cannot redeem the Data Centre package link.");

            resolveResponse.EnsureSuccessStatusCode();

            using var resolvedJson = JsonDocument.Parse(
                resolveResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult());
            itemId = resolvedJson.RootElement.TryGetProperty("id", out var itemValue)
                ? itemValue.GetString()
                : itemId;
            if (resolvedJson.RootElement.TryGetProperty("parentReference", out var parent) &&
                parent.TryGetProperty("driveId", out var driveValue))
                driveId = driveValue.GetString();
        }

        if (string.IsNullOrWhiteSpace(driveId) ||
            string.IsNullOrWhiteSpace(itemId))
            throw new InvalidOperationException(
                "Data Centre OneDrive package identifiers are missing.");

        var url =
            $"https://graph.microsoft.com/v1.0/drives/{Uri.EscapeDataString(driveId)}/items/{Uri.EscapeDataString(itemId)}/content";

        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        using var response = DeploymentHttp.Send(
            request,
            HttpCompletionOption.ResponseHeadersRead);

        if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized ||
            response.StatusCode == System.Net.HttpStatusCode.Forbidden)
            throw new InvalidOperationException(
                "The signed-in CRECCOM Microsoft 365 account cannot access this Data Centre application package.");

        response.EnsureSuccessStatusCode();

        using var source = response.Content.ReadAsStream();
        using var destination = File.Create(packagePath);
        source.CopyTo(destination);
    }

    private static string GetGraphAccessToken()
    {
        try
        {
            using var pipe = new NamedPipeClientStream(
                ".",
                GraphTokenPipeName,
                PipeDirection.InOut,
                PipeOptions.Asynchronous);

            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(8));
            pipe.ConnectAsync(timeout.Token).GetAwaiter().GetResult();

            using var reader = new StreamReader(pipe, Encoding.UTF8, false, 4096, leaveOpen: true);
            using var writer = new StreamWriter(
                pipe,
                new UTF8Encoding(false),
                4096,
                leaveOpen: true)
            {
                AutoFlush = true
            };

            writer.WriteLine(JsonSerializer.Serialize(new { action = "graph_token" }));
            var responseLine = reader.ReadLineAsync(timeout.Token).GetAwaiter().GetResult();

            if (string.IsNullOrWhiteSpace(responseLine))
                throw new InvalidOperationException("Microsoft 365 package broker returned no response.");

            using var response = JsonDocument.Parse(responseLine);
            var ok = response.RootElement.TryGetProperty("ok", out var okValue) && okValue.GetBoolean();
            if (!ok)
            {
                var error = response.RootElement.TryGetProperty("error", out var errorValue)
                    ? errorValue.GetString()
                    : null;
                throw new InvalidOperationException(
                    error ?? "Microsoft 365 package broker could not provide storage access.");
            }

            var token = response.RootElement.TryGetProperty("accessToken", out var tokenValue)
                ? tokenValue.GetString()
                : null;
            if (string.IsNullOrWhiteSpace(token))
                throw new InvalidOperationException("Microsoft 365 package broker returned no access token.");

            return token;
        }
        catch (TimeoutException)
        {
            throw new InvalidOperationException(
                "No signed-in CRECCOM Microsoft 365 user session is available for Data Centre package access.");
        }
        catch (OperationCanceledException)
        {
            throw new InvalidOperationException(
                "No signed-in CRECCOM Microsoft 365 user session is available for Data Centre package access.");
        }
    }

    private static string ResolveZipInstaller(
        string extractRoot,
        ApplicationDeploymentPayload deployment)
    {
        var entry = deployment.InstallerEntry;
        if (string.IsNullOrWhiteSpace(entry))
        {
            var candidates = Directory.EnumerateFiles(
                    extractRoot,
                    "*",
                    SearchOption.AllDirectories)
                .Where(path =>
                    path.EndsWith(".msi", StringComparison.OrdinalIgnoreCase) ||
                    path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                .Take(2)
                .ToList();

            if (candidates.Count != 1)
                throw new InvalidOperationException(
                    "ZIP package installer could not be identified unambiguously.");

            return candidates[0];
        }

        var normalizedEntry = entry
            .Replace('/', Path.DirectorySeparatorChar)
            .Replace('\\', Path.DirectorySeparatorChar)
            .TrimStart(Path.DirectorySeparatorChar);

        var rootFull = Path.GetFullPath(extractRoot)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            + Path.DirectorySeparatorChar;
        var candidate = Path.GetFullPath(Path.Combine(extractRoot, normalizedEntry));

        if (!candidate.StartsWith(rootFull, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("ZIP installer path is outside the approved package folder.");
        if (!File.Exists(candidate))
            throw new FileNotFoundException("ZIP installer entry was not found.", candidate);

        return candidate;
    }

    private static ProcessStartInfo BuildInstallerStartInfo(
        string installerPath,
        ApplicationDeploymentPayload deployment)
    {
        if (deployment.InstallerType.Equals("msi", StringComparison.OrdinalIgnoreCase))
        {
            return new ProcessStartInfo
            {
                FileName = "msiexec.exe",
                Arguments = $"/i \"{installerPath}\" /qn /norestart {deployment.InstallArgs}".Trim(),
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = Path.GetDirectoryName(installerPath)!
            };
        }

        return new ProcessStartInfo
        {
            FileName = installerPath,
            Arguments = deployment.InstallArgs ?? string.Empty,
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = Path.GetDirectoryName(installerPath)!
        };
    }

    private static void VerifySha256(string filePath, string expected)
    {
        using var stream = File.OpenRead(filePath);
        var actual = Convert.ToHexString(SHA256.HashData(stream));
        if (!string.Equals(actual, expected.Trim(), StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException(
                "The application package failed SHA-256 verification and was not installed.");
    }

    private static void TryWriteDeploymentAudit(Guid commandId, string evidence, string message)
    {
        try
        {
            JsonStorage.AppendEvent(new AuditEvent
            {
                Kind = AuditEventKind.Warning,
                Timestamp = DateTimeOffset.Now,
                ComputerName = Environment.MachineName,
                WindowsUser = UsbDeviceDiscovery.GetInteractiveUser(),
                Evidence = evidence,
                Notes = $"Command {commandId}: {message}"
            });
        }
        catch { }
    }

    private static void ShowRemoteSupportNotice()
    {
        const string title = "CRECCOM IT Support";
        const string message =
            "CRECCOM IT has requested a remote support session. No remote access has started. Please contact IT and open Windows Quick Assist only when you are ready to continue.";

        var sessionId = WTSGetActiveConsoleSessionId();
        if (sessionId == NoActiveSession)
        {
            throw new InvalidOperationException(
                "No interactive Windows session is currently available for the support notice.");
        }

        var displayed = WTSSendMessage(
            IntPtr.Zero,
            unchecked((int)sessionId),
            title,
            title.Length * sizeof(char),
            message,
            message.Length * sizeof(char),
            MbOk | MbIconInformation,
            120,
            out _,
            false);

        if (!displayed)
        {
            throw new System.ComponentModel.Win32Exception(
                Marshal.GetLastWin32Error(),
                "Windows could not display the CRECCOM support notice.");
        }
    }

    [DllImport("kernel32.dll")]
    private static extern uint WTSGetActiveConsoleSessionId();

    [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WTSSendMessage(
        IntPtr hServer,
        int sessionId,
        string title,
        int titleLength,
        string message,
        int messageLength,
        int style,
        int timeout,
        out int response,
        [MarshalAs(UnmanagedType.Bool)] bool wait);
}
