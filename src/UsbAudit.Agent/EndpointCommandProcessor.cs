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
    private static readonly ConcurrentDictionary<Guid, DeploymentProgressReport> Progress = new();
    private static readonly ConcurrentDictionary<Guid, byte> Running = new();
    private static readonly SemaphoreSlim DeploymentGate = new(1, 1);
    private static readonly HttpClient DeploymentHttp = new()
    {
        Timeout = TimeSpan.FromMinutes(20)
    };

    public static bool HasActiveDeployment => Running.Count > 0;

    public static List<EndpointCommandResult> GetPendingResults() => Results.Values.ToList();

    public static List<DeploymentProgressReport> GetDeploymentProgress() =>
        Progress.Values.OrderBy(item => item.UpdatedAt).ToList();

    public static void AcknowledgeResults(IEnumerable<Guid> commandIds)
    {
        foreach (var id in commandIds)
        {
            Results.TryRemove(id, out _);
            Progress.TryRemove(id, out _);
        }
    }

    public static void Process(IEnumerable<EndpointCommandEnvelope>? commands)
    {
        if (commands is null) return;

        foreach (var command in commands.Take(20))
        {
            if (Results.ContainsKey(command.CommandId) || Running.ContainsKey(command.CommandId))
                continue;

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

                        if (Running.TryAdd(command.CommandId, 0))
                        {
                            SetProgress(command.CommandId, deployment, 2, "queued",
                                "Deployment received by the endpoint.", deployment.Attempt);
                            _ = Task.Run(() => RunDeploymentAsync(command.CommandId, deployment));
                        }
                        break;

                    case "verify_application_package":
                        var verificationJson = JsonSerializer.Serialize(command.Payload);
                        var verification = JsonSerializer.Deserialize<ApplicationDeploymentPayload>(
                            verificationJson,
                            new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                        if (verification is null || verification.AppId == Guid.Empty)
                            throw new InvalidOperationException("Application verification payload was invalid.");

                        if (Running.TryAdd(command.CommandId, 0))
                            _ = Task.Run(() => RunPackageVerificationAsync(command.CommandId, verification));
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

    private static async Task RunPackageVerificationAsync(
        Guid commandId,
        ApplicationDeploymentPayload deployment)
    {
        await DeploymentGate.WaitAsync();
        var root = Path.Combine(StoragePaths.DataDirectory, "PackageVerification", commandId.ToString("N"));
        Directory.CreateDirectory(root);

        try
        {
            var packageType = string.IsNullOrWhiteSpace(deployment.PackageType)
                ? deployment.InstallerType
                : deployment.PackageType;
            var extension = packageType.Equals("zip", StringComparison.OrdinalIgnoreCase)
                ? ".zip"
                : packageType.Equals("msi", StringComparison.OrdinalIgnoreCase) ? ".msi" : ".exe";
            var packagePath = Path.Combine(root, "package" + extension);

            Exception? lastError = null;
            for (var attempt = 1; attempt <= 5; attempt++)
            {
                try
                {
                    if (File.Exists(packagePath)) File.Delete(packagePath);
                    await DownloadDeploymentPackageAsync(deployment, packagePath, _ => { });
                    lastError = null;
                    break;
                }
                catch (Exception ex)
                {
                    lastError = ex;
                    if (attempt < 5)
                        await Task.Delay(TimeSpan.FromSeconds(attempt * 3));
                }
            }

            if (lastError is not null)
                throw new InvalidOperationException($"Package verification download failed after 5 attempts: {lastError.Message}");

            string digest;
            await using (var stream = File.OpenRead(packagePath))
                digest = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();

            if (!string.IsNullOrWhiteSpace(deployment.Sha256) &&
                !string.Equals(digest, deployment.Sha256.Trim(), StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("The stored package no longer matches its approved SHA-256.");

            await RunDefenderScanAsync(packagePath);

            if (packageType.Equals("zip", StringComparison.OrdinalIgnoreCase))
            {
                var extractRoot = Path.Combine(root, "expanded");
                Directory.CreateDirectory(extractRoot);
                ZipFile.ExtractToDirectory(packagePath, extractRoot, overwriteFiles: true);
                var installerPath = ResolveZipInstaller(extractRoot, deployment);
                await RunDefenderScanAsync(installerPath);
            }

            var message = $"{deployment.AppName} package verified: SHA-256 calculated and Microsoft Defender reported no threat.";
            Results[commandId] = new EndpointCommandResult
            {
                CommandId = commandId,
                Status = "completed",
                Message = message,
                AppId = deployment.AppId,
                PackageSha256 = digest,
                DefenderScanStatus = "clean"
            };
            TryWriteDeploymentAudit(commandId, "Application package verified", message);
        }
        catch (Exception ex)
        {
            Results[commandId] = new EndpointCommandResult
            {
                CommandId = commandId,
                Status = "failed",
                Message = ex.Message,
                AppId = deployment.AppId,
                DefenderScanStatus = "failed"
            };
            TryWriteDeploymentAudit(commandId, "Application package verification failed", ex.Message);
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { }
            Running.TryRemove(commandId, out _);
            DeploymentGate.Release();
        }
    }

    private static async Task RunDeploymentAsync(
        Guid commandId,
        ApplicationDeploymentPayload deployment)
    {
        await DeploymentGate.WaitAsync();
        try
        {
            SetProgress(commandId, deployment, 4, "preparing",
                "Preparing deployment workspace.", deployment.Attempt);

            var message = await DeployApplicationAsync(commandId, deployment);

            SetProgress(commandId, deployment, 100, "completed",
                message, deployment.Attempt, "clean");

            Results[commandId] = new EndpointCommandResult
            {
                CommandId = commandId,
                Status = "completed",
                Message = message
            };
        }
        catch (Exception ex)
        {
            var previous = Progress.TryGetValue(commandId, out var current)
                ? current.ProgressPercent
                : 0;

            SetProgress(commandId, deployment, Math.Clamp(previous, 0, 99), "failed",
                ex.Message, deployment.Attempt,
                current?.DefenderScanStatus);

            Results[commandId] = new EndpointCommandResult
            {
                CommandId = commandId,
                Status = "failed",
                Message = ex.Message
            };

            TryWriteDeploymentAudit(commandId, "Application deployment failed", ex.Message);
        }
        finally
        {
            Running.TryRemove(commandId, out _);
            DeploymentGate.Release();
        }
    }

    private static async Task<string> DeployApplicationAsync(
        Guid commandId,
        ApplicationDeploymentPayload deployment)
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

        if (deployment.InstallerType.Equals("exe", StringComparison.OrdinalIgnoreCase) &&
            string.IsNullOrWhiteSpace(deployment.InstallArgs))
            throw new InvalidOperationException(
                $"{deployment.AppName} is an EXE package without silent install arguments. It was not started because an interactive installer can wait indefinitely.");

        if (string.IsNullOrWhiteSpace(deployment.Sha256) ||
            deployment.Sha256.Length != 64 ||
            !deployment.Sha256.All(Uri.IsHexDigit))
            throw new InvalidOperationException("Application package SHA-256 is invalid.");

        var root = Path.Combine(StoragePaths.DataDirectory, "Deployments", commandId.ToString("N"));
        Directory.CreateDirectory(root);

        var packageExtension = packageType.Equals("zip", StringComparison.OrdinalIgnoreCase)
            ? ".zip"
            : packageType.Equals("msi", StringComparison.OrdinalIgnoreCase) ? ".msi" : ".exe";

        var cacheRoot = Path.Combine(StoragePaths.DataDirectory, "PackageCache");
        Directory.CreateDirectory(cacheRoot);
        var cacheKey = deployment.Sha256.Trim().ToLowerInvariant();
        var cachedPackagePath = Path.Combine(cacheRoot, cacheKey + packageExtension);
        var packagePath = cachedPackagePath;

        try
        {
            if (File.Exists(cachedPackagePath) && IsPackageHashValid(cachedPackagePath, deployment.Sha256))
            {
                SetProgress(commandId, deployment, 58, "cache_hit",
                    "Verified package already cached on this endpoint. Download skipped.",
                    deployment.Attempt);
            }
            else
            {
                try { if (File.Exists(cachedPackagePath)) File.Delete(cachedPackagePath); } catch { }

                var temporaryPackagePath = Path.Combine(root, "package" + packageExtension);
                await DownloadWithRetryAsync(commandId, deployment, temporaryPackagePath);

                SetProgress(commandId, deployment, 60, "verifying_hash",
                    "Verifying SHA-256 package integrity.", deployment.Attempt);
                VerifySha256(temporaryPackagePath, deployment.Sha256);

                File.Copy(temporaryPackagePath, cachedPackagePath, overwrite: true);
                packagePath = cachedPackagePath;
            }

            SetProgress(commandId, deployment, 66, "hash_verified",
                "SHA-256 verified.", deployment.Attempt);

            SetProgress(commandId, deployment, 69, "defender_scan",
                "Scanning package with Microsoft Defender.", deployment.Attempt, "scanning");
            await RunDefenderScanAsync(packagePath);
            SetProgress(commandId, deployment, 74, "defender_clean",
                "Microsoft Defender scan completed with no threat reported.",
                deployment.Attempt, "clean");

            var installerPath = packagePath;
            if (packageType.Equals("zip", StringComparison.OrdinalIgnoreCase))
            {
                SetProgress(commandId, deployment, 76, "extracting",
                    "Extracting approved ZIP package.", deployment.Attempt, "clean");

                var extractRoot = Path.Combine(root, "expanded");
                Directory.CreateDirectory(extractRoot);
                ZipFile.ExtractToDirectory(packagePath, extractRoot, overwriteFiles: true);
                installerPath = ResolveZipInstaller(extractRoot, deployment);

                SetProgress(commandId, deployment, 78, "defender_scan",
                    "Scanning extracted installer with Microsoft Defender.",
                    deployment.Attempt, "scanning");
                await RunDefenderScanAsync(installerPath);
                SetProgress(commandId, deployment, 80, "defender_clean",
                    "Extracted installer passed Microsoft Defender scan.",
                    deployment.Attempt, "clean");
            }

            using var process = new Process();
            process.StartInfo = BuildInstallerStartInfo(installerPath, deployment);

            SetProgress(commandId, deployment, 82, "installing",
                $"Installing {deployment.AppName}.", deployment.Attempt, "clean");

            if (!process.Start())
                throw new InvalidOperationException("Windows could not start the application installer.");

            var installStarted = DateTimeOffset.UtcNow;
            var installTimeout = TimeSpan.FromMinutes(Math.Clamp(deployment.InstallTimeoutMinutes, 5, 60));
            var exitTask = process.WaitForExitAsync();

            while (!exitTask.IsCompleted)
            {
                var elapsed = DateTimeOffset.UtcNow - installStarted;
                if (elapsed > installTimeout)
                {
                    try { process.Kill(entireProcessTree: true); } catch { }
                    throw new TimeoutException(
                        $"Installation of {deployment.AppName} exceeded its {installTimeout.TotalMinutes:0}-minute unattended-install timeout and was stopped.");
                }

                var percent = 82 + (int)Math.Min(15,
                    Math.Floor(elapsed.TotalMinutes / Math.Max(1d, installTimeout.TotalMinutes) * 15d));

                SetProgress(commandId, deployment, percent, "installing",
                    $"Installer is running ({FormatElapsed(elapsed)}).",
                    deployment.Attempt, "clean");

                await Task.WhenAny(exitTask, Task.Delay(TimeSpan.FromSeconds(5)));
            }

            await exitTask;

            var successCodes = deployment.SuccessCodes.Count > 0
                ? deployment.SuccessCodes
                : [0, 1641, 3010];

            if (!successCodes.Contains(process.ExitCode))
                throw new InvalidOperationException(
                    $"{deployment.AppName} installer exited with code {process.ExitCode}.");

            SetProgress(commandId, deployment, 98, "finalizing",
                "Refreshing endpoint software inventory.", deployment.Attempt, "clean");
            _ = EndpointInventory.Capture();

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

    private static async Task DownloadWithRetryAsync(
        Guid commandId,
        ApplicationDeploymentPayload deployment,
        string packagePath)
    {
        const int maximumAttempts = 3;
        Exception? lastError = null;

        for (var attempt = 1; attempt <= maximumAttempts; attempt++)
        {
            try
            {
                if (File.Exists(packagePath)) File.Delete(packagePath);

                SetProgress(commandId, deployment, 6, "downloading",
                    attempt == 1
                        ? "Downloading application package."
                        : $"Retrying package download ({attempt}/{maximumAttempts}).",
                    Math.Max(deployment.Attempt, attempt));

                await DownloadDeploymentPackageAsync(
                    deployment,
                    packagePath,
                    fraction =>
                    {
                        var percent = 8 + (int)Math.Floor(Math.Clamp(fraction, 0d, 1d) * 48d);
                        SetProgress(commandId, deployment, percent, "downloading",
                            $"Downloading package — {Math.Round(fraction * 100)}%.",
                            Math.Max(deployment.Attempt, attempt));
                    });

                return;
            }
            catch (HttpRequestException ex) when (
                ex.StatusCode is System.Net.HttpStatusCode.Unauthorized
                    or System.Net.HttpStatusCode.Forbidden
                    or System.Net.HttpStatusCode.NotFound)
            {
                throw new InvalidOperationException(
                    "The package download link is no longer usable. Smart Console stopped immediately instead of retrying the same expired link.", ex);
            }
            catch (Exception ex) when (attempt < maximumAttempts)
            {
                lastError = ex;
                SetProgress(commandId, deployment, 6, "retrying",
                    $"Download attempt {attempt} failed. Retrying automatically ({attempt + 1}/{maximumAttempts}).",
                    Math.Max(deployment.Attempt, attempt));

                await Task.Delay(TimeSpan.FromSeconds(attempt * 2));
            }
            catch (Exception ex)
            {
                lastError = ex;
                break;
            }
        }

        throw new InvalidOperationException(
            $"Package download failed after {maximumAttempts} attempts: {lastError?.Message}");
    }

    private static async Task DownloadDeploymentPackageAsync(
        ApplicationDeploymentPayload deployment,
        string packagePath,
        Action<double> reportProgress)
    {
        if (deployment.StorageProvider.Equals("onedrive", StringComparison.OrdinalIgnoreCase))
        {
            await DownloadOneDrivePackageAsync(deployment, packagePath, reportProgress);
            return;
        }

        if (!Uri.TryCreate(deployment.PackageUrl, UriKind.Absolute, out var packageUri) ||
            packageUri.Scheme != Uri.UriSchemeHttps)
            throw new InvalidOperationException("Application package must use HTTPS.");

        using var response = await DeploymentHttp.GetAsync(
            packageUri,
            HttpCompletionOption.ResponseHeadersRead);
        response.EnsureSuccessStatusCode();

        var total = response.Content.Headers.ContentLength ?? deployment.FileSizeBytes ?? 0;
        await using var source = await response.Content.ReadAsStreamAsync();
        await using var destination = File.Create(packagePath);
        await CopyWithProgressAsync(source, destination, total, reportProgress);
    }

    private static async Task DownloadOneDrivePackageAsync(
        ApplicationDeploymentPayload deployment,
        string packagePath,
        Action<double> reportProgress)
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

            using var resolveResponse = await DeploymentHttp.SendAsync(resolveRequest);
            if (resolveResponse.StatusCode == System.Net.HttpStatusCode.Unauthorized ||
                resolveResponse.StatusCode == System.Net.HttpStatusCode.Forbidden)
                throw new InvalidOperationException(
                    "The signed-in CRECCOM Microsoft 365 account cannot redeem the Data Centre package link.");

            resolveResponse.EnsureSuccessStatusCode();

            using var resolvedJson = JsonDocument.Parse(
                await resolveResponse.Content.ReadAsStringAsync());
            itemId = resolvedJson.RootElement.TryGetProperty("id", out var itemValue)
                ? itemValue.GetString()
                : itemId;
            if (resolvedJson.RootElement.TryGetProperty("parentReference", out var parent) &&
                parent.TryGetProperty("driveId", out var driveValue))
                driveId = driveValue.GetString();
        }

        if (string.IsNullOrWhiteSpace(driveId) || string.IsNullOrWhiteSpace(itemId))
            throw new InvalidOperationException(
                "Data Centre OneDrive package identifiers are missing.");

        var url =
            $"https://graph.microsoft.com/v1.0/drives/{Uri.EscapeDataString(driveId)}/items/{Uri.EscapeDataString(itemId)}/content";

        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        using var response = await DeploymentHttp.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead);

        if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized ||
            response.StatusCode == System.Net.HttpStatusCode.Forbidden)
            throw new InvalidOperationException(
                "The signed-in CRECCOM Microsoft 365 account cannot access this Data Centre application package.");

        response.EnsureSuccessStatusCode();

        var total = response.Content.Headers.ContentLength ?? deployment.FileSizeBytes ?? 0;
        await using var source = await response.Content.ReadAsStreamAsync();
        await using var destination = File.Create(packagePath);
        await CopyWithProgressAsync(source, destination, total, reportProgress);
    }

    private static async Task CopyWithProgressAsync(
        Stream source,
        Stream destination,
        long totalBytes,
        Action<double> reportProgress)
    {
        var buffer = new byte[4 * 1024 * 1024];
        long copied = 0;
        var lastReport = DateTimeOffset.MinValue;

        while (true)
        {
            var read = await source.ReadAsync(buffer);
            if (read <= 0) break;

            await destination.WriteAsync(buffer.AsMemory(0, read));
            copied += read;

            if (DateTimeOffset.UtcNow - lastReport >= TimeSpan.FromSeconds(1))
            {
                reportProgress(totalBytes > 0 ? copied / (double)totalBytes : 0d);
                lastReport = DateTimeOffset.UtcNow;
            }
        }

        reportProgress(1d);
    }

    private static async Task RunDefenderScanAsync(string filePath)
    {
        var scanner = FindDefenderScanner();
        if (scanner is null)
            throw new InvalidOperationException(
                "Microsoft Defender scanner is unavailable. The package was not installed.");

        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = scanner,
                Arguments = $"-Scan -ScanType 3 -File \"{filePath}\"",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            }
        };

        if (!process.Start())
            throw new InvalidOperationException("Microsoft Defender scan could not be started.");

        var outputTask = process.StandardOutput.ReadToEndAsync();
        var errorTask = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(10));

        try
        {
            await process.WaitForExitAsync(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            throw new TimeoutException("Microsoft Defender scan exceeded 10 minutes.");
        }

        var output = await outputTask;
        var error = await errorTask;

        if (process.ExitCode != 0 || !File.Exists(filePath))
        {
            var detail = string.Join(" ", new[] { output, error }
                .Where(value => !string.IsNullOrWhiteSpace(value)))
                .Replace('\r', ' ')
                .Replace('\n', ' ')
                .Trim();

            if (detail.Length > 300) detail = detail[..300] + "…";
            throw new InvalidOperationException(
                string.IsNullOrWhiteSpace(detail)
                    ? "Microsoft Defender did not clear the package for installation."
                    : $"Microsoft Defender did not clear the package: {detail}");
        }
    }

    private static string? FindDefenderScanner()
    {
        try
        {
            var platformRoot = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "Microsoft",
                "Windows Defender",
                "Platform");

            if (Directory.Exists(platformRoot))
            {
                var latest = Directory.EnumerateDirectories(platformRoot)
                    .OrderByDescending(path => path, StringComparer.OrdinalIgnoreCase)
                    .Select(path => Path.Combine(path, "MpCmdRun.exe"))
                    .FirstOrDefault(File.Exists);

                if (!string.IsNullOrWhiteSpace(latest)) return latest;
            }
        }
        catch { }

        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var fallback = Path.Combine(programFiles, "Windows Defender", "MpCmdRun.exe");
        return File.Exists(fallback) ? fallback : null;
    }

    private static void SetProgress(
        Guid commandId,
        ApplicationDeploymentPayload deployment,
        int percent,
        string stage,
        string? message,
        int attempt,
        string? defenderStatus = null)
    {
        Progress[commandId] = new DeploymentProgressReport
        {
            CommandId = commandId,
            DeploymentTaskId = deployment.DeploymentTaskId,
            ProgressPercent = Math.Clamp(percent, 0, 100),
            Stage = stage,
            Message = message,
            Attempt = Math.Max(1, attempt),
            DefenderScanStatus = defenderStatus,
            UpdatedAt = DateTimeOffset.UtcNow
        };
    }

    private static string FormatElapsed(TimeSpan elapsed) =>
        elapsed.TotalMinutes >= 1
            ? $"{(int)elapsed.TotalMinutes}m {elapsed.Seconds}s"
            : $"{Math.Max(1, elapsed.Seconds)}s";

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
                throw new InvalidOperationException(
                    "Microsoft 365 package broker returned no access token.");

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
            throw new InvalidOperationException(
                "ZIP installer path is outside the approved package folder.");
        if (!File.Exists(candidate))
            throw new FileNotFoundException(
                "ZIP installer entry was not found.", candidate);

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

    private static bool IsPackageHashValid(string filePath, string expected)
    {
        try
        {
            using var stream = File.OpenRead(filePath);
            var actual = Convert.ToHexString(SHA256.HashData(stream));
            return string.Equals(actual, expected.Trim(), StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static void VerifySha256(string filePath, string expected)
    {
        using var stream = File.OpenRead(filePath);
        var actual = Convert.ToHexString(SHA256.HashData(stream));
        if (!string.Equals(actual, expected.Trim(), StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException(
                "The application package failed SHA-256 verification and was not installed.");
    }

    private static void TryWriteDeploymentAudit(
        Guid commandId,
        string evidence,
        string message)
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
