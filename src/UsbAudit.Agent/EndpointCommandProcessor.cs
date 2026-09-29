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
    private const uint CreateUnicodeEnvironment = 0x00000400;
    private const uint CreateNewConsole = 0x00000010;
    private const string GraphTokenPipeName = "CRECCOM.SmartConsole.GraphToken";

    private static readonly ConcurrentDictionary<Guid, EndpointCommandResult> Results = new();
    private static readonly ConcurrentDictionary<Guid, DeploymentProgressReport> Progress = new();
    private static readonly ConcurrentDictionary<Guid, byte> Running = new();
    private static readonly SemaphoreSlim DeploymentGate = new(1, 1);
    private static readonly HttpClient DeploymentHttp = new()
    {
        Timeout = TimeSpan.FromMinutes(20)
    };

    private sealed record DeploymentExecutionResult(bool Completed, string Message);

    public static bool HasActiveDeployment => Running.Count > 0;

    public static List<EndpointCommandResult> GetPendingResults() => Results.Values.ToList();

    public static List<DeploymentProgressReport> GetDeploymentProgress()
    {
        var snapshot = Progress.Values.ToDictionary(item => item.CommandId);

        foreach (var pending in JsonStorage.ReadPendingDeployments())
        {
            if (snapshot.ContainsKey(pending.CommandId)) continue;

            var (percent, stage, message) = pending.State switch
            {
                "install_requested" => (81, "install_requested", "Installation requested from the Smart Console client."),
                "installing" => (82, "installing", pending.Message ?? $"Installing {pending.AppName}."),
                "failed" => (80, "failed", pending.Message ?? "Installation failed. Retry is available on the endpoint."),
                _ => (80, "ready_to_install", pending.Message ?? $"{pending.AppName} is downloaded, verified and ready to install.")
            };

            snapshot[pending.CommandId] = new DeploymentProgressReport
            {
                CommandId = pending.CommandId,
                DeploymentTaskId = pending.DeploymentTaskId,
                ProgressPercent = percent,
                Stage = stage,
                Message = message,
                Attempt = Math.Max(1, pending.Attempt),
                DefenderScanStatus = "clean",
                UpdatedAt = pending.InstallRequestedAt ?? pending.StagedAt
            };
        }

        return snapshot.Values.OrderBy(item => item.UpdatedAt).ToList();
    }

    public static void AcknowledgeResults(IEnumerable<Guid> commandIds)
    {
        foreach (var id in commandIds)
        {
            Results.TryRemove(id, out _);
            Progress.TryRemove(id, out _);
        }
    }

    public static void QueuePendingInstall(Guid commandId)
    {
        var pending = JsonStorage.LoadPendingDeployment(commandId);
        if (pending is null) return;
        if (!Running.TryAdd(commandId, 0)) return;

        _ = Task.Run(() => RunPendingDeploymentAsync(commandId));
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

            var outcome = await DeployApplicationAsync(commandId, deployment);

            if (outcome.Completed)
            {
                SetProgress(commandId, deployment, 100, "completed",
                    outcome.Message, deployment.Attempt, "clean");

                Results[commandId] = new EndpointCommandResult
                {
                    CommandId = commandId,
                    Status = "completed",
                    Message = outcome.Message
                };
            }
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

    private static async Task<DeploymentExecutionResult> DeployApplicationAsync(
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

        var visibleInstall = deployment.InstallMode.Equals("visible", StringComparison.OrdinalIgnoreCase);
        var manualInstall = deployment.InstallTrigger.Equals("manual", StringComparison.OrdinalIgnoreCase);

        if (!visibleInstall &&
            deployment.InstallerType.Equals("exe", StringComparison.OrdinalIgnoreCase) &&
            string.IsNullOrWhiteSpace(deployment.InstallArgs))
            throw new InvalidOperationException(
                $"{deployment.AppName} is configured for silent deployment but has no silent install arguments.");

        if (string.IsNullOrWhiteSpace(deployment.Sha256) ||
            deployment.Sha256.Length != 64 ||
            !deployment.Sha256.All(Uri.IsHexDigit))
            throw new InvalidOperationException("Application package SHA-256 is invalid.");

        var root = Path.Combine(StoragePaths.DataDirectory, "Deployments", commandId.ToString("N"));
        Directory.CreateDirectory(root);

        var packageExtension = packageType.Equals("zip", StringComparison.OrdinalIgnoreCase)
            ? ".zip"
            : packageType.Equals("msi", StringComparison.OrdinalIgnoreCase) ? ".msi" : ".exe";

        Directory.CreateDirectory(StoragePaths.PackageCacheDirectory);
        var cacheKey = deployment.Sha256.Trim().ToLowerInvariant();
        var cachedPackagePath = Path.Combine(StoragePaths.PackageCacheDirectory, cacheKey + packageExtension);
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

            var defenderMarker = cachedPackagePath + ".defender-ok";
            if (File.Exists(defenderMarker) &&
                string.Equals((await File.ReadAllTextAsync(defenderMarker)).Trim(), cacheKey, StringComparison.OrdinalIgnoreCase))
            {
                SetProgress(commandId, deployment, 74, "defender_cached",
                    "Previously verified package reused from this endpoint cache.",
                    deployment.Attempt, "clean");
            }
            else
            {
                SetProgress(commandId, deployment, 69, "defender_scan",
                    "Scanning package with Microsoft Defender.", deployment.Attempt, "scanning");
                await RunDefenderScanAsync(packagePath);
                await File.WriteAllTextAsync(defenderMarker, cacheKey);
                SetProgress(commandId, deployment, 74, "defender_clean",
                    "Microsoft Defender scan completed with no threat reported.",
                    deployment.Attempt, "clean");
            }

            if (manualInstall)
            {
                var pending = new PendingApplicationDeployment
                {
                    CommandId = commandId,
                    DeploymentTaskId = deployment.DeploymentTaskId,
                    DeploymentBatchId = deployment.DeploymentBatchId,
                    AppId = deployment.AppId,
                    AppName = deployment.AppName,
                    AppVersion = deployment.AppVersion,
                    Publisher = deployment.Publisher,
                    InstallerType = deployment.InstallerType,
                    PackageType = packageType,
                    Sha256 = deployment.Sha256,
                    CachedPackagePath = packagePath,
                    InstallerEntry = deployment.InstallerEntry,
                    InstallArgs = deployment.InstallArgs,
                    InstallMode = deployment.InstallMode,
                    InstallTimeoutMinutes = deployment.InstallTimeoutMinutes,
                    SuccessCodes = deployment.SuccessCodes.Count > 0 ? deployment.SuccessCodes : [0, 1641, 3010],
                    Attempt = deployment.Attempt,
                    State = "ready",
                    Message = $"{deployment.AppName} {deployment.AppVersion} is downloaded, verified and ready to install.",
                    FileSizeBytes = deployment.FileSizeBytes,
                    StagedAt = DateTimeOffset.UtcNow
                };
                JsonStorage.SavePendingDeployment(pending);

                SetProgress(commandId, deployment, 80, "ready_to_install",
                    pending.Message, deployment.Attempt, "clean");
                TryWriteDeploymentAudit(commandId, "Application package staged", pending.Message);

                return new DeploymentExecutionResult(false, pending.Message);
            }

            var message = await InstallPreparedPackageAsync(
                commandId, deployment, packagePath, packageType, root);
            return new DeploymentExecutionResult(true, message);
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { }
        }
    }

    private static async Task RunPendingDeploymentAsync(Guid commandId)
    {
        await DeploymentGate.WaitAsync();
        PendingApplicationDeployment? pending = null;

        try
        {
            pending = JsonStorage.LoadPendingDeployment(commandId)
                ?? throw new InvalidOperationException("The staged application package is no longer available.");

            if (!File.Exists(pending.CachedPackagePath))
                throw new FileNotFoundException("The staged package is missing from the endpoint cache.", pending.CachedPackagePath);

            VerifySha256(pending.CachedPackagePath, pending.Sha256);

            pending.State = "installing";
            pending.Message = $"Installing {pending.AppName} from the local Smart Console cache.";
            pending.InstallRequestedAt ??= DateTimeOffset.UtcNow;
            JsonStorage.SavePendingDeployment(pending);

            var deployment = ToDeploymentPayload(pending);
            SetProgress(commandId, deployment, 82, "installing",
                pending.Message, pending.Attempt, "clean");

            var root = Path.Combine(StoragePaths.DataDirectory, "Deployments", commandId.ToString("N") + "-manual");
            Directory.CreateDirectory(root);
            try
            {
                var message = await InstallPreparedPackageAsync(
                    commandId, deployment, pending.CachedPackagePath, pending.PackageType, root);

                SetProgress(commandId, deployment, 100, "completed",
                    message, pending.Attempt, "clean");

                Results[commandId] = new EndpointCommandResult
                {
                    CommandId = commandId,
                    Status = "completed",
                    Message = message
                };

                JsonStorage.DeletePendingDeployment(commandId);
            }
            finally
            {
                try { Directory.Delete(root, recursive: true); } catch { }
            }
        }
        catch (Exception ex)
        {
            if (pending is not null)
            {
                pending.State = "failed";
                pending.Message = ex.Message;
                JsonStorage.SavePendingDeployment(pending);

                var deployment = ToDeploymentPayload(pending);
                SetProgress(commandId, deployment, 80, "failed",
                    ex.Message, pending.Attempt, "clean");
            }

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
            JsonStorage.AcknowledgePendingDeploymentInstallRequest(commandId);
            Running.TryRemove(commandId, out _);
            DeploymentGate.Release();
        }
    }

    private static ApplicationDeploymentPayload ToDeploymentPayload(PendingApplicationDeployment pending) =>
        new()
        {
            DeploymentTaskId = pending.DeploymentTaskId,
            DeploymentBatchId = pending.DeploymentBatchId,
            AppId = pending.AppId,
            AppName = pending.AppName,
            AppVersion = pending.AppVersion,
            Publisher = pending.Publisher,
            InstallerType = pending.InstallerType,
            PackageType = pending.PackageType,
            FileSizeBytes = pending.FileSizeBytes,
            InstallerEntry = pending.InstallerEntry,
            Sha256 = pending.Sha256,
            InstallArgs = pending.InstallArgs,
            InstallMode = pending.InstallMode,
            InstallTrigger = "manual",
            InstallTimeoutMinutes = pending.InstallTimeoutMinutes,
            SuccessCodes = pending.SuccessCodes,
            Attempt = pending.Attempt
        };

    private static async Task<string> InstallPreparedPackageAsync(
        Guid commandId,
        ApplicationDeploymentPayload deployment,
        string packagePath,
        string packageType,
        string workspaceRoot)
    {
        VerifySha256(packagePath, deployment.Sha256);

        var installerPath = packagePath;
        if (packageType.Equals("zip", StringComparison.OrdinalIgnoreCase))
        {
            SetProgress(commandId, deployment, 76, "extracting",
                "Extracting approved ZIP package.", deployment.Attempt, "clean");

            var extractRoot = Path.Combine(workspaceRoot, "expanded");
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

        var visibleInstall = deployment.InstallMode.Equals("visible", StringComparison.OrdinalIgnoreCase);
        using var process = visibleInstall
            ? StartVisibleInstallerForActiveUser(installerPath, deployment)
            : new Process { StartInfo = BuildInstallerStartInfo(installerPath, deployment) };

        SetProgress(commandId, deployment, 82,
            visibleInstall ? "visible_install" : "installing",
            visibleInstall
                ? $"Installer opened for the signed-in user. Waiting for user completion."
                : $"Installing {deployment.AppName} silently.",
            deployment.Attempt, "clean");

        if (!visibleInstall && !process.Start())
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
                    visibleInstall
                        ? $"Visible installation of {deployment.AppName} exceeded its {installTimeout.TotalMinutes:0}-minute timeout and was stopped."
                        : $"Silent installation of {deployment.AppName} exceeded its {installTimeout.TotalMinutes:0}-minute timeout and was stopped.");
            }

            var percent = 82 + (int)Math.Min(15,
                Math.Floor(elapsed.TotalMinutes / Math.Max(1d, installTimeout.TotalMinutes) * 15d));

            SetProgress(commandId, deployment, percent,
                visibleInstall ? "visible_install" : "installing",
                visibleInstall
                    ? $"Installer is open for the user ({FormatElapsed(elapsed)})."
                    : $"Silent installer is running ({FormatElapsed(elapsed)}).",
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
        var installKind = visibleInstall ? "visible installation" : "silent installation";
        var message = restartRequired
            ? $"{deployment.AppName} {deployment.AppVersion} {installKind} completed successfully. Windows reports that a restart is required."
            : $"{deployment.AppName} {deployment.AppVersion} {installKind} completed successfully.";

        TryWriteDeploymentAudit(commandId, "Application deployed", message);
        return message;
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

    private static Process StartVisibleInstallerForActiveUser(
        string installerPath,
        ApplicationDeploymentPayload deployment)
    {
        var sessionId = WTSGetActiveConsoleSessionId();
        if (sessionId == NoActiveSession)
            throw new InvalidOperationException(
                "The package is downloaded and ready, but Visible install requires a signed-in Windows user. Retry when a user is signed in.");

        if (!WTSQueryUserToken(sessionId, out var userToken))
            throw new System.ComponentModel.Win32Exception(
                Marshal.GetLastWin32Error(),
                "Smart Console could not open the installer in the signed-in user's session.");

        IntPtr environment = IntPtr.Zero;
        try
        {
            if (!CreateEnvironmentBlock(out environment, userToken, false))
                environment = IntPtr.Zero;

            var powershell = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                "System32", "WindowsPowerShell", "v1.0", "powershell.exe");

            var executable = deployment.InstallerType.Equals("msi", StringComparison.OrdinalIgnoreCase)
                ? "msiexec.exe"
                : installerPath;

            var arguments = deployment.InstallerType.Equals("msi", StringComparison.OrdinalIgnoreCase)
                ? $"/i \"{installerPath}\" {deployment.InstallArgs}".Trim()
                : deployment.InstallArgs ?? string.Empty;

            static string PsQuote(string value) => "'" + value.Replace("'", "''") + "'";

            var script =
                $"$p=Start-Process -FilePath {PsQuote(executable)} " +
                $"-ArgumentList {PsQuote(arguments)} -Verb RunAs -PassThru -Wait; " +
                "if($p){exit $p.ExitCode}else{exit 1}";

            var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
            var commandLine = new StringBuilder(
                $"\"{powershell}\" -NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded}");

            var startup = new StartupInfo
            {
                cb = Marshal.SizeOf<StartupInfo>(),
                lpDesktop = "winsta0\\default"
            };

            if (!CreateProcessAsUser(
                    userToken,
                    powershell,
                    commandLine,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    CreateUnicodeEnvironment | CreateNewConsole,
                    environment,
                    Path.GetDirectoryName(installerPath),
                    ref startup,
                    out var processInfo))
            {
                throw new System.ComponentModel.Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Smart Console could not start the visible installer for the signed-in user.");
            }

            try
            {
                return System.Diagnostics.Process.GetProcessById(unchecked((int)processInfo.dwProcessId));
            }
            finally
            {
                if (processInfo.hThread != IntPtr.Zero) CloseHandle(processInfo.hThread);
                if (processInfo.hProcess != IntPtr.Zero) CloseHandle(processInfo.hProcess);
            }
        }
        finally
        {
            if (environment != IntPtr.Zero) DestroyEnvironmentBlock(environment);
            if (userToken != IntPtr.Zero) CloseHandle(userToken);
        }
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

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo
    {
        public int cb;
        public string? lpReserved;
        public string? lpDesktop;
        public string? lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSQueryUserToken(uint sessionId, out IntPtr token);

    [DllImport("userenv.dll", SetLastError = true)]
    private static extern bool CreateEnvironmentBlock(
        out IntPtr environment,
        IntPtr token,
        bool inherit);

    [DllImport("userenv.dll", SetLastError = true)]
    private static extern bool DestroyEnvironmentBlock(IntPtr environment);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessAsUser(
        IntPtr token,
        string? applicationName,
        StringBuilder commandLine,
        IntPtr processAttributes,
        IntPtr threadAttributes,
        bool inheritHandles,
        uint creationFlags,
        IntPtr environment,
        string? currentDirectory,
        ref StartupInfo startupInfo,
        out ProcessInformation processInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

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
