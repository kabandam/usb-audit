using System.Diagnostics;
using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using UsbAudit.Shared;

namespace UsbAudit.Agent;

internal static class GitHubUpdateManager
{
    private const string ManagedFeedUrl = "https://pgbipustotixwahmotvu.supabase.co/functions/v1/usb-audit-release-feed";
    private const string AssetName = "UsbAudit-win-x64.zip";
    private static readonly HttpClient Http = CreateClient();
    private static readonly SemaphoreSlim UpdateGate = new(1, 1);

    private sealed class ManagedRelease
    {
        public string Version { get; set; } = string.Empty;
        public string? Tag { get; set; }
        public string PackageUrl { get; set; } = string.Empty;
        public string Sha256 { get; set; } = string.Empty;
        public long Size { get; set; }
        public string? ReleaseUrl { get; set; }
    }

    public static async Task<bool> CheckAndApplyAsync(UsbAuditSettings settings, CancellationToken token, bool forceCheck = false, bool forceInstall = false)
    {
        var entered = false;
        try
        {
            entered = await UpdateGate.WaitAsync(0, token);
            if (!entered) return false;

            await CheckAndApplyCoreAsync(settings, token, forceCheck, forceInstall);
            return true;
        }
        finally
        {
            if (entered) UpdateGate.Release();
        }
    }

    private static async Task CheckAndApplyCoreAsync(UsbAuditSettings settings, CancellationToken token, bool forceCheck, bool forceInstall)
    {
        var current = GetCurrentVersion();
        var status = new UpdateStatus
        {
            LastCheckedAt = DateTimeOffset.Now,
            CurrentVersion = current.ToString(),
            State = "Checking",
            Message = "Checking the CRECCOM managed update feed."
        };
        JsonStorage.SaveUpdateStatus(status);

        try
        {
            if (!settings.AutoUpdatesEnabled && !forceCheck && !forceInstall)
            {
                status.State = "Disabled";
                status.Message = "Automatic updates are disabled in Smart Console settings.";
                JsonStorage.SaveUpdateStatus(status);
                return;
            }

            var release = await GetManagedReleaseAsync(token);
            var latest = ParseVersion(release.Version);
            status.LatestVersion = latest.ToString();
            status.ReleaseUrl = release.ReleaseUrl;

            if (latest.CompareTo(current) <= 0)
            {
                status.State = "Up to date";
                status.Message = $"Smart Console {current} is the latest managed release.";
                JsonStorage.SaveUpdateStatus(status);
                return;
            }

            // A deliberate administrator inventory refresh overrides the scheduled update
            // preferences, but still uses the approved feed, version comparison, HTTPS,
            // size check and SHA-256 verification. Never reinstall the same version.
            var install = forceInstall || settings.AutoInstallUpdates;
            status.State = install ? "Downloading" : "Available";
            status.Message = install
                ? $"Downloading Smart Console {latest} from the CRECCOM managed update service."
                : $"Smart Console {latest} is available. Enable automatic installation to apply it.";
            JsonStorage.SaveUpdateStatus(status);
            if (!install) return;

            if (!Uri.TryCreate(release.PackageUrl, UriKind.Absolute, out var packageUri) ||
                packageUri.Scheme != Uri.UriSchemeHttps ||
                !packageUri.Host.EndsWith(".supabase.co", StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Managed update feed returned an invalid package location.");

            if (string.IsNullOrWhiteSpace(release.Sha256) ||
                release.Sha256.Length != 64 ||
                !release.Sha256.All(Uri.IsHexDigit))
                throw new InvalidDataException("Managed update feed returned an invalid SHA-256 digest.");

            var tag = string.IsNullOrWhiteSpace(release.Tag) ? "v" + latest : release.Tag!;
            var updateRoot = Path.Combine(StoragePaths.UpdatesDirectory, tag.Replace('/', '-'));
            var zipPath = Path.Combine(updateRoot, AssetName);
            var staging = Path.Combine(updateRoot, "staging");
            // Preserve a partially downloaded verified release between retries so an
            // Internet interruption resumes from the last completed byte instead of
            // throwing away the whole package.
            Directory.CreateDirectory(updateRoot);

            if (release.Size <= 0)
                throw new InvalidDataException("Managed update feed returned an invalid package size.");

            await DownloadManagedPackageAsync(packageUri, zipPath, release.Size, token);
            try
            {
                VerifyExpectedHash(zipPath, release.Sha256);
            }
            catch
            {
                // A completed but invalid file must never be reused on the next retry.
                try { File.Delete(zipPath); } catch { }
                throw;
            }

            if (Directory.Exists(staging)) Directory.Delete(staging, true);
            ZipFile.ExtractToDirectory(zipPath, staging, true);

            var updater = Path.Combine(staging, "Apply-UsbAuditUpdate.ps1");
            if (!File.Exists(updater))
                throw new InvalidOperationException("The managed release package does not contain the update installer script.");

            status.State = "Installing";
            status.Message = $"Smart Console {latest} is verified and staged for in-place installation.";
            JsonStorage.SaveUpdateStatus(status);

            var installRoot = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, ".."));
            var args = $"-NoProfile -ExecutionPolicy Bypass -File \"{updater}\" -InstallRoot \"{installRoot}\" -StagingRoot \"{staging}\" -ServiceName \"UsbAuditAgent\"";
            Process.Start(new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = args,
                UseShellExecute = false,
                CreateNoWindow = true
            });
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            status.State = "Update check failed";
            status.Message = ex.Message;
            JsonStorage.SaveUpdateStatus(status);
            JsonStorage.AppendEvent(new AuditEvent
            {
                Kind = AuditEventKind.Warning,
                Timestamp = DateTimeOffset.Now,
                ComputerName = Environment.MachineName,
                Evidence = "Automatic update warning",
                Notes = ex.Message
            });
        }
    }

    private static async Task<ManagedRelease> GetManagedReleaseAsync(CancellationToken token)
    {
        using var response = await Http.GetAsync(ManagedFeedUrl, token);
        response.EnsureSuccessStatusCode();
        await using var stream = await response.Content.ReadAsStreamAsync(token);
        var release = await JsonSerializer.DeserializeAsync<ManagedRelease>(
            stream,
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true },
            token);

        if (release is null ||
            string.IsNullOrWhiteSpace(release.Version) ||
            string.IsNullOrWhiteSpace(release.PackageUrl) ||
            string.IsNullOrWhiteSpace(release.Sha256) ||
            release.Size <= 0)
            throw new InvalidDataException("CRECCOM managed update feed returned incomplete release information.");

        return release;
    }

    private static async Task DownloadManagedPackageAsync(Uri packageUri, string destinationPath, long totalSize, CancellationToken token)
    {
        const int chunkSize = 8 * 1024 * 1024;
        var existing = File.Exists(destinationPath) ? new FileInfo(destinationPath).Length : 0L;
        if (existing < 0 || existing > totalSize)
        {
            try { File.Delete(destinationPath); } catch { }
            existing = 0;
        }

        await using var output = new FileStream(
            destinationPath,
            FileMode.OpenOrCreate,
            FileAccess.Write,
            FileShare.None,
            1024 * 1024,
            useAsync: true);

        output.SetLength(existing);
        output.Position = existing;

        var start = existing;
        while (start < totalSize)
        {
            var end = Math.Min(start + chunkSize - 1, totalSize - 1);
            var expectedBytes = checked((int)(end - start + 1));
            Exception? lastError = null;
            var completed = false;

            for (var attempt = 1; attempt <= 8; attempt++)
            {
                try
                {
                    using var request = new HttpRequestMessage(HttpMethod.Get, packageUri);
                    request.Headers.Range = new System.Net.Http.Headers.RangeHeaderValue(start, end);

                    using var response = await Http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, token);
                    if (response.StatusCode != System.Net.HttpStatusCode.PartialContent)
                        throw new HttpRequestException($"Managed update chunk {start}-{end} returned HTTP {(int)response.StatusCode}.");

                    var contentRange = response.Content.Headers.ContentRange;
                    if (contentRange?.From != start || contentRange?.To != end)
                        throw new InvalidDataException($"Managed update chunk {start}-{end} returned an unexpected range.");

                    // Buffer one bounded chunk before touching the persistent file.
                    // If Wi-Fi disappears mid-response, the partial chunk is discarded
                    // and retried instead of corrupting the resume point.
                    await using var source = await response.Content.ReadAsStreamAsync(token);
                    using var chunk = new MemoryStream(expectedBytes);
                    await source.CopyToAsync(chunk, 1024 * 1024, token);
                    if (chunk.Length != expectedBytes)
                        throw new IOException($"Managed update chunk {start}-{end} was interrupted. Expected {expectedBytes} bytes, received {chunk.Length}.");

                    chunk.Position = 0;
                    await chunk.CopyToAsync(output, 1024 * 1024, token);
                    await output.FlushAsync(token);
                    start = end + 1;
                    lastError = null;
                    completed = true;
                    break;
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    lastError = ex;
                    if (attempt < 8)
                        await Task.Delay(TimeSpan.FromSeconds(Math.Min(30, attempt * 3)), token);
                }
            }

            if (!completed)
                throw lastError ?? new IOException($"Managed update chunk {start}-{end} could not be downloaded.");
        }

        await output.FlushAsync(token);
        if (output.Length != totalSize)
            throw new InvalidDataException($"Managed update download size mismatch. Expected {totalSize}, received {output.Length}.");
    }

    private static HttpClient CreateClient()
    {
        var client = new HttpClient { Timeout = TimeSpan.FromMinutes(15) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("CRECCOM-UsbAudit-Agent/1.3");
        return client;
    }

    private static Version GetCurrentVersion() =>
        Assembly.GetExecutingAssembly().GetName().Version ?? new Version(1, 0, 0);

    private static Version ParseVersion(string value)
    {
        var clean = value.Trim().TrimStart('v', 'V');
        var dash = clean.IndexOf('-');
        if (dash >= 0) clean = clean[..dash];
        if (!Version.TryParse(clean, out var version))
            throw new InvalidOperationException($"Managed release version '{value}' is invalid.");
        return version;
    }

    private static void VerifyExpectedHash(string filePath, string expected)
    {
        using var stream = File.OpenRead(filePath);
        var actual = Convert.ToHexString(SHA256.HashData(stream));
        if (!string.Equals(actual, expected.Trim(), StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("The managed update package failed SHA-256 verification and was not installed.");
    }
}
