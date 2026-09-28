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

    private sealed class ManagedRelease
    {
        public string Version { get; set; } = string.Empty;
        public string? Tag { get; set; }
        public string PackageUrl { get; set; } = string.Empty;
        public string Sha256 { get; set; } = string.Empty;
        public long Size { get; set; }
        public string? ReleaseUrl { get; set; }
    }

    public static async Task CheckAndApplyAsync(UsbAuditSettings settings, CancellationToken token, bool forceCheck = false)
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
            if (!settings.AutoUpdatesEnabled && !forceCheck)
            {
                status.State = "Disabled";
                status.Message = "Automatic updates are disabled in USB Audit settings.";
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
                status.Message = $"USB Audit {current} is the latest managed release.";
                JsonStorage.SaveUpdateStatus(status);
                return;
            }

            status.State = settings.AutoInstallUpdates ? "Downloading" : "Available";
            status.Message = settings.AutoInstallUpdates
                ? $"Downloading USB Audit {latest} from the CRECCOM managed update service."
                : $"USB Audit {latest} is available. Enable automatic installation to apply it.";
            JsonStorage.SaveUpdateStatus(status);
            if (!settings.AutoInstallUpdates) return;

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
            if (Directory.Exists(updateRoot)) Directory.Delete(updateRoot, true);
            Directory.CreateDirectory(updateRoot);

            if (release.Size <= 0)
                throw new InvalidDataException("Managed update feed returned an invalid package size.");

            await DownloadManagedPackageAsync(packageUri, zipPath, release.Size, token);
            VerifyExpectedHash(zipPath, release.Sha256);
            ZipFile.ExtractToDirectory(zipPath, staging, true);

            var updater = Path.Combine(staging, "Apply-UsbAuditUpdate.ps1");
            if (!File.Exists(updater))
                throw new InvalidOperationException("The managed release package does not contain the update installer script.");

            status.State = "Installing";
            status.Message = $"USB Audit {latest} is verified and staged for in-place installation.";
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
        await using var output = new FileStream(destinationPath, FileMode.Create, FileAccess.Write, FileShare.None, 1024 * 1024, useAsync: true);

        for (long start = 0; start < totalSize; start += chunkSize)
        {
            var end = Math.Min(start + chunkSize - 1, totalSize - 1);
            Exception? lastError = null;

            for (var attempt = 1; attempt <= 4; attempt++)
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

                    await using var source = await response.Content.ReadAsStreamAsync(token);
                    await source.CopyToAsync(output, 1024 * 1024, token);
                    lastError = null;
                    break;
                }
                catch (Exception ex) when (attempt < 4 && ex is not OperationCanceledException)
                {
                    lastError = ex;
                    await Task.Delay(TimeSpan.FromSeconds(attempt * 2), token);
                }
            }

            if (lastError is not null) throw lastError;
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
