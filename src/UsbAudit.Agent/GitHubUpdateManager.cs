using System.Diagnostics;
using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using UsbAudit.Shared;

namespace UsbAudit.Agent;

internal static class GitHubUpdateManager
{
    private const string AssetName = "UsbAudit-win-x64.zip";
    private const string ChecksumAssetName = AssetName + ".sha256";
    private static readonly HttpClient Http = CreateClient();

    public static async Task CheckAndApplyAsync(UsbAuditSettings settings, CancellationToken token, bool forceCheck = false)
    {
        var current = GetCurrentVersion();
        var status = new UpdateStatus
        {
            LastCheckedAt = DateTimeOffset.Now,
            CurrentVersion = current.ToString(),
            State = "Checking",
            Message = "Checking GitHub Releases for a newer stable version."
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

            if (!TryParseRepository(settings.UpdateRepository, out var owner, out var repo))
                throw new InvalidOperationException("Update repository must use owner/repository format.");

            using var response = await Http.GetAsync($"https://api.github.com/repos/{owner}/{repo}/releases/latest", token);
            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
                throw new InvalidOperationException("Update repository or a published release was not found. Publish at least one GitHub Release.");
            response.EnsureSuccessStatusCode();

            await using var stream = await response.Content.ReadAsStreamAsync(token);
            using var json = await JsonDocument.ParseAsync(stream, cancellationToken: token);
            var root = json.RootElement;
            var tag = root.GetProperty("tag_name").GetString() ?? string.Empty;
            var latest = ParseVersion(tag);
            status.LatestVersion = latest.ToString();
            status.ReleaseUrl = root.TryGetProperty("html_url", out var html) ? html.GetString() : null;

            if (latest.CompareTo(current) <= 0)
            {
                status.State = "Up to date";
                status.Message = $"USB Audit {current} is the latest stable release.";
                JsonStorage.SaveUpdateStatus(status);
                return;
            }

            JsonElement? asset = null;
            JsonElement? checksumAsset = null;
            foreach (var item in root.GetProperty("assets").EnumerateArray())
            {
                var name = item.GetProperty("name").GetString();
                if (string.Equals(name, AssetName, StringComparison.OrdinalIgnoreCase))
                    asset = item;
                else if (string.Equals(name, ChecksumAssetName, StringComparison.OrdinalIgnoreCase))
                    checksumAsset = item;
            }
            if (asset is null) throw new InvalidOperationException($"Release {tag} does not contain {AssetName}.");

            status.State = settings.AutoInstallUpdates ? "Downloading" : "Available";
            status.Message = settings.AutoInstallUpdates
                ? $"Downloading USB Audit {latest}."
                : $"USB Audit {latest} is available. Enable automatic installation to apply it.";
            JsonStorage.SaveUpdateStatus(status);
            if (!settings.AutoInstallUpdates) return;

            var downloadUrl = asset.Value.GetProperty("browser_download_url").GetString()
                ?? throw new InvalidOperationException("Release asset has no download URL.");
            var expectedDigest = asset.Value.TryGetProperty("digest", out var digestElement) ? digestElement.GetString() : null;

            var updateRoot = Path.Combine(StoragePaths.UpdatesDirectory, tag.Replace('/', '-'));
            var zipPath = Path.Combine(updateRoot, AssetName);
            var staging = Path.Combine(updateRoot, "staging");
            if (Directory.Exists(updateRoot)) Directory.Delete(updateRoot, true);
            Directory.CreateDirectory(updateRoot);

            using (var download = await Http.GetAsync(downloadUrl, HttpCompletionOption.ResponseHeadersRead, token))
            {
                download.EnsureSuccessStatusCode();
                await using var source = await download.Content.ReadAsStreamAsync(token);
                await using var destination = File.Create(zipPath);
                await source.CopyToAsync(destination, token);
            }

            var verified = VerifyDigestIfPresent(zipPath, expectedDigest);
            if (!verified)
            {
                if (checksumAsset is null)
                    throw new InvalidDataException($"Release {tag} has no SHA-256 digest or {ChecksumAssetName}; the update was not installed.");

                var checksumUrl = checksumAsset.Value.GetProperty("browser_download_url").GetString()
                    ?? throw new InvalidOperationException("Checksum asset has no download URL.");
                var checksumText = await Http.GetStringAsync(checksumUrl, token);
                VerifyChecksumText(zipPath, checksumText);
            }

            ZipFile.ExtractToDirectory(zipPath, staging, true);

            var updater = Path.Combine(staging, "Apply-UsbAuditUpdate.ps1");
            if (!File.Exists(updater)) throw new InvalidOperationException("The release package does not contain the update installer script.");

            status.State = "Installing";
            status.Message = $"USB Audit {latest} is staged and will now replace the installed version.";
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

            // The external updater stops this service after it has started and stages a rollback copy.
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

    private static HttpClient CreateClient()
    {
        var client = new HttpClient { Timeout = TimeSpan.FromMinutes(10) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("UsbAudit-Agent/1.2");
        client.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
        client.DefaultRequestHeaders.Add("X-GitHub-Api-Version", "2026-03-10");
        return client;
    }

    private static Version GetCurrentVersion() =>
        Assembly.GetExecutingAssembly().GetName().Version ?? new Version(1, 0, 0);

    private static Version ParseVersion(string tag)
    {
        var clean = tag.Trim().TrimStart('v', 'V');
        var dash = clean.IndexOf('-');
        if (dash >= 0) clean = clean[..dash];
        if (!Version.TryParse(clean, out var version))
            throw new InvalidOperationException($"Release tag '{tag}' is not a valid version. Use tags such as v1.1.0.");
        return version;
    }

    private static bool TryParseRepository(string value, out string owner, out string repo)
    {
        owner = string.Empty;
        repo = string.Empty;
        var parts = (value ?? string.Empty).Trim().Trim('/').Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 2) return false;
        owner = parts[0];
        repo = parts[1];
        return owner.All(IsSafe) && repo.All(IsSafe);
    }

    private static bool IsSafe(char c) => char.IsLetterOrDigit(c) || c is '-' or '_' or '.';

    private static bool VerifyDigestIfPresent(string filePath, string? digest)
    {
        if (string.IsNullOrWhiteSpace(digest)) return false;
        const string prefix = "sha256:";
        if (!digest.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return false;
        var expected = digest[prefix.Length..].Trim();
        VerifyExpectedHash(filePath, expected);
        return true;
    }

    private static void VerifyChecksumText(string filePath, string checksumText)
    {
        var expected = checksumText
            .Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)
            .FirstOrDefault(part => part.Length == 64 && part.All(Uri.IsHexDigit));
        if (expected is null)
            throw new InvalidDataException("The published SHA-256 checksum is invalid.");
        VerifyExpectedHash(filePath, expected);
    }

    private static void VerifyExpectedHash(string filePath, string expected)
    {
        using var stream = File.OpenRead(filePath);
        var actual = Convert.ToHexString(SHA256.HashData(stream));
        if (!string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("The downloaded update failed SHA-256 verification and was not installed.");
    }
}
