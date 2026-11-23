using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using UsbAudit.Shared;

namespace UsbAudit.App;

// Runs independently of the Windows agent, so it can repair a stopped or
// damaged agent using the same pinned, checksum-verified CRECCOM release feed.
internal static class OnlineRepairManager
{
    private const string ProjectHost = "pgbipustotixwahmotvu.supabase.co";
    private const string FeedUrl = "https://" + ProjectHost + "/functions/v1/usb-audit-release-feed";
    private const string ProxyPath = "/functions/v1/usb-audit-release-proxy";
    private const string PackageName = "UsbAudit-win-x64.zip";
    private const int ChunkSize = 8 * 1024 * 1024;
    private const long MaximumPackageBytes = 1024L * 1024 * 1024;

    private sealed class Release
    {
        public string Version { get; set; } = "";
        public string Tag { get; set; } = "";
        public string PackageUrl { get; set; } = "";
        public string Sha256 { get; set; } = "";
        public long Size { get; set; }
    }

    public static async Task StartAsync(IProgress<string> progress, CancellationToken cancellationToken = default)
    {
        StoragePaths.EnsureDirectories();
        var current = Assembly.GetExecutingAssembly().GetName().Version ?? new Version(1, 0, 0);
        var status = new UpdateStatus
        {
            LastCheckedAt = DateTimeOffset.Now,
            CurrentVersion = current.ToString(3),
            State = "Repair checking",
            Message = "Checking the approved CRECCOM repair package."
        };
        var repairRoot = Path.Combine(StoragePaths.UpdatesDirectory, "repair-" + Guid.NewGuid().ToString("N"));
        var handedOff = false;

        void Report(string state, string message)
        {
            status.State = state;
            status.Message = message;
            status.LastCheckedAt = DateTimeOffset.Now;
            JsonStorage.SaveUpdateStatus(status);
            progress.Report(message);
        }

        try
        {
            using var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false })
            {
                Timeout = TimeSpan.FromMinutes(15)
            };
            http.DefaultRequestHeaders.UserAgent.ParseAdd("CRECCOM-SmartConsole-Repair/1.0");

            using var feedResponse = await http.GetAsync(FeedUrl, cancellationToken);
            feedResponse.EnsureSuccessStatusCode();
            await using var feedStream = await feedResponse.Content.ReadAsStreamAsync(cancellationToken);
            var release = await JsonSerializer.DeserializeAsync<Release>(feedStream,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true }, cancellationToken);
            if (release is null ||
                !Version.TryParse(release.Version.TrimStart('v', 'V'), out var latest) ||
                latest.CompareTo(current) < 0 ||
                release.Tag != "v" + latest.ToString(3) ||
                release.Size <= 0 || release.Size > MaximumPackageBytes ||
                release.Sha256.Length != 64 || !release.Sha256.All(Uri.IsHexDigit) ||
                !Uri.TryCreate(release.PackageUrl, UriKind.Absolute, out var proxyUri) ||
                proxyUri.Scheme != Uri.UriSchemeHttps ||
                !string.Equals(proxyUri.Host, ProjectHost, StringComparison.OrdinalIgnoreCase) ||
                proxyUri.AbsolutePath != ProxyPath ||
                !string.Equals(proxyUri.Query, "?tag=" + Uri.EscapeDataString(release.Tag),
                    StringComparison.Ordinal))
                throw new InvalidDataException("The managed repair feed is invalid, incomplete, or older than the installed app.");

            status.LatestVersion = latest.ToString(3);
            Directory.CreateDirectory(repairRoot);
            var zipPath = Path.Combine(repairRoot, PackageName);
            var stagePath = Path.Combine(repairRoot, "staging");

            Report("Repair downloading", "Downloading a fresh verified Smart Console " + latest.ToString(3) + " package.");
            await using (var output = new FileStream(zipPath, FileMode.CreateNew, FileAccess.Write,
                             FileShare.None, 1024 * 1024, useAsync: true))
            {
                long offset = 0;
                while (offset < release.Size)
                {
                    var end = Math.Min(offset + ChunkSize - 1, release.Size - 1);
                    var expectedLength = checked((int)(end - offset + 1));
                    for (var attempt = 1; ; attempt++)
                    {
                        try
                        {
                            using var request = new HttpRequestMessage(HttpMethod.Get, proxyUri);
                            request.Headers.Range = new System.Net.Http.Headers.RangeHeaderValue(offset, end);
                            using var response = await http.SendAsync(request,
                                HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                            if (response.StatusCode != System.Net.HttpStatusCode.PartialContent ||
                                response.Content.Headers.ContentRange?.From != offset ||
                                response.Content.Headers.ContentRange?.To != end ||
                                response.Content.Headers.ContentRange?.Length != release.Size)
                                throw new InvalidDataException("The repair download returned an invalid byte range.");

                            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
                            using var chunk = new MemoryStream(expectedLength);
                            await stream.CopyToAsync(chunk, cancellationToken);
                            if (chunk.Length != expectedLength)
                                throw new EndOfStreamException("The repair download was interrupted.");

                            chunk.Position = 0;
                            await chunk.CopyToAsync(output, cancellationToken);
                            offset = end + 1;
                            break;
                        }
                        catch (Exception ex) when (attempt < 4 && ex is not OperationCanceledException)
                        {
                            await Task.Delay(TimeSpan.FromSeconds(attempt * 2), cancellationToken);
                        }
                    }
                    Report("Repair downloading", "Downloaded " +
                        Math.Round(100d * offset / release.Size) + "% of the verified repair package.");
                }
                await output.FlushAsync(cancellationToken);
            }

            Report("Repair verifying", "Verifying the complete download before replacing any files.");
            await using (var file = File.OpenRead(zipPath))
            {
                var digest = Convert.ToHexString(await SHA256.HashDataAsync(file, cancellationToken));
                if (!string.Equals(digest, release.Sha256, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("SHA-256 verification failed; nothing was installed.");
            }

            ZipFile.ExtractToDirectory(zipPath, stagePath);
            var installer = Path.Combine(stagePath, "Apply-UsbAuditUpdate.ps1");
            foreach (var required in new[]
            {
                installer,
                Path.Combine(stagePath, "Agent", "UsbAudit.Agent.exe"),
                Path.Combine(stagePath, "App", "SmartConsole.exe"),
                Path.Combine(stagePath, "Identity", "UsbAudit.Identity.exe")
            })
            {
                if (!File.Exists(required))
                    throw new InvalidDataException("The verified package is missing a required repair file.");
            }

            // The updater has an exclusive machine-wide mutex, same-volume
            // backup/rollback, SHA-256 copy checks, and service restart logic.
            // ProgramData enrollment/settings are outside its replacement roots.
            var installRoot = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, ".."));
            Report("Repair installing", "Verified. Reinstalling program files and restarting the agent; Smart Console may close.");
            var start = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                WorkingDirectory = stagePath,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            foreach (var arg in new[]
            {
                "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "RemoteSigned",
                "-File", installer, "-InstallRoot", installRoot,
                "-StagingRoot", stagePath, "-ServiceName", "UsbAuditAgent"
            }) start.ArgumentList.Add(arg);

            using var process = Process.Start(start)
                ?? throw new InvalidOperationException("Windows could not start the verified repair installer.");
            handedOff = true;
        }
        catch (Exception ex)
        {
            Report("Repair failed", ex.Message);
            throw;
        }
        finally
        {
            // Do not delete the staged installer after launching it: it must
            // remain available while the desktop process is being replaced.
            if (!handedOff)
            {
                try { if (Directory.Exists(repairRoot)) Directory.Delete(repairRoot, true); }
                catch { /* Leave temporary files for normal disk cleanup. */ }
            }
        }
    }
}
