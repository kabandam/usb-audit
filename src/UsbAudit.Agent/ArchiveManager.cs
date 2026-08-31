using UsbAudit.Shared;

namespace UsbAudit.Agent;

internal static class ArchiveManager
{
    public static async Task<string?> TryArchiveAsync(
        string sourcePath,
        ConnectedUsbDevice device,
        UsbAuditSettings settings,
        CancellationToken cancellationToken)
    {
        if (!settings.RetainTransferredFiles) return null;

        var info = new FileInfo(sourcePath);
        if (!info.Exists) return null;
        var maxBytes = Math.Max(1, settings.MaximumArchiveFileSizeMb) * 1024L * 1024L;
        if (info.Length > maxBytes) return null;

        StoragePaths.EnsureDirectories();
        EnforceRetention(settings);
        if (GetDirectorySize(StoragePaths.ArchiveDirectory) >= Math.Max(1, settings.ArchiveQuotaGb) * 1024L * 1024L * 1024L)
        {
            return null;
        }

        var serialFolder = Sanitize(device.DeviceSerial ?? device.DriveLetter.Replace(":", ""));
        var dayFolder = DateTime.Now.ToString("yyyy-MM-dd");
        var targetFolder = Path.Combine(StoragePaths.ArchiveDirectory, serialFolder, dayFolder);
        Directory.CreateDirectory(targetFolder);

        var targetName = $"{DateTime.Now:HHmmssfff}_{Guid.NewGuid():N}_{Path.GetFileName(sourcePath)}";
        var targetPath = Path.Combine(targetFolder, targetName);

        await using var input = new FileStream(sourcePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1024 * 128, true);
        await using var output = new FileStream(targetPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1024 * 128, true);
        await input.CopyToAsync(output, cancellationToken);
        return targetPath;
    }

    public static void EnforceRetention(UsbAuditSettings settings)
    {
        try
        {
            if (!Directory.Exists(StoragePaths.ArchiveDirectory)) return;
            var cutoff = DateTime.UtcNow.AddDays(-Math.Max(1, settings.RetentionDays));
            foreach (var file in Directory.EnumerateFiles(StoragePaths.ArchiveDirectory, "*", SearchOption.AllDirectories))
            {
                try
                {
                    var info = new FileInfo(file);
                    if (info.CreationTimeUtc < cutoff) info.Delete();
                }
                catch { }
            }
        }
        catch { }
    }

    private static long GetDirectorySize(string directory)
    {
        try
        {
            return Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories)
                .Select(path => { try { return new FileInfo(path).Length; } catch { return 0L; } })
                .Sum();
        }
        catch { return 0; }
    }

    private static string Sanitize(string value)
    {
        foreach (var invalid in Path.GetInvalidFileNameChars()) value = value.Replace(invalid, '_');
        return string.IsNullOrWhiteSpace(value) ? "unknown-device" : value;
    }
}
