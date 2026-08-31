using System.Diagnostics;
using System.Management;
using Microsoft.Win32;
using UsbAudit.Shared;

namespace UsbAudit.Agent;

internal static class EndpointInventory
{
    public static EndpointSnapshot Capture()
    {
        return new EndpointSnapshot
        {
            OsName = ReadWmi("Win32_OperatingSystem", "Caption"),
            OsVersion = Environment.OSVersion.VersionString,
            Manufacturer = ReadWmi("Win32_ComputerSystem", "Manufacturer"),
            Model = ReadWmi("Win32_ComputerSystem", "Model"),
            SerialNumber = ReadWmi("Win32_BIOS", "SerialNumber"),
            TotalMemoryBytes = ReadWmiLong("Win32_ComputerSystem", "TotalPhysicalMemory"),
            ProcessorName = ReadWmi("Win32_Processor", "Name"),
            DefenderStatus = ReadDefenderStatus(),
            FirewallEnabled = ReadFirewallEnabled(),
            InstalledSoftware = ReadInstalledSoftware()
                .OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
                .Take(1000)
                .ToList(),
            CapturedAt = DateTimeOffset.UtcNow
        };
    }

    private static string? ReadWmi(string className, string property)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher($"SELECT {property} FROM {className}");
            foreach (ManagementObject result in searcher.Get())
                return result[property]?.ToString()?.Trim();
        }
        catch { }
        return null;
    }

    private static long? ReadWmiLong(string className, string property)
    {
        var value = ReadWmi(className, property);
        return long.TryParse(value, out var parsed) ? parsed : null;
    }

    private static string ReadDefenderStatus()
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = "-NoProfile -NonInteractive -Command \"$s=Get-MpComputerStatus -ErrorAction Stop; if($s.AntivirusEnabled -and $s.RealTimeProtectionEnabled){'Protected'}elseif($s.AntivirusEnabled){'Attention'}else{'Disabled'}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            });
            if (process is null) return "Unknown";
            if (!process.WaitForExit(5000))
            {
                try { process.Kill(true); } catch { }
                return "Unknown";
            }
            var value = process.StandardOutput.ReadToEnd().Trim();
            return string.IsNullOrWhiteSpace(value) ? "Unknown" : value;
        }
        catch { return "Unknown"; }
    }

    private static bool? ReadFirewallEnabled()
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = "-NoProfile -NonInteractive -Command \"if((Get-NetFirewallProfile -ErrorAction Stop | Where-Object Enabled).Count -gt 0){'true'}else{'false'}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            });
            if (process is null) return null;
            if (!process.WaitForExit(5000))
            {
                try { process.Kill(true); } catch { }
                return null;
            }
            return bool.TryParse(process.StandardOutput.ReadToEnd().Trim(), out var enabled) ? enabled : null;
        }
        catch { return null; }
    }

    private static IEnumerable<InstalledSoftwareItem> ReadInstalledSoftware()
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var locations = new[]
        {
            (RegistryHive.LocalMachine, RegistryView.Registry64),
            (RegistryHive.LocalMachine, RegistryView.Registry32),
            (RegistryHive.CurrentUser, RegistryView.Registry64),
            (RegistryHive.CurrentUser, RegistryView.Registry32)
        };

        foreach (var (hive, view) in locations)
        {
            RegistryKey? root = null;
            RegistryKey? uninstall = null;
            try
            {
                root = RegistryKey.OpenBaseKey(hive, view);
                uninstall = root.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
                if (uninstall is null) continue;

                foreach (var subName in uninstall.GetSubKeyNames())
                {
                    using var sub = uninstall.OpenSubKey(subName);
                    var name = sub?.GetValue("DisplayName")?.ToString()?.Trim();
                    if (string.IsNullOrWhiteSpace(name)) continue;
                    var version = sub?.GetValue("DisplayVersion")?.ToString()?.Trim();
                    var publisher = sub?.GetValue("Publisher")?.ToString()?.Trim();
                    var key = $"{name}|{version}|{publisher}";
                    if (!seen.Add(key)) continue;

                    yield return new InstalledSoftwareItem
                    {
                        Name = name,
                        Version = version,
                        Publisher = publisher,
                        InstallLocation = sub?.GetValue("InstallLocation")?.ToString()?.Trim(),
                        UninstallCommand = sub?.GetValue("QuietUninstallString")?.ToString()?.Trim()
                                           ?? sub?.GetValue("UninstallString")?.ToString()?.Trim()
                    };
                }
            }
            finally
            {
                uninstall?.Dispose();
                root?.Dispose();
            }
        }
    }
}
