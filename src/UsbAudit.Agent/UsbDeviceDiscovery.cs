using System.Management;
using UsbAudit.Shared;

namespace UsbAudit.Agent;

internal static class UsbDeviceDiscovery
{
    public static List<ConnectedUsbDevice> Discover()
    {
        var results = new Dictionary<string, ConnectedUsbDevice>(StringComparer.OrdinalIgnoreCase);

        // Prefer WMI associations so USB HDD/SSD devices that Windows reports as "fixed"
        // are still recognized as USB-backed volumes.
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT DeviceID, Model, SerialNumber, InterfaceType, PNPDeviceID FROM Win32_DiskDrive");
            foreach (ManagementObject disk in searcher.Get())
            {
                using (disk)
                {
                    var interfaceType = disk["InterfaceType"]?.ToString() ?? string.Empty;
                    var pnp = disk["PNPDeviceID"]?.ToString() ?? string.Empty;
                    var isUsb = string.Equals(interfaceType, "USB", StringComparison.OrdinalIgnoreCase) ||
                                pnp.StartsWith("USB", StringComparison.OrdinalIgnoreCase) ||
                                pnp.Contains("USBSTOR", StringComparison.OrdinalIgnoreCase);
                    if (!isUsb) continue;

                    var model = disk["Model"]?.ToString()?.Trim();
                    var serial = disk["SerialNumber"]?.ToString()?.Trim();

                    foreach (ManagementObject partition in disk.GetRelated("Win32_DiskPartition"))
                    {
                        using (partition)
                        {
                            foreach (ManagementObject logical in partition.GetRelated("Win32_LogicalDisk"))
                            {
                                using (logical)
                                {
                                    var logicalId = logical["DeviceID"]?.ToString();
                                    if (string.IsNullOrWhiteSpace(logicalId)) continue;
                                    TryAddVolume(results, logicalId, model, serial);
                                }
                            }
                        }
                    }
                }
            }
        }
        catch
        {
            // Fall through to removable-drive enumeration.
        }

        // Fallback also catches thumb drives on machines where WMI disk associations are unavailable.
        foreach (var drive in DriveInfo.GetDrives())
        {
            try
            {
                if (!drive.IsReady || drive.DriveType != DriveType.Removable) continue;
                var logicalId = drive.Name.TrimEnd('\\');
                if (!results.ContainsKey(logicalId))
                {
                    TryAddVolume(results, logicalId, null, TryGetVolumeSerial(logicalId));
                }
            }
            catch { }
        }

        return results.Values.OrderBy(x => x.DriveLetter).ToList();
    }

    private static void TryAddVolume(
        IDictionary<string, ConnectedUsbDevice> results,
        string logicalId,
        string? model,
        string? physicalSerial)
    {
        try
        {
            var drive = new DriveInfo(logicalId + "\\");
            if (!drive.IsReady) return;
            var serial = string.IsNullOrWhiteSpace(physicalSerial) ? TryGetVolumeSerial(logicalId) : physicalSerial;
            var name = string.IsNullOrWhiteSpace(model) ? "Removable USB storage" : model!;
            results[logicalId] = new ConnectedUsbDevice
            {
                DeviceKey = $"{serial ?? "noserial"}|{logicalId}",
                DriveLetter = logicalId,
                DeviceName = name.Trim(),
                DeviceSerial = serial?.Trim(),
                VolumeLabel = Safe(() => drive.VolumeLabel),
                FileSystem = Safe(() => drive.DriveFormat),
                TotalSizeBytes = SafeLong(() => drive.TotalSize),
                AvailableFreeSpaceBytes = SafeLong(() => drive.AvailableFreeSpace),
                ConnectedAt = DateTimeOffset.Now
            };
        }
        catch
        {
            // Volume can disappear between WMI discovery and DriveInfo inspection.
        }
    }

    private static string? TryGetVolumeSerial(string logicalId)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT VolumeSerialNumber FROM Win32_LogicalDisk WHERE DeviceID='{logicalId}'");
            foreach (ManagementObject item in searcher.Get())
            {
                using (item)
                {
                    return item["VolumeSerialNumber"]?.ToString();
                }
            }
        }
        catch { }
        return null;
    }

    public static string GetInteractiveUser()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT UserName FROM Win32_ComputerSystem");
            foreach (ManagementObject item in searcher.Get())
            {
                using (item)
                {
                    var user = item["UserName"]?.ToString();
                    if (!string.IsNullOrWhiteSpace(user)) return user;
                }
            }
        }
        catch { }
        return Environment.UserName;
    }

    private static string? Safe(Func<string> getter)
    {
        try { return getter(); } catch { return null; }
    }

    private static long SafeLong(Func<long> getter)
    {
        try { return getter(); } catch { return 0; }
    }
}
