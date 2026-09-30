using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using UsbAudit.Shared;

namespace UsbAudit.Agent;

/// <summary>
/// Reports only the active Windows network adapter. No GPS, browsing activity,
/// traffic capture, or active bandwidth test is performed by this background service.
/// </summary>
internal static class NetworkInventory
{
    private static readonly object Gate = new();
    private static NetworkSnapshot? cached;
    private static DateTimeOffset lastCaptured = DateTimeOffset.MinValue;

    public static NetworkSnapshot Capture()
    {
        lock (Gate)
        {
            var now = DateTimeOffset.UtcNow;
            if (cached is not null && now - lastCaptured < TimeSpan.FromSeconds(30))
                return cached;

            try
            {
                var candidate = NetworkInterface.GetAllNetworkInterfaces()
                    .Where(n => n.OperationalStatus == OperationalStatus.Up
                        && n.NetworkInterfaceType != NetworkInterfaceType.Loopback
                        && n.NetworkInterfaceType != NetworkInterfaceType.Tunnel)
                    .Select(n => new { Adapter = n, Properties = n.GetIPProperties() })
                    .Where(n => n.Properties.UnicastAddresses.Any(a =>
                        a.Address.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(a.Address)))
                    .OrderByDescending(n => n.Properties.GatewayAddresses.Any(g =>
                        g.Address.AddressFamily == AddressFamily.InterNetwork && !g.Address.Equals(IPAddress.Any)))
                    .ThenByDescending(n => n.Adapter.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 ||
                                           n.Adapter.NetworkInterfaceType == NetworkInterfaceType.Ethernet)
                    .FirstOrDefault();

                if (candidate is null)
                {
                    cached = new NetworkSnapshot { ConnectionType = "Disconnected", ObservedAt = now };
                }
                else
                {
                    var nic = candidate.Adapter;
                    var props = candidate.Properties;
                    var kind = nic.NetworkInterfaceType switch
                    {
                        NetworkInterfaceType.Wireless80211 => "Wi-Fi",
                        NetworkInterfaceType.Ethernet => "Ethernet",
                        NetworkInterfaceType.Ppp => "PPP/Mobile",
                        _ => nic.NetworkInterfaceType.ToString()
                    };
                    var ipv4 = props.UnicastAddresses.FirstOrDefault(a =>
                        a.Address.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(a.Address));
                    var gateway = props.GatewayAddresses.FirstOrDefault(g =>
                        g.Address.AddressFamily == AddressFamily.InterNetwork && !g.Address.Equals(IPAddress.Any));
                    var macBytes = nic.GetPhysicalAddress().GetAddressBytes();
                    cached = new NetworkSnapshot
                    {
                        ConnectionType = kind,
                        AdapterName = nic.Name,
                        NetworkName = kind == "Wi-Fi" ? ReadWiFiSsid() ?? nic.Name : nic.Name,
                        LocalIp = ipv4?.Address.ToString(),
                        GatewayIp = gateway?.Address.ToString(),
                        DnsServers = props.DnsAddresses.Select(ip => ip.ToString()).Take(6).ToList(),
                        MacAddress = macBytes.Length == 6
                            ? string.Join(":", macBytes.Select(b => b.ToString("X2"))) : null,
                        LinkSpeedMbps = nic.Speed > 0 ? Math.Round(nic.Speed / 1_000_000d, 2) : null,
                        ObservedAt = now
                    };
                }
            }
            catch
            {
                cached = new NetworkSnapshot { ConnectionType = "Unavailable", ObservedAt = now };
            }

            lastCaptured = now;
            return cached;
        }
    }

    private static string? ReadWiFiSsid()
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = "netsh.exe",
                Arguments = "wlan show interfaces",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            });
            if (process is null) return null;
            if (!process.WaitForExit(2500))
            {
                try { process.Kill(true); } catch { }
                return null;
            }
            foreach (var raw in process.StandardOutput.ReadToEnd().Split('\n'))
            {
                var line = raw.Trim();
                var colon = line.IndexOf(':');
                if (colon <= 0) continue;
                // Distinguish SSID from BSSID, which is the access point MAC.
                if (line[..colon].Trim().Equals("SSID", StringComparison.OrdinalIgnoreCase))
                    return string.IsNullOrWhiteSpace(line[(colon + 1)..])
                        ? null : line[(colon + 1)..].Trim();
            }
        }
        catch { }
        return null;
    }
}
