using System.Collections.Concurrent;
using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Hosting;
using UsbAudit.Shared;

namespace UsbAudit.Agent;

internal sealed class SoftwareControlWorker : BackgroundService
{
    private const uint NoActiveSession = 0xFFFFFFFF;
    private const int MbOk = 0x00000000;
    private const int MbIconWarning = 0x00000030;
    private static readonly ConcurrentDictionary<string, DateTimeOffset> LastNotice = new(StringComparer.OrdinalIgnoreCase);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        StoragePaths.EnsureDirectories();

        ManagementEventWatcher? watcher = null;
        EventArrivedEventHandler? handler = null;

        try
        {
            watcher = new ManagementEventWatcher(new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace"));
            handler = (_, args) =>
            {
                try
                {
                    var value = args.NewEvent.Properties["ProcessID"]?.Value;
                    if (value is null) return;
                    var processId = Convert.ToInt32(value);
                    _ = Task.Run(() => EvaluateProcess(processId), CancellationToken.None);
                }
                catch { }
            };

            watcher.EventArrived += handler;
            watcher.Start();

            while (!stoppingToken.IsCancellationRequested)
                await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        catch (Exception ex)
        {
            AppendWarning($"Software control watcher could not start: {ex.Message}");
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    ScanRunningProcesses();
                    await Task.Delay(TimeSpan.FromSeconds(3), stoppingToken);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
                catch { await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken); }
            }
        }
        finally
        {
            if (watcher is not null)
            {
                try
                {
                    if (handler is not null) watcher.EventArrived -= handler;
                    watcher.Stop();
                }
                catch { }
                watcher.Dispose();
            }
        }
    }

    internal static void RecheckRunningProcesses() => ScanRunningProcesses();

    private static void ScanRunningProcesses()
    {
        var policy = JsonStorage.LoadEndpointControlPolicy();
        if (!IsControlEnabled(policy)) return;

        foreach (var process in Process.GetProcesses())
        {
            try { EvaluateProcess(process.Id, policy); }
            catch { }
            finally { process.Dispose(); }
        }
    }

    private static void EvaluateProcess(int processId)
    {
        var policy = JsonStorage.LoadEndpointControlPolicy();
        EvaluateProcess(processId, policy);
    }

    private static void EvaluateProcess(int processId, EndpointControlPolicy policy)
    {
        if (!IsControlEnabled(policy)) return;
        if (processId <= 4 || processId == Environment.ProcessId) return;

        string? executablePath = null;
        string processName = string.Empty;

        try
        {
            using var process = Process.GetProcessById(processId);
            processName = process.ProcessName;
            try { executablePath = process.MainModule?.FileName; } catch { }

            executablePath ??= ReadExecutablePath(processId);
            if (string.IsNullOrWhiteSpace(executablePath)) return;

            var fullPath = SafeFullPath(executablePath);
            if (string.IsNullOrWhiteSpace(fullPath) || IsProtectedSystemPath(fullPath)) return;

            var rule = policy.BlockedSoftware.FirstOrDefault(item => MatchesRule(fullPath, item));
            if (rule is null) return;

            try
            {
                process.Kill(entireProcessTree: true);
                process.WaitForExit(2500);
            }
            catch
            {
                return;
            }

            JsonStorage.AppendEvent(new AuditEvent
            {
                Timestamp = DateTimeOffset.Now,
                Kind = AuditEventKind.Warning,
                Direction = TransferDirection.Unknown,
                WindowsUser = UsbDeviceDiscovery.GetInteractiveUser(),
                ComputerName = Environment.MachineName,
                FileName = Path.GetFileName(fullPath),
                FilePath = fullPath,
                Evidence = "EndpointPolicy",
                Notes = rule.ApprovalRequired
                    ? $"Launch stopped pending IT approval: {rule.SoftwareName}"
                    : $"Blocked application launch: {rule.SoftwareName}"
            });

            ShowBlockedNotice(rule.SoftwareName, processName, rule.ApprovalRequired);
        }
        catch { }
    }

    private static bool IsControlEnabled(EndpointControlPolicy policy) =>
        policy.Mode.Equals("enforce", StringComparison.OrdinalIgnoreCase)
        && policy.BlockedSoftware.Count > 0;

    private static bool MatchesRule(string executablePath, BlockedSoftwareRule rule)
    {
        foreach (var item in rule.ExecutablePaths)
        {
            var normalized = SafeFullPath(item);
            if (!string.IsNullOrWhiteSpace(normalized)
                && executablePath.Equals(normalized, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        var installRoot = SafeFullPath(rule.InstallLocation);
        if (string.IsNullOrWhiteSpace(installRoot) || IsGenericInstallRoot(installRoot)) return false;

        var root = installRoot.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                   + Path.DirectorySeparatorChar;
        return executablePath.StartsWith(root, StringComparison.OrdinalIgnoreCase);
    }

    private static string? ReadExecutablePath(int processId)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT ExecutablePath FROM Win32_Process WHERE ProcessId = {processId}");
            foreach (ManagementObject result in searcher.Get())
                return result["ExecutablePath"]?.ToString();
        }
        catch { }
        return null;
    }

    private static string? SafeFullPath(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        try
        {
            var expanded = Environment.ExpandEnvironmentVariables(value.Trim().Trim('"'));
            return Path.GetFullPath(expanded);
        }
        catch { return null; }
    }

    private static bool IsProtectedSystemPath(string path)
    {
        var windows = SafeFullPath(Environment.GetFolderPath(Environment.SpecialFolder.Windows));
        var auditProgram = SafeFullPath(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "UsbAudit"));

        if (!string.IsNullOrWhiteSpace(windows) && IsUnder(path, windows)) return true;
        if (!string.IsNullOrWhiteSpace(auditProgram) && IsUnder(path, auditProgram)) return true;

        try
        {
            var ownPath = Environment.ProcessPath;
            if (!string.IsNullOrWhiteSpace(ownPath)
                && path.Equals(Path.GetFullPath(ownPath), StringComparison.OrdinalIgnoreCase))
                return true;
        }
        catch { }

        return false;
    }

    private static bool IsGenericInstallRoot(string path)
    {
        var roots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Environment.GetFolderPath(Environment.SpecialFolder.Windows)
        };

        return roots.Select(SafeFullPath)
            .Where(item => !string.IsNullOrWhiteSpace(item))
            .Any(item => path.TrimEnd('\\').Equals(item!.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsUnder(string path, string root)
    {
        var prefix = root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                     + Path.DirectorySeparatorChar;
        return path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
               || path.Equals(root, StringComparison.OrdinalIgnoreCase);
    }

    private static void ShowBlockedNotice(string softwareName, string processName, bool approvalRequired)
    {
        var key = string.IsNullOrWhiteSpace(softwareName) ? processName : softwareName;
        var now = DateTimeOffset.UtcNow;
        if (LastNotice.TryGetValue(key, out var last) && now - last < TimeSpan.FromMinutes(3)) return;
        LastNotice[key] = now;

        try
        {
            var sessionId = WTSGetActiveConsoleSessionId();
            if (sessionId == NoActiveSession) return;

            const string title = "CRECCOM Endpoint Control";
            var message = approvalRequired
                ? $"{softwareName} has been installed but requires CRECCOM IT approval before you can run it. Contact IT; you do not need to reinstall."
                : $"{softwareName} is blocked by the active CRECCOM endpoint policy. Contact IT if you need access.";
            WTSSendMessage(
                IntPtr.Zero,
                unchecked((int)sessionId),
                title,
                title.Length * sizeof(char),
                message,
                message.Length * sizeof(char),
                MbOk | MbIconWarning,
                30,
                out _,
                false);
        }
        catch { }
    }

    private static void AppendWarning(string message)
    {
        try
        {
            JsonStorage.AppendEvent(new AuditEvent
            {
                Timestamp = DateTimeOffset.Now,
                Kind = AuditEventKind.Warning,
                Direction = TransferDirection.Unknown,
                WindowsUser = UsbDeviceDiscovery.GetInteractiveUser(),
                ComputerName = Environment.MachineName,
                Evidence = "EndpointPolicy",
                Notes = message
            });
        }
        catch { }
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
