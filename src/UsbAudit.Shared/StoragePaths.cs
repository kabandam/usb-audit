namespace UsbAudit.Shared;

public static class StoragePaths
{
    public static string BaseDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "UsbAudit");

    public static string DataDirectory => Path.Combine(BaseDirectory, "Data");
    public static string ArchiveDirectory => Path.Combine(BaseDirectory, "Archive");
    public static string EventLogPath => Path.Combine(DataDirectory, "events.jsonl");
    public static string ConnectedDevicesPath => Path.Combine(DataDirectory, "connected-devices.json");
    public static string SettingsPath => Path.Combine(BaseDirectory, "settings.json");
    public static string AgentLogPath => Path.Combine(DataDirectory, "agent.log");
    public static string UpdateStatusPath => Path.Combine(DataDirectory, "update-status.json");
    public static string UpdateRequestPath => Path.Combine(DataDirectory, "update-request.flag");
    public static string UpdatesDirectory => Path.Combine(BaseDirectory, "Updates");

    public static void EnsureDirectories()
    {
        Directory.CreateDirectory(BaseDirectory);
        Directory.CreateDirectory(DataDirectory);
        Directory.CreateDirectory(ArchiveDirectory);
        Directory.CreateDirectory(UpdatesDirectory);
    }
}
