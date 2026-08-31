namespace UsbAudit.Shared;

public static class Formatting
{
    public static string Bytes(long? value)
    {
        if (value is null) return "—";
        var bytes = (double)value.Value;
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        var unit = 0;
        while (bytes >= 1024 && unit < units.Length - 1)
        {
            bytes /= 1024;
            unit++;
        }
        return $"{bytes:0.##} {units[unit]}";
    }
}
