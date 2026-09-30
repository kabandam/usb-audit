using System.Security.Cryptography;
using System.Text.Json;

namespace UsbAudit.Shared;

/// <summary>
/// Centrally provisioned PBKDF2 verifier. No plaintext settings password is persisted.
/// This is an additional UI guard; Windows ACLs still protect ProgramData/UsbAudit.
/// </summary>
public sealed class ConnectionSettingsVerifier
{
    public string SaltHex { get; set; } = string.Empty;
    public string HashHex { get; set; } = string.Empty;
    public int Iterations { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}

public static class ConnectionSettingsGuard
{
    private static readonly object Gate = new();
    private static readonly JsonSerializerOptions Json = new() { PropertyNameCaseInsensitive = true, WriteIndented = true };

    public static bool IsProvisioned => Read() is not null;

    public static bool Verify(string password)
    {
        var verifier = Read();
        if (verifier is null || string.IsNullOrEmpty(password)) return false;
        try
        {
            var salt = Convert.FromHexString(verifier.SaltHex);
            var expected = Convert.FromHexString(verifier.HashHex);
            var actual = Rfc2898DeriveBytes.Pbkdf2(
                password, salt, verifier.Iterations, HashAlgorithmName.SHA256, expected.Length);
            return CryptographicOperations.FixedTimeEquals(actual, expected);
        }
        catch (Exception) { return false; }
    }

    public static void SaveFromCloud(ConnectionSettingsVerifier verifier)
    {
        if (verifier.Iterations < 150_000 || verifier.Iterations > 1_000_000 ||
            verifier.SaltHex.Length != 32 || verifier.HashHex.Length != 64 ||
            !Convert.TryFromHexString(verifier.SaltHex, new byte[16], out var saltLength) || saltLength != 16 ||
            !Convert.TryFromHexString(verifier.HashHex, new byte[32], out var hashLength) || hashLength != 32 ||
            verifier.UpdatedAt == default)
            throw new InvalidOperationException("Invalid connection-settings administrator verifier.");

        lock (Gate)
        {
            var current = Read();
            if (current is not null && current.UpdatedAt > verifier.UpdatedAt) return;
            StoragePaths.EnsureDirectories();
            var temp = StoragePaths.ConnectionGuardPath + ".tmp";
            File.WriteAllText(temp, JsonSerializer.Serialize(verifier, Json));
            File.Move(temp, StoragePaths.ConnectionGuardPath, true);
        }
    }

    private static ConnectionSettingsVerifier? Read()
    {
        lock (Gate)
        {
            try
            {
                if (!File.Exists(StoragePaths.ConnectionGuardPath)) return null;
                var item = JsonSerializer.Deserialize<ConnectionSettingsVerifier>(
                    File.ReadAllText(StoragePaths.ConnectionGuardPath), Json);
                return item is { Iterations: >= 150_000 and <= 1_000_000 } &&
                       item.SaltHex.Length == 32 && item.HashHex.Length == 64
                    ? item : null;
            }
            catch { return null; }
        }
    }
}
