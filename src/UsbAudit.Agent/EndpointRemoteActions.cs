using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using UsbAudit.Shared;

namespace UsbAudit.Agent;

internal static class EndpointRemoteActions
{
    private const uint NoActiveSession = 0xFFFFFFFF;
    private const int TokenUserClass = 1;
    private const uint PolicyLookupNames = 0x00000800;
    private const uint CreateUnicodeEnvironment = 0x00000400;
    private const uint CreateNoWindow = 0x08000000;
    private const int NameUserPrincipal = 8;
    private const string DenyInteractiveLogonRight = "SeDenyInteractiveLogonRight";
    private static readonly string RestrictionStatePath =
        Path.Combine(StoragePaths.DataDirectory, "access-restriction.json");

    private sealed record ActiveUserContext(
        uint SessionId,
        string Sid,
        string AccountName,
        string ProfilePath,
        IntPtr UserToken) : IDisposable
    {
        public void Dispose()
        {
            if (UserToken != IntPtr.Zero) CloseHandle(UserToken);
        }
    }

    private sealed record AccessRestrictionState(
        string Sid,
        string AccountName,
        DateTimeOffset RestrictedAt);

    private sealed record OneDriveStatus(
        bool IsRunning,
        bool AccountConfigured,
        string? UserEmail,
        string? SyncRoot,
        string? ClientVersion,
        string? TenantId,
        bool DesktopProtected,
        bool DocumentsProtected,
        bool PicturesProtected,
        string Health);

    private sealed record DeviceRegistrationStatus(
        bool EntraJoined,
        string? TenantId);

    public static EndpointCommandResult ExecuteDeviceControl(
        Guid commandId,
        Dictionary<string, object?> payload)
    {
        var action = PayloadAction(payload);
        return action switch
        {
            "lock" => LockSession(commandId),
            "sign_out" => SignOut(commandId),
            "restart" => SchedulePowerAction(commandId, restart: true),
            "shutdown" => SchedulePowerAction(commandId, restart: false),
            "restrict_access" => RestrictAccess(commandId),
            "restore_access" => RestoreAccess(commandId),
            _ => throw new InvalidOperationException("Unsupported managed device-control action.")
        };
    }

    public static EndpointCommandResult ExecuteOneDrive(
        Guid commandId,
        Dictionary<string, object?> payload)
    {
        var action = PayloadAction(payload);
        return action switch
        {
            "status" => OneDriveStatusResult(commandId, action, "OneDrive protection status refreshed."),
            "start" => StartOneDrive(commandId),
            "restart" => RestartOneDrive(commandId),
            "enable_folder_protection" => EnableFolderProtection(commandId),
            "enforce_assigned_protection" => EnforceAssignedOneDriveProtection(commandId, payload),
            _ => throw new InvalidOperationException("Unsupported managed OneDrive action.")
        };
    }

    private static EndpointCommandResult LockSession(Guid commandId)
    {
        var sessionId = WTSGetActiveConsoleSessionId();
        if (sessionId == NoActiveSession)
            throw new InvalidOperationException("No signed-in Windows session is available to lock.");

        if (!WTSDisconnectSession(IntPtr.Zero, sessionId, false))
            throw new System.ComponentModel.Win32Exception(
                Marshal.GetLastWin32Error(), "Windows could not lock the signed-in session.");

        return Completed(commandId, "Windows session locked by CRECCOM IT.", new()
        {
            ["action"] = "lock",
            ["sessionId"] = sessionId
        });
    }

    private static EndpointCommandResult SignOut(Guid commandId)
    {
        var sessionId = WTSGetActiveConsoleSessionId();
        if (sessionId == NoActiveSession)
            throw new InvalidOperationException("No signed-in Windows session is available to sign out.");

        if (!WTSLogoffSession(IntPtr.Zero, sessionId, false))
            throw new System.ComponentModel.Win32Exception(
                Marshal.GetLastWin32Error(), "Windows could not sign out the current session.");

        return Completed(commandId, "Current Windows user signed out by CRECCOM IT.", new()
        {
            ["action"] = "sign_out",
            ["sessionId"] = sessionId
        });
    }

    private static EndpointCommandResult SchedulePowerAction(Guid commandId, bool restart)
    {
        var action = restart ? "restart" : "shutdown";
        var arguments = restart
            ? "/r /t 60 /d p:4:1 /c \"CRECCOM IT scheduled a managed restart. Save your work.\""
            : "/s /t 60 /d p:4:1 /c \"CRECCOM IT scheduled a managed shutdown. Save your work.\"";

        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                "shutdown.exe"),
            Arguments = arguments,
            UseShellExecute = false,
            CreateNoWindow = true
        }) ?? throw new InvalidOperationException($"Windows {action} command could not be started.");

        if (!process.WaitForExit(10_000) || process.ExitCode != 0)
            throw new InvalidOperationException($"Windows rejected the managed {action} request.");

        return Completed(
            commandId,
            restart
                ? "Managed restart scheduled in 60 seconds."
                : "Managed shutdown scheduled in 60 seconds.",
            new()
            {
                ["action"] = action,
                ["delaySeconds"] = 60
            });
    }

    private static EndpointCommandResult RestrictAccess(Guid commandId)
    {
        using var user = GetActiveUserContext();
        var sid = new SecurityIdentifier(user.Sid);

        // Never remotely deny the built-in recovery Administrator account.
        if (user.Sid.EndsWith("-500", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException(
                "The built-in Administrator account cannot be restricted remotely. Use a standard managed user account.");

        AddAccountRight(sid, DenyInteractiveLogonRight);
        Directory.CreateDirectory(StoragePaths.DataDirectory);
        File.WriteAllText(
            RestrictionStatePath,
            JsonSerializer.Serialize(new AccessRestrictionState(
                user.Sid,
                user.AccountName,
                DateTimeOffset.UtcNow)));

        // Disconnecting the session takes effect immediately while leaving the
        // Smart Console Windows service and network connectivity alive.
        var disconnected = WTSDisconnectSession(IntPtr.Zero, user.SessionId, false);

        return Completed(commandId,
            disconnected
                ? $"Interactive sign-in restricted for {user.AccountName}. Smart Console management remains available."
                : $"Interactive sign-in restricted for {user.AccountName}, but Windows could not disconnect the current session automatically. The restriction will apply at the next sign-in.",
            new()
            {
                ["action"] = "restrict_access",
                ["accessRestricted"] = true,
                ["restrictedUser"] = user.AccountName,
                ["restrictedSid"] = user.Sid,
                ["sessionDisconnected"] = disconnected
            });
    }

    private static EndpointCommandResult RestoreAccess(Guid commandId)
    {
        if (!File.Exists(RestrictionStatePath))
        {
            return Completed(commandId, "No Smart Console sign-in restriction is currently recorded on this endpoint.", new()
            {
                ["action"] = "restore_access",
                ["accessRestricted"] = false
            });
        }

        AccessRestrictionState? state;
        try
        {
            state = JsonSerializer.Deserialize<AccessRestrictionState>(
                File.ReadAllText(RestrictionStatePath));
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                "The local access-restriction record could not be read safely.", ex);
        }

        if (state is null || string.IsNullOrWhiteSpace(state.Sid))
            throw new InvalidOperationException("The local access-restriction record is incomplete.");

        RemoveAccountRight(new SecurityIdentifier(state.Sid), DenyInteractiveLogonRight);
        File.Delete(RestrictionStatePath);

        return Completed(commandId, $"Interactive sign-in restored for {state.AccountName}.", new()
        {
            ["action"] = "restore_access",
            ["accessRestricted"] = false,
            ["restrictedUser"] = state.AccountName,
            ["restrictedSid"] = state.Sid
        });
    }

    private static EndpointCommandResult StartOneDrive(Guid commandId)
    {
        using var user = GetActiveUserContext();
        var executable = ResolveOneDriveExecutable(user.ProfilePath);
        if (string.IsNullOrWhiteSpace(executable))
            throw new InvalidOperationException("Microsoft OneDrive is not installed for the signed-in Windows user.");

        if (!IsOneDriveRunning(user.SessionId))
            StartAsActiveUser(user, executable, string.Empty);

        Thread.Sleep(1200);
        return OneDriveStatusResult(
            commandId,
            "start",
            "OneDrive start request completed.",
            user);
    }

    private static EndpointCommandResult RestartOneDrive(Guid commandId)
    {
        using var user = GetActiveUserContext();
        var executable = ResolveOneDriveExecutable(user.ProfilePath);
        if (string.IsNullOrWhiteSpace(executable))
            throw new InvalidOperationException("Microsoft OneDrive is not installed for the signed-in Windows user.");

        foreach (var process in Process.GetProcessesByName("OneDrive"))
        {
            try
            {
                if (process.SessionId != unchecked((int)user.SessionId)) continue;
                process.Kill(entireProcessTree: true);
                process.WaitForExit(5000);
            }
            catch { }
            finally { process.Dispose(); }
        }

        StartAsActiveUser(user, executable, string.Empty);
        Thread.Sleep(1500);

        return OneDriveStatusResult(
            commandId,
            "restart",
            "OneDrive restarted for the signed-in Windows user.",
            user);
    }

    private static EndpointCommandResult EnableFolderProtection(Guid commandId)
    {
        using var user = GetActiveUserContext();
        var tenantId = ResolveTenantId(user);
        if (!Guid.TryParse(tenantId, out _))
        {
            throw new InvalidOperationException(
                "A Microsoft 365 tenant ID could not be detected on this PC. The user must be signed in to the CRECCOM work account before folder protection can be enabled.");
        }

        ApplyOneDriveProtectionPolicy(tenantId, enableSilentAccountConfig: false);
        RestartOneDriveForUser(user, requireInstalledClient: false);

        Thread.Sleep(1500);
        return OneDriveStatusResult(
            commandId,
            "enable_folder_protection",
            "OneDrive folder-protection policy applied. Desktop, Documents and Pictures will move into the CRECCOM OneDrive when the signed-in OneDrive client processes the policy.",
            user);
    }

    private static EndpointCommandResult EnforceAssignedOneDriveProtection(
        Guid commandId,
        Dictionary<string, object?> payload)
    {
        var expectedUpn = PayloadString(payload, "expectedUserPrincipalName");
        if (string.IsNullOrWhiteSpace(expectedUpn))
            throw new InvalidOperationException("The assigned Microsoft 365 user is missing from this OneDrive command.");

        var expectedTenantId = PayloadString(payload, "expectedTenantId");

        using var user = GetActiveUserContext();
        var registration = ReadDeviceRegistrationStatus();
        if (!registration.EntraJoined)
        {
            throw new InvalidOperationException(
                "Silent OneDrive sign-in was not applied because this PC is not Microsoft Entra joined.");
        }

        var windowsUpn = ResolveActiveUserUpn(user);
        if (string.IsNullOrWhiteSpace(windowsUpn))
        {
            throw new InvalidOperationException(
                "Smart Console could not resolve the signed-in Windows user's Entra UPN. Sign in to Windows with the assigned CRECCOM work account and try again.");
        }

        if (!string.Equals(
                windowsUpn.Trim(),
                expectedUpn.Trim(),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"OneDrive enforcement blocked: Windows is signed in as {windowsUpn}, but this PC is assigned to {expectedUpn}.");
        }

        var existingStatus = ReadOneDriveStatus(user);
        if (!string.IsNullOrWhiteSpace(existingStatus.UserEmail) &&
            !string.Equals(
                existingStatus.UserEmail.Trim(),
                expectedUpn.Trim(),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"OneDrive enforcement blocked: OneDrive is already configured as {existingStatus.UserEmail}, but this PC is assigned to {expectedUpn}. Sign out the incorrect OneDrive account before retrying.");
        }

        var tenantId = registration.TenantId ?? ResolveTenantId(user);
        if (!Guid.TryParse(tenantId, out var parsedTenant))
        {
            throw new InvalidOperationException(
                "The Microsoft Entra tenant ID could not be resolved on this PC.");
        }

        if (!string.IsNullOrWhiteSpace(expectedTenantId) &&
            Guid.TryParse(expectedTenantId, out var expectedTenant) &&
            expectedTenant != parsedTenant)
        {
            throw new InvalidOperationException(
                "OneDrive enforcement blocked because this PC is joined to a different Microsoft Entra tenant than the assigned account.");
        }

        var executable = ResolveOneDriveExecutable(user.ProfilePath);
        if (string.IsNullOrWhiteSpace(executable))
        {
            throw new InvalidOperationException(
                "Microsoft OneDrive is not installed for the signed-in Windows user.");
        }

        ApplyOneDriveProtectionPolicy(parsedTenant.ToString(), enableSilentAccountConfig: true);
        RestartOneDriveForUser(user, requireInstalledClient: true);

        Thread.Sleep(2500);
        var status = ReadOneDriveStatus(user);
        var reportedEmail = status.UserEmail;
        var accountMatch =
            string.IsNullOrWhiteSpace(reportedEmail) ||
            string.Equals(reportedEmail, expectedUpn, StringComparison.OrdinalIgnoreCase);

        return Completed(
            commandId,
            string.IsNullOrWhiteSpace(reportedEmail)
                ? $"Silent OneDrive sign-in and folder protection were enforced for {expectedUpn}. OneDrive is processing the assigned Windows/Entra identity."
                : $"Silent OneDrive sign-in and folder protection were enforced for {expectedUpn}.",
            new()
            {
                ["action"] = "enforce_assigned_protection",
                ["isRunning"] = status.IsRunning,
                ["accountConfigured"] = status.AccountConfigured,
                ["userEmail"] = status.UserEmail,
                ["syncRoot"] = status.SyncRoot,
                ["clientVersion"] = status.ClientVersion,
                ["tenantId"] = status.TenantId ?? parsedTenant.ToString(),
                ["desktopProtected"] = status.DesktopProtected,
                ["documentsProtected"] = status.DocumentsProtected,
                ["picturesProtected"] = status.PicturesProtected,
                ["health"] = status.Health,
                ["entraJoined"] = true,
                ["windowsUserUpn"] = windowsUpn,
                ["expectedUserEmail"] = expectedUpn,
                ["accountMatch"] = accountMatch,
                ["silentSigninEnabled"] = true,
                ["reportedAt"] = DateTimeOffset.UtcNow.ToString("O")
            });
    }

    private static void ApplyOneDriveProtectionPolicy(
        string tenantId,
        bool enableSilentAccountConfig)
    {
        using var key = Registry.LocalMachine.CreateSubKey(
            @"SOFTWARE\Policies\Microsoft\OneDrive",
            writable: true);

        if (key is null)
            throw new InvalidOperationException("Windows could not open the OneDrive policy registry.");

        if (enableSilentAccountConfig)
            key.SetValue("SilentAccountConfig", 1, RegistryValueKind.DWord);

        key.SetValue("KFMSilentOptIn", tenantId, RegistryValueKind.String);
        key.SetValue("KFMBlockOptOut", 1, RegistryValueKind.DWord);
        key.SetValue("KFMSilentOptInWithNotification", 0, RegistryValueKind.DWord);
    }

    private static void RestartOneDriveForUser(
        ActiveUserContext user,
        bool requireInstalledClient)
    {
        var executable = ResolveOneDriveExecutable(user.ProfilePath);
        if (string.IsNullOrWhiteSpace(executable))
        {
            if (requireInstalledClient)
                throw new InvalidOperationException(
                    "Microsoft OneDrive is not installed for the signed-in Windows user.");
            return;
        }

        foreach (var process in Process.GetProcessesByName("OneDrive"))
        {
            try
            {
                if (process.SessionId != unchecked((int)user.SessionId)) continue;
                process.Kill(entireProcessTree: true);
                process.WaitForExit(5000);
            }
            catch { }
            finally { process.Dispose(); }
        }

        StartAsActiveUser(user, executable, string.Empty);
    }

    private static EndpointCommandResult OneDriveStatusResult(
        Guid commandId,
        string action,
        string message,
        ActiveUserContext? existingUser = null)
    {
        var ownsUser = existingUser is null;
        var user = existingUser ?? GetActiveUserContext();
        try
        {
            var status = ReadOneDriveStatus(user);
            return Completed(commandId, message, new()
            {
                ["action"] = action,
                ["isRunning"] = status.IsRunning,
                ["accountConfigured"] = status.AccountConfigured,
                ["userEmail"] = status.UserEmail,
                ["syncRoot"] = status.SyncRoot,
                ["clientVersion"] = status.ClientVersion,
                ["tenantId"] = status.TenantId,
                ["desktopProtected"] = status.DesktopProtected,
                ["documentsProtected"] = status.DocumentsProtected,
                ["picturesProtected"] = status.PicturesProtected,
                ["health"] = status.Health,
                ["reportedAt"] = DateTimeOffset.UtcNow.ToString("O")
            });
        }
        finally
        {
            if (ownsUser) user.Dispose();
        }
    }

    private static OneDriveStatus ReadOneDriveStatus(ActiveUserContext user)
    {
        string? email = null;
        string? syncRoot = null;
        string? tenantId = null;

        using (var accounts = Registry.Users.OpenSubKey(
                   $@"{user.Sid}\Software\Microsoft\OneDrive\Accounts"))
        {
            var business = accounts?.GetSubKeyNames()
                .FirstOrDefault(name => name.StartsWith("Business", StringComparison.OrdinalIgnoreCase));
            if (!string.IsNullOrWhiteSpace(business))
            {
                using var account = accounts!.OpenSubKey(business);
                email = account?.GetValue("UserEmail") as string;
                syncRoot = account?.GetValue("UserFolder") as string;
                tenantId =
                    account?.GetValue("ConfiguredTenantId") as string ??
                    account?.GetValue("TenantID") as string ??
                    account?.GetValue("TenantId") as string;
            }
        }

        tenantId ??= ResolveTenantId(user);
        var executable = ResolveOneDriveExecutable(user.ProfilePath);
        var version = !string.IsNullOrWhiteSpace(executable) && File.Exists(executable)
            ? FileVersionInfo.GetVersionInfo(executable).FileVersion
            : null;

        var desktop = false;
        var documents = false;
        var pictures = false;
        using (var shell = Registry.Users.OpenSubKey(
                   $@"{user.Sid}\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"))
        {
            desktop = IsProtectedKnownFolder(shell?.GetValue("Desktop") as string, syncRoot, user.ProfilePath);
            documents = IsProtectedKnownFolder(shell?.GetValue("Personal") as string, syncRoot, user.ProfilePath);
            pictures = IsProtectedKnownFolder(shell?.GetValue("My Pictures") as string, syncRoot, user.ProfilePath);
        }

        var configured = !string.IsNullOrWhiteSpace(email) || !string.IsNullOrWhiteSpace(syncRoot);
        var running = IsOneDriveRunning(user.SessionId);
        var health = !configured
            ? "not_configured"
            : !running
                ? "stopped"
                : desktop && documents && pictures
                    ? "protected"
                    : "running";

        return new OneDriveStatus(
            running,
            configured,
            email,
            syncRoot,
            version,
            tenantId,
            desktop,
            documents,
            pictures,
            health);
    }

    private static bool IsProtectedKnownFolder(
        string? path,
        string? syncRoot,
        string profilePath)
    {
        if (string.IsNullOrWhiteSpace(path) || string.IsNullOrWhiteSpace(syncRoot))
            return false;

        var expanded = ExpandUserPath(path, profilePath, syncRoot);
        var root = ExpandUserPath(syncRoot, profilePath, syncRoot)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

        try
        {
            var full = Path.GetFullPath(expanded);
            var rootFull = Path.GetFullPath(root) + Path.DirectorySeparatorChar;
            return full.StartsWith(rootFull, StringComparison.OrdinalIgnoreCase)
                || string.Equals(full, root, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return expanded.Contains(root, StringComparison.OrdinalIgnoreCase);
        }
    }

    private static string ExpandUserPath(
        string value,
        string profilePath,
        string? syncRoot)
    {
        var expanded = value
            .Replace("%USERPROFILE%", profilePath, StringComparison.OrdinalIgnoreCase);
        if (!string.IsNullOrWhiteSpace(syncRoot))
        {
            expanded = expanded
                .Replace("%OneDrive%", syncRoot, StringComparison.OrdinalIgnoreCase)
                .Replace("%OneDriveCommercial%", syncRoot, StringComparison.OrdinalIgnoreCase);
        }
        return Environment.ExpandEnvironmentVariables(expanded);
    }

    private static string? ResolveTenantId(ActiveUserContext user)
    {
        var registration = ReadDeviceRegistrationStatus();
        if (!string.IsNullOrWhiteSpace(registration.TenantId))
            return registration.TenantId;

        using var accounts = Registry.Users.OpenSubKey(
            $@"{user.Sid}\Software\Microsoft\OneDrive\Accounts");
        var business = accounts?.GetSubKeyNames()
            .FirstOrDefault(name => name.StartsWith("Business", StringComparison.OrdinalIgnoreCase));
        if (string.IsNullOrWhiteSpace(business)) return null;
        using var account = accounts!.OpenSubKey(business);
        return account?.GetValue("ConfiguredTenantId") as string
            ?? account?.GetValue("TenantID") as string
            ?? account?.GetValue("TenantId") as string;
    }

    private static DeviceRegistrationStatus ReadDeviceRegistrationStatus()
    {
        var entraJoined = false;
        string? tenantId = null;

        try
        {
            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.System),
                    "dsregcmd.exe"),
                Arguments = "/status",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            });

            if (process is not null)
            {
                var output = process.StandardOutput.ReadToEnd();
                process.WaitForExit(8000);

                foreach (var line in output.Split('\n'))
                {
                    var trimmed = line.Trim();
                    var parts = trimmed.Split(':', 2);
                    if (parts.Length != 2) continue;

                    var name = parts[0].Trim();
                    var value = parts[1].Trim();

                    if (name.Equals("AzureAdJoined", StringComparison.OrdinalIgnoreCase))
                        entraJoined = value.Equals("YES", StringComparison.OrdinalIgnoreCase);
                    else if (name.Equals("TenantId", StringComparison.OrdinalIgnoreCase) &&
                             Guid.TryParse(value, out var parsed))
                        tenantId = parsed.ToString();
                }
            }
        }
        catch { }

        return new DeviceRegistrationStatus(entraJoined, tenantId);
    }

    private static string? ResolveActiveUserUpn(ActiveUserContext user)
    {
        if (ImpersonateLoggedOnUser(user.UserToken))
        {
            try
            {
                uint length = 512;
                var buffer = new StringBuilder((int)length);
                if (GetUserNameEx(NameUserPrincipal, buffer, ref length))
                {
                    var upn = buffer.ToString().Trim();
                    if (upn.Contains('@')) return upn;
                }

                if (length > 512 && length < 4096)
                {
                    buffer = new StringBuilder((int)length);
                    if (GetUserNameEx(NameUserPrincipal, buffer, ref length))
                    {
                        var upn = buffer.ToString().Trim();
                        if (upn.Contains('@')) return upn;
                    }
                }
            }
            finally
            {
                RevertToSelf();
            }
        }

        try
        {
            using var identities = Registry.Users.OpenSubKey(
                $@"{user.Sid}\Software\Microsoft\IdentityCRL\StoredIdentities");
            var stored = identities?.GetSubKeyNames()
                .FirstOrDefault(name => name.Contains('@'));
            if (!string.IsNullOrWhiteSpace(stored)) return stored;
        }
        catch { }

        try
        {
            using var identities = Registry.Users.OpenSubKey(
                $@"{user.Sid}\Software\Microsoft\Office\16.0\Common\Identity\Identities");
            if (identities is not null)
            {
                foreach (var subKeyName in identities.GetSubKeyNames())
                {
                    using var identity = identities.OpenSubKey(subKeyName);
                    var email = identity?.GetValue("EmailAddress") as string;
                    if (!string.IsNullOrWhiteSpace(email) && email.Contains('@'))
                        return email;
                }
            }
        }
        catch { }

        try
        {
            return ReadOneDriveStatus(user).UserEmail;
        }
        catch
        {
            return null;
        }
    }

    private static string? PayloadString(
        Dictionary<string, object?> payload,
        string key)
    {
        if (!payload.TryGetValue(key, out var value) || value is null)
            return null;

        return value switch
        {
            JsonElement element when element.ValueKind == JsonValueKind.String => element.GetString(),
            _ => Convert.ToString(value)
        };
    }

    private static string? ResolveOneDriveExecutable(string profilePath)
    {
        var candidates = new[]
        {
            Path.Combine(profilePath, "AppData", "Local", "Microsoft", "OneDrive", "OneDrive.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Microsoft OneDrive", "OneDrive.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Microsoft OneDrive", "OneDrive.exe")
        };
        return candidates.FirstOrDefault(File.Exists);
    }

    private static bool IsOneDriveRunning(uint sessionId)
    {
        foreach (var process in Process.GetProcessesByName("OneDrive"))
        {
            try
            {
                if (process.SessionId == unchecked((int)sessionId)) return true;
            }
            catch { }
            finally { process.Dispose(); }
        }
        return false;
    }

    private static string PayloadAction(Dictionary<string, object?> payload)
    {
        if (!payload.TryGetValue("action", out var value) || value is null)
            throw new InvalidOperationException("Managed endpoint action payload is missing.");

        var action = value switch
        {
            JsonElement element when element.ValueKind == JsonValueKind.String => element.GetString(),
            _ => Convert.ToString(value)
        };
        if (string.IsNullOrWhiteSpace(action))
            throw new InvalidOperationException("Managed endpoint action payload is invalid.");

        return action.Trim().ToLowerInvariant();
    }

    private static EndpointCommandResult Completed(
        Guid commandId,
        string message,
        Dictionary<string, object?> details) =>
        new()
        {
            CommandId = commandId,
            Status = "completed",
            Message = message,
            Details = details
        };

    private static ActiveUserContext GetActiveUserContext()
    {
        var sessionId = WTSGetActiveConsoleSessionId();
        if (sessionId == NoActiveSession)
            throw new InvalidOperationException("No signed-in Windows user session is available.");

        if (!WTSQueryUserToken(sessionId, out var token))
            throw new System.ComponentModel.Win32Exception(
                Marshal.GetLastWin32Error(),
                "Smart Console could not inspect the signed-in Windows session.");

        try
        {
            using var identity = new WindowsIdentity(token);
            var sid = identity.User?.Value
                ?? throw new InvalidOperationException("The signed-in Windows user SID could not be resolved.");
            var account = identity.Name ?? sid;
            using var profileKey = Registry.LocalMachine.OpenSubKey(
                $@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}");
            var profile = profileKey?.GetValue("ProfileImagePath") as string;
            if (string.IsNullOrWhiteSpace(profile))
                throw new InvalidOperationException("The signed-in Windows user profile could not be resolved.");

            return new ActiveUserContext(
                sessionId,
                sid,
                account,
                Environment.ExpandEnvironmentVariables(profile),
                token);
        }
        catch
        {
            CloseHandle(token);
            throw;
        }
    }

    private static void StartAsActiveUser(
        ActiveUserContext user,
        string executable,
        string arguments)
    {
        IntPtr environment = IntPtr.Zero;
        try
        {
            if (!CreateEnvironmentBlock(out environment, user.UserToken, false))
                environment = IntPtr.Zero;

            var commandLine = new StringBuilder(
                $"\"{executable}\"{(string.IsNullOrWhiteSpace(arguments) ? string.Empty : " " + arguments)}");
            var startup = new StartupInfo
            {
                cb = Marshal.SizeOf<StartupInfo>(),
                lpDesktop = "winsta0\\default"
            };

            if (!CreateProcessAsUser(
                    user.UserToken,
                    executable,
                    commandLine,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    CreateUnicodeEnvironment | CreateNoWindow,
                    environment,
                    Path.GetDirectoryName(executable),
                    ref startup,
                    out var processInfo))
            {
                throw new System.ComponentModel.Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Smart Console could not start OneDrive in the signed-in Windows session.");
            }

            if (processInfo.hThread != IntPtr.Zero) CloseHandle(processInfo.hThread);
            if (processInfo.hProcess != IntPtr.Zero) CloseHandle(processInfo.hProcess);
        }
        finally
        {
            if (environment != IntPtr.Zero) DestroyEnvironmentBlock(environment);
        }
    }

    private static void AddAccountRight(SecurityIdentifier sid, string right) =>
        ChangeAccountRight(sid, right, add: true);

    private static void RemoveAccountRight(SecurityIdentifier sid, string right) =>
        ChangeAccountRight(sid, right, add: false);

    private static void ChangeAccountRight(
        SecurityIdentifier sid,
        string right,
        bool add)
    {
        var attributes = new LsaObjectAttributes
        {
            Length = Marshal.SizeOf<LsaObjectAttributes>()
        };

        var openStatus = LsaOpenPolicy(
            IntPtr.Zero,
            ref attributes,
            PolicyLookupNames,
            out var policyHandle);
        if (openStatus != 0)
            throw new System.ComponentModel.Win32Exception(
                unchecked((int)LsaNtStatusToWinError(openStatus)),
                "Windows security policy could not be opened.");

        IntPtr sidPtr = IntPtr.Zero;
        IntPtr rightBuffer = IntPtr.Zero;
        try
        {
            var sidBytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(sidBytes, 0);
            sidPtr = Marshal.AllocHGlobal(sidBytes.Length);
            Marshal.Copy(sidBytes, 0, sidPtr, sidBytes.Length);

            rightBuffer = Marshal.StringToHGlobalUni(right);
            var rights = new[]
            {
                new LsaUnicodeString
                {
                    Buffer = rightBuffer,
                    Length = checked((ushort)(right.Length * 2)),
                    MaximumLength = checked((ushort)((right.Length + 1) * 2))
                }
            };

            var status = add
                ? LsaAddAccountRights(policyHandle, sidPtr, rights, 1)
                : LsaRemoveAccountRights(policyHandle, sidPtr, false, rights, 1);

            // STATUS_OBJECT_NAME_NOT_FOUND is harmless for idempotent restore.
            if (status != 0 && !( !add && LsaNtStatusToWinError(status) == 2 ))
            {
                throw new System.ComponentModel.Win32Exception(
                    unchecked((int)LsaNtStatusToWinError(status)),
                    add
                        ? "Windows could not restrict interactive sign-in for this account."
                        : "Windows could not restore interactive sign-in for this account.");
            }
        }
        finally
        {
            if (rightBuffer != IntPtr.Zero) Marshal.FreeHGlobal(rightBuffer);
            if (sidPtr != IntPtr.Zero) Marshal.FreeHGlobal(sidPtr);
            LsaClose(policyHandle);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LsaObjectAttributes
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LsaUnicodeString
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo
    {
        public int cb;
        public string? lpReserved;
        public string? lpDesktop;
        public string? lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwFillAttribute;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [DllImport("kernel32.dll")]
    private static extern uint WTSGetActiveConsoleSessionId();

    [DllImport("wtsapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WTSQueryUserToken(uint sessionId, out IntPtr token);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WTSDisconnectSession(
        IntPtr serverHandle,
        uint sessionId,
        [MarshalAs(UnmanagedType.Bool)] bool wait);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WTSLogoffSession(
        IntPtr serverHandle,
        uint sessionId,
        [MarshalAs(UnmanagedType.Bool)] bool wait);

    [DllImport("userenv.dll", SetLastError = true)]
    private static extern bool CreateEnvironmentBlock(
        out IntPtr environment,
        IntPtr token,
        bool inherit);

    [DllImport("userenv.dll", SetLastError = true)]
    private static extern bool DestroyEnvironmentBlock(IntPtr environment);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ImpersonateLoggedOnUser(IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool RevertToSelf();

    [DllImport("secur32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetUserNameEx(
        int nameFormat,
        StringBuilder userName,
        ref uint userNameSize);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessAsUser(
        IntPtr token,
        string? applicationName,
        StringBuilder commandLine,
        IntPtr processAttributes,
        IntPtr threadAttributes,
        bool inheritHandles,
        uint creationFlags,
        IntPtr environment,
        string? currentDirectory,
        ref StartupInfo startupInfo,
        out ProcessInformation processInformation);

    [DllImport("advapi32.dll", SetLastError = false)]
    private static extern uint LsaOpenPolicy(
        IntPtr systemName,
        ref LsaObjectAttributes objectAttributes,
        uint desiredAccess,
        out IntPtr policyHandle);

    [DllImport("advapi32.dll", SetLastError = false)]
    private static extern uint LsaAddAccountRights(
        IntPtr policyHandle,
        IntPtr accountSid,
        LsaUnicodeString[] userRights,
        uint countOfRights);

    [DllImport("advapi32.dll", SetLastError = false)]
    private static extern uint LsaRemoveAccountRights(
        IntPtr policyHandle,
        IntPtr accountSid,
        [MarshalAs(UnmanagedType.Bool)] bool allRights,
        LsaUnicodeString[] userRights,
        uint countOfRights);

    [DllImport("advapi32.dll")]
    private static extern uint LsaNtStatusToWinError(uint status);

    [DllImport("advapi32.dll")]
    private static extern uint LsaClose(IntPtr policyHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
}
