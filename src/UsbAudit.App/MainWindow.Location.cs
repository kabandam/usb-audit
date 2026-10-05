using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Threading;
using Windows.Devices.Geolocation;
using UsbAudit.Shared;

namespace UsbAudit.App;

public partial class MainWindow
{
    private readonly DispatcherTimer _locationTimer = new();
    private bool _locationBusy;

    private void InitializeLocationTracking()
    {
        _locationTimer.Interval = TimeSpan.FromMinutes(5);
        _locationTimer.Tick += async (_, _) => await CaptureLocationAsync();
        _locationTimer.Start();
        UpdateLocationControls();
        // Do not prompt automatically. Only the explicit button requests access.
        if (JsonStorage.LoadLocationState().Enabled) _ = CaptureLocationAsync();
    }

    private void UpdateLocationControls()
    {
        var state = JsonStorage.LoadLocationState();
        var unlocked = _connectionUnlocked
                       && DateTimeOffset.UtcNow < _connectionUnlockedUntil
                       && ConnectionSettingsGuard.Version == _verifiedPasswordVersion;
        EnableLocationButton.IsEnabled = unlocked && !state.Enabled;
        DisableLocationButton.IsEnabled = unlocked && state.Enabled;
        LocationStatusText.Text = !state.Enabled
            ? "Disabled. No precise coordinates are being collected or uploaded."
            : state.CapturedAt.HasValue
                ? $"Enabled • last permitted reading {state.CapturedAt.Value.LocalDateTime:dd MMM yyyy HH:mm} • accuracy {state.AccuracyMeters:0} m • {state.Status}"
                : $"Enabled • {state.Status}. Waiting for a Windows location reading.";
    }

    private async void EnableLocation_Click(object sender, RoutedEventArgs e)
    {
        if (!EnsureLocationSettingsUnlocked()) return;
        if (MessageBox.Show(this,
                "Enable background asset-location reporting while Smart Console is open? After Windows grants permission, the app will request a location about every five minutes and the agent will send the reading to CRECCOM's secure console. Only designated administrators may view it. You can disable this later.",
                "CRECCOM device location permission", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
            return;
        try
        {
            // Windows requires this call on the foreground UI thread and controls permission.
            var access = await Geolocator.RequestAccessAsync();
            if (access != GeolocationAccessStatus.Allowed)
            {
                LocationStatusText.Text = "Windows did not grant location access. Open Windows Location settings to review permission.";
                return;
            }
            JsonStorage.SaveLocationState(new EndpointLocationSnapshot { Enabled = true, Status = "awaiting_position" });
            UpdateLocationControls();
            await CaptureLocationAsync();
        }
        catch (Exception ex)
        {
            LocationStatusText.Text = "Location access unavailable: " + ex.Message;
        }
    }

    private void DisableLocation_Click(object sender, RoutedEventArgs e)
    {
        if (!EnsureLocationSettingsUnlocked()) return;
        // Remove the local precise sample immediately. Ingestion clears the server's copy.
        JsonStorage.SaveLocationState(new EndpointLocationSnapshot { Enabled = false, Status = "disabled" });
        RequestLocationUpload();
        UpdateLocationControls();
    }

    private void OpenLocationSettings_Click(object sender, RoutedEventArgs e)
    {
        if (!EnsureLocationSettingsUnlocked()) return;
        try { Process.Start(new ProcessStartInfo("ms-settings:privacy-location") { UseShellExecute = true }); }
        catch { LocationStatusText.Text = "Open Settings > Privacy & security > Location to review Windows location access."; }
    }

    private bool EnsureLocationSettingsUnlocked()
    {
        var valid = _connectionUnlocked
                    && DateTimeOffset.UtcNow < _connectionUnlockedUntil
                    && ConnectionSettingsGuard.Version == _verifiedPasswordVersion;
        if (valid) return true;

        LockConnectionSettings();
        ConnectionSettingsExpander.IsExpanded = true;
        ConnectionAccessMessage.Text = "Enter the administrator password to manage device location and asset security.";
        try { ConnectionAccessPasswordBox.Focus(); } catch { }
        return false;
    }

    private async Task CaptureLocationAsync()
    {
        if (_locationBusy || !JsonStorage.LoadLocationState().Enabled) return;
        _locationBusy = true;
        try
        {
            var locator = new Geolocator { DesiredAccuracyInMeters = 50 };
            var position = await locator.GetGeopositionAsync(TimeSpan.FromMinutes(2), TimeSpan.FromSeconds(12));
            if (!JsonStorage.LoadLocationState().Enabled) return; // Do not race an opt-out.
            var coordinate = position.Coordinate;
            var latitude = coordinate.Point.Position.Latitude;
            var longitude = coordinate.Point.Position.Longitude;
            var accuracy = coordinate.Accuracy;
            if (!double.IsFinite(latitude) || !double.IsFinite(longitude) || !double.IsFinite(accuracy) ||
                Math.Abs(latitude) > 90 || Math.Abs(longitude) > 180 || accuracy < 0) return;
            JsonStorage.SaveLocationState(new EndpointLocationSnapshot
            {
                Enabled = true, Status = "reporting", Latitude = latitude,
                Longitude = longitude, AccuracyMeters = accuracy,
                Source = "windows_geolocator", CapturedAt = coordinate.Timestamp
            });
            RequestLocationUpload();
        }
        catch (UnauthorizedAccessException)
        {
            JsonStorage.SaveLocationState(new EndpointLocationSnapshot { Enabled = false, Status = "permission_denied" });
            RequestLocationUpload();
        }
        catch (Exception)
        {
            // An unavailable positioning service must not break the dashboard or cloud sync.
            var state = JsonStorage.LoadLocationState();
            if (state.Enabled) { state.Status = "unavailable"; JsonStorage.SaveLocationState(state); }
        }
        finally { _locationBusy = false; UpdateLocationControls(); }
    }

    private static void RequestLocationUpload()
    {
        try { File.WriteAllText(StoragePaths.CloudSyncRequestPath, "authorized location status changed"); }
        catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    private void CheckLocationRefreshRequest()
    {
        try
        {
            if (!File.Exists(StoragePaths.LocationRefreshRequestPath)) return;
            File.Delete(StoragePaths.LocationRefreshRequestPath);
            if (JsonStorage.LoadLocationState().Enabled) _ = CaptureLocationAsync();
        }
        catch (IOException) { } catch (UnauthorizedAccessException) { }
    }
}
