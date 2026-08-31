using System.IO;
using System.Windows;
using System.Windows.Threading;
using UsbAudit.Shared;

namespace UsbAudit.App;

public partial class App : Application
{
    private static readonly object LogLock = new();

    protected override void OnStartup(StartupEventArgs e)
    {
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += OnUnhandledException;

        base.OnStartup(e);

        try
        {
            StoragePaths.EnsureDirectories();
            WriteStartupLog("USB Audit dashboard starting.");

            var window = new MainWindow();
            MainWindow = window;
            window.Show();
            window.Activate();

            WriteStartupLog("USB Audit dashboard window opened successfully.");
        }
        catch (Exception ex)
        {
            WriteStartupLog("Dashboard startup failed: " + ex);
            MessageBox.Show(
                "USB Audit could not open the dashboard.\n\n" + ex.Message +
                "\n\nDiagnostic log: C:\\ProgramData\\UsbAudit\\Data\\ui-startup.log",
                "USB Audit startup error",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            Shutdown(1);
        }
    }

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        WriteStartupLog("Unhandled dashboard exception: " + e.Exception);
        MessageBox.Show(
            "USB Audit encountered a dashboard error. The background monitoring service is separate and may still be running.\n\n" +
            e.Exception.Message + "\n\nDiagnostic log: C:\\ProgramData\\UsbAudit\\Data\\ui-startup.log",
            "USB Audit error",
            MessageBoxButton.OK,
            MessageBoxImage.Error);
        e.Handled = true;
    }

    private static void OnUnhandledException(object sender, UnhandledExceptionEventArgs e)
    {
        WriteStartupLog("Unhandled application exception: " + e.ExceptionObject);
    }

    private static void WriteStartupLog(string message)
    {
        try
        {
            var directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "UsbAudit", "Data");
            Directory.CreateDirectory(directory);
            var path = Path.Combine(directory, "ui-startup.log");
            lock (LogLock)
            {
                File.AppendAllText(path, $"{DateTimeOffset.Now:O}  {message}{Environment.NewLine}");
            }
        }
        catch
        {
            // Startup diagnostics must never prevent the dashboard from opening.
        }
    }
}
