using System.Windows;
using System.Windows.Controls;

namespace UsbAudit.App;

public partial class MainWindow
{
    private void Refresh_Click(object sender, RoutedEventArgs e)
    {
        RefreshData();
    }

    private void TransferSearchBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        ApplyTransferFilter();
    }

    private void DirectionFilter_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        ApplyTransferFilter();
    }
}