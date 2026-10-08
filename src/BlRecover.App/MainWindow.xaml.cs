using System;
using System.Collections.Specialized;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using BlRecover;

namespace BlRecover.App
{
    public partial class MainWindow : Window
    {
        private readonly MainViewModel _vm = new MainViewModel();

        public MainWindow()
        {
            InitializeComponent();
            DataContext = _vm;

            Loaded += (s, e) =>
            {
                _vm.Boot();
                LogScroll.ScrollChanged += LogScroll_ScrollChanged;
                _vm.LogLines.CollectionChanged += LogLines_CollectionChanged;
            };
        }

        private void LogLines_CollectionChanged(object sender, NotifyCollectionChangedEventArgs e)
        {
            if (e.Action == NotifyCollectionChangedAction.Add)
                LogScroll.ScrollToEnd();
        }

        private void LogScroll_ScrollChanged(object sender, ScrollChangedEventArgs e)
        {
            // keep pinned to the bottom unless the user scrolled up to read history
            if (e.ExtentHeightChange != 0 && !_pinned)
                LogScroll.ScrollToEnd();
        }

        private bool _pinned = true;
    }
}
