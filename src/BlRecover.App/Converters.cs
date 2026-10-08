using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using BlRecover;

namespace BlRecover.App
{
    /// <summary>true -&gt; Visible, false -&gt; Collapsed</summary>
    public sealed class BoolToVisibilityConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            bool v = value is bool b && b;
            if (parameter is string s && s == "invert") v = !v;
            return v ? Visibility.Visible : Visibility.Collapsed;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return value is Visibility vis && vis == Visibility.Visible;
        }
    }

    public sealed class InverseBoolToVisibilityConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            bool v = value is bool b && b;
            return v ? Visibility.Collapsed : Visibility.Visible;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return value is Visibility vis && vis == Visibility.Collapsed;
        }
    }

    /// <summary>Maps a log severity to a colour that reads well on the dark log panel.</summary>
    /// <summary>Resolves a resource key name to its brush, e.g. "GoodBrush" -&gt; the green brush.</summary>
    public sealed class ResourceKeyToBrushConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            string key = value as string;
            if (!string.IsNullOrEmpty(key))
            {
                try
                {
                    object res = Application.Current?.TryFindResource(key);
                    if (res is Brush b) return b;
                }
                catch { }
            }
            return new SolidColorBrush(Color.FromRgb(0x5C, 0x6B, 0x7A));
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotSupportedException();
        }
    }

    public sealed class LogLevelToBrushConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (!(value is LogLevel)) return new SolidColorBrush(Color.FromRgb(0xC8, 0xD6, 0xE2));
            switch ((LogLevel)value)
            {
                case LogLevel.Ok: return new SolidColorBrush(Color.FromRgb(0x6F, 0xD0, 0x9A));
                case LogLevel.Warn: return new SolidColorBrush(Color.FromRgb(0xF2, 0xC1, 0x66));
                case LogLevel.Bad: return new SolidColorBrush(Color.FromRgb(0xFF, 0x8A, 0x80));
                case LogLevel.Header:
                case LogLevel.Title: return new SolidColorBrush(Color.FromRgb(0x7E, 0xC4, 0xFF));
                case LogLevel.Dim: return new SolidColorBrush(Color.FromRgb(0x86, 0x97, 0xA6));
                default: return new SolidColorBrush(Color.FromRgb(0xC8, 0xD6, 0xE2));
            }
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotSupportedException();
        }
    }
}
