using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace BlRecover.App
{
    /// <summary>
    /// Final gate before anything is written. Deliberately knows nothing about the engine: the
    /// view model passes plain display data plus the token the operator must type back.
    /// </summary>
    public partial class ConfirmWindow : Window
    {
        private readonly string _token;

        public ConfirmWindow(string token, string devicePath, string model, string serial,
                             string action, string[] details)
        {
            InitializeComponent();

            _token = token ?? "";
            ActionText.Text = action;
            DeviceText.Text = devicePath;
            ModelText.Text = model;
            SerialText.Text = "Serial: " + (string.IsNullOrWhiteSpace(serial) ? "(none reported)" : serial);
            PromptText.Text = "This is the last step before anything is written to this disk. " +
                              "Anything other than the exact token cancels.";
            TokenText.Text = _token.Length > 0 ? _token : "(no token available)";

            Brush ink = (Brush)FindResource("InkStrongBrush");
            foreach (string d in details ?? new string[0])
            {
                Details.Items.Add(new TextBlock
                {
                    Text = d,
                    FontSize = 12.5,
                    TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(0, 1, 0, 1),
                    Foreground = ink
                });
            }

            var good = (Brush)FindResource("GoodBrush");
            var bad = (Brush)FindResource("BadBrush");
            var muted = (Brush)FindResource("InkMutedBrush");

            TokenBox.TextChanged += (s, e) =>
            {
                bool ok = TokenMatches(TokenBox.Text, _token);
                OkButton.IsEnabled = ok;
                // Say plainly whether it matches, instead of leaving a dead button to interpret.
                if (TokenBox.Text.Trim().Length == 0)
                {
                    MatchText.Text = "Waiting for the token.";
                    MatchText.Foreground = muted;
                }
                else if (ok)
                {
                    MatchText.Text = "Token matches. Write to disk is now enabled.";
                    MatchText.Foreground = good;
                }
                else
                {
                    MatchText.Text = "That does not match the token shown above. " +
                                     "Note this is the disk confirmation token, not your BitLocker recovery key.";
                    MatchText.Foreground = bad;
                }
            };
            OkButton.IsEnabled = false;
            MatchText.Text = "Waiting for the token.";
            MatchText.Foreground = muted;

            Loaded += (s, e) => { TokenBox.Focus(); };
        }

        /// <summary>
        /// Compares the typed text to the required token, ignoring case and the spacing/hyphen
        /// formatting people naturally add. It is still the right token: every character of it
        /// must be present, in order.
        /// </summary>
        private static bool TokenMatches(string typed, string token)
        {
            if (string.IsNullOrEmpty(token)) return false;
            return string.Equals(Normalise(typed), Normalise(token), StringComparison.OrdinalIgnoreCase);
        }

        private static string Normalise(string s)
        {
            if (s == null) return "";
            var sb = new System.Text.StringBuilder(s.Length);
            foreach (char c in s)
            {
                if (c == ' ' || c == '-' || c == '\t' || c == '\r' || c == '\n') continue;
                sb.Append(c);
            }
            return sb.ToString();
        }

        private void OnOk(object sender, RoutedEventArgs e)
        {
            DialogResult = true;
            Close();
        }

        private void OnCancel(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }
    }
}
