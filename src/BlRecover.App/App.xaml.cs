using System;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using BlRecover;

namespace BlRecover.App
{
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            // The engine writes both to the console and to Log.Emitted. In a GUI there is no
            // console, so silence the mirror and let the view model collect everything.
            Log.MirrorToConsole = false;
            base.OnStartup(e);

            // Must happen before any device is opened: being elevated is not enough, the
            // "Manage Volume" privilege has to be enabled in the process token as well.
            Privileges.EnableForRawDiskAccess();

            if (e.Args != null && e.Args.Any(a =>
                    string.Equals(a, "--ui-smoke-test", StringComparison.OrdinalIgnoreCase)))
            {
                DispatcherUnhandledException += (s, ex) =>
                {
                    UiSmokeTest.Say("  UNHANDLED: " + ex.Exception);
                    ex.Handled = true;
                };
                AppDomain.CurrentDomain.UnhandledException += (s, ex) =>
                    UiSmokeTest.Say("  FATAL: " + ex.ExceptionObject);
                int code = UiSmokeTest.Run(this);
                Shutdown(code);
                return;
            }

            if (e.Args != null && e.Args.Any(a =>
                    string.Equals(a, "--ui-demo", StringComparison.OrdinalIgnoreCase)))
            {
                DispatcherUnhandledException += (s, ex) =>
                {
                    UiSmokeTest.Say("  UNHANDLED: " + ex.Exception);
                    ex.Handled = true;
                };
                UiDemo.Run(this);
                return;   // the window stays open so it can be looked at
            }

            // normal start
            new MainWindow().Show();
        }
    }

    /// <summary>
    /// Fills the real window from a synthetic image so the whole flow can be seen and
    /// rehearsed without going anywhere near a real disk. Read-only: it never restores.
    /// </summary>
    internal static class UiDemo
    {
        public static void Run(Application app)
        {
            string img = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "blrecover-demo.img");
            UiSmokeTest.Say("demo: building a synthetic 1 GiB BitLocker image at " + img);
            ImageFactory.BuildFile(new ImageFactory.Spec
            {
                Path = img,
                SizeBytes = 1024L * 1024 * 1024,
                VolumeStartLba = 2048,
                VolumeSectors = (1024L * 1024 * 1024 / 512) - 2048 - 34,
                DestroyPrimaryGpt = true,
                Method = 0x8000,
                Protector = 0x0800
            });

            var win = new MainWindow();
            win.Show();
            var vm = (MainViewModel)win.DataContext;
            vm.Boot();

            // Add the image as if it were another disk.
            vm.DemoAddDisk(img);
            if (vm.Disks.Count > 0) vm.SelectedDisk = vm.Disks[vm.Disks.Count - 1];

            vm.Inspect();
            UiSmokeTest.Say("demo: inspect -> " + vm.Status);

            vm.ScanWholeDevice = false;
            vm.ScanAsync().ContinueWith(_ =>
            {
                UiSmokeTest.Say("demo: scan -> " + vm.Status + " (" + vm.Volumes.Count + " volume(s))");
                if (vm.Volumes.Count > 0)
                {
                    vm.SelectedTab = 1;
                    UiSmokeTest.Say("demo: showing the Scan tab with the recovered volume");
                }
            });
        }
    }

    /// <summary>
    /// Loads the real window for real and walks the visual tree. This is the only thing that
    /// catches runtime XAML failures - a missing StaticResource or a MaterialDesign theme
    /// resource throws when the tree is built, not when it compiles.
    /// </summary>
    internal static class UiSmokeTest
    {
        private static readonly System.Collections.Generic.List<string> Lines =
            new System.Collections.Generic.List<string>();

        public static void Say(string s)
        {
            Lines.Add(s);
            try { Console.WriteLine(s); } catch { }
            try { System.IO.File.AppendAllText(LogPath, s + Environment.NewLine); } catch { }
        }

        public static string LogPath
        {
            get
            {
                return System.IO.Path.Combine(System.IO.Path.GetTempPath(),
                                              "blrecover-ui-smoke.log");
            }
        }

        public static int Run(Application app)
        {
            int problems = 0;
            try
            {
                try { System.IO.File.Delete(LogPath); } catch { }
                Say("ui-smoke-test: building MainWindow...");
                var win = new MainWindow();
                win.Show();

                int controls = Walk(win, "window", ref problems);
                Say("  visual tree built: " + controls + " visual elements, " + problems + " problem(s)");

                // Force the view model through its main paths so bindings actually resolve.
                var vm = (MainViewModel)win.DataContext;
                vm.Boot();
                Say("  disks listed     : " + vm.Disks.Count);
                Say("  elevated         : " + vm.IsElevated);
                if (vm.Disks.Count > 0)
                {
                    vm.SelectedDisk = vm.Disks[0];
                    vm.Inspect();
                    Say("  inspect status   : " + vm.Status);
                    if (vm.Report != null)
                    {
                        Say("  partitions seen  : " + vm.Report.PartitionList.Count);
                        Say("  health           : " + vm.Report.HealthText);
                    }
                }

                var confirm = new ConfirmWindow("ABC12345", @"\\.\PhysicalDrive9", "TEST", "SERIAL1",
                                                "smoke test action", new[] { "detail one", "detail two" });
                // It has to be shown before its visual tree exists: a Window that was never
                // rendered has no visual children, so any walk of it finds nothing.
                confirm.Show();
                confirm.UpdateLayout();
                DispatcherFrameSettle();
                Say("  confirm dialog   : constructed and shown");
                problems += CheckConfirmDialog(confirm, "ABC12345");
                confirm.Close();

                problems += CheckLayout(win);

                // The relaunch path must be the .exe: asking the shell to elevate the .dll fails
                // with "No application is associated with the specified file".
                string exe = MainViewModel.CurrentExecutablePath();
                Say("  executable path  : " + (exe ?? "(could not resolve)"));
                bool okExe = exe != null
                             && exe.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                             && System.IO.File.Exists(exe);
                Say("  relaunch target  : " + (okExe ? "usable .exe" : "NOT USABLE"));
                if (!okExe) Say("  SMOKE TEST FAILED: the elevate button would still fail");

                win.Close();
                app.Shutdown();
            }
            catch (Exception ex)
            {
                problems++;
                Say("  SMOKE TEST FAILED: " + ex);
            }

            if (problems == 0) Say("UI SMOKE TEST PASSED");
            else Say("UI SMOKE TEST FAILED with " + problems + " problem(s)");

            try { System.IO.File.WriteAllLines(LogPath, Lines); } catch { }
            return problems == 0 ? 0 : 1;
        }

        /// <summary>
        /// Measures the real laid-out window. Building the visual tree proves the XAML parses; it
        /// does NOT prove the controls are reachable. A TabControl sitting in an Auto-sized grid row
        /// grows to its content, overflows the window and gets clipped - no exception, no missing
        /// element, and the "Write partition entry" button simply cannot be clicked. That shipped
        /// because this check did not exist, so now it does: every tab is selected in turn and every
        /// button is required to be inside the window, with the ones that carry the actual work
        /// additionally required to be reachable by scrolling.
        /// </summary>
        /// <summary>
        /// The confirmation gate is only meaningful if the operator can satisfy it. It once asked
        /// the user to "type the token below" while displaying no token at all, so the only way to
        /// pass it was to read the source and work out that the token is the last 8 characters of
        /// the disk serial. This asserts the token is on screen, that the button starts disabled,
        /// and that typing it - in any spacing or case - enables the write.
        /// </summary>
        private static int CheckConfirmDialog(ConfirmWindow w, string token)
        {
            int problems = 0;
            try
            {
                var shown = FindAll(w, typeof(TextBlock)).OfType<TextBlock>()
                              .Select(t => t.Text ?? "").FirstOrDefault(t => t.Trim() == token);
                if (shown == null)
                {
                    problems++;
                    Say("  confirm token   : NOT DISPLAYED - the operator cannot know what to type");
                }
                else
                {
                    Say("  confirm token   : displayed as '" + token + "'");
                }

                var box = FindAll(w, typeof(TextBox)).OfType<TextBox>().FirstOrDefault();
                Button ok = null;
                foreach (Button b in FindAll(w, typeof(Button)))
                    if (b.Content is string && ((string)b.Content).IndexOf("Write", StringComparison.OrdinalIgnoreCase) >= 0)
                        ok = b;

                if (box == null || ok == null)
                {
                    problems++;
                    Say("  confirm gate    : could not find the token box / write button");
                    return problems;
                }

                if (ok.IsEnabled)
                {
                    problems++;
                    Say("  confirm gate    : write button starts ENABLED - the gate is not a gate");
                }
                else
                {
                    Say("  confirm gate    : write button starts disabled");
                }

                box.Text = token.ToLowerInvariant().Insert(4, "-");   // wrong case, odd spacing
                w.UpdateLayout();
                if (!ok.IsEnabled)
                {
                    problems++;
                    Say("  confirm gate    : typing the token did NOT enable the write");
                }
                else
                {
                    Say("  confirm gate    : typing the token enables the write (case/format tolerant)");
                }

                box.Text = "definitely-not-the-token";
                w.UpdateLayout();
                if (ok.IsEnabled)
                {
                    problems++;
                    Say("  confirm gate    : a WRONG token still enabled the write");
                }
                else
                {
                    Say("  confirm gate    : a wrong token leaves the write disabled");
                }
            }
            catch (Exception ex)
            {
                problems++;
                Say("  confirm dialog check failed: " + ex.GetType().Name + ": " + ex.Message);
            }
            return problems;
        }

        private static int CheckLayout(Window win)
        {
            int problems = 0;
            try
            {
                var vm = (MainViewModel)win.DataContext;
                win.UpdateLayout();
                Say("  window size     : " + Math.Round(win.ActualWidth) + " x " + Math.Round(win.ActualHeight));

                var tabs = FindAll(win, typeof(TabControl));
                if (tabs.Count != 1)
                {
                    problems++;
                    Say("  expected exactly one TabControl, found " + tabs.Count);
                    return problems;
                }
                var tab = (TabControl)tabs[0];
                int tabCount = tab.Items.Count;
                Say("  tabs             : " + tabCount);

                for (int t = 0; t < tabCount; t++)
                {
                    tab.SelectedIndex = t;
                    vm.SelectedTab = t;
                    win.UpdateLayout();
                    DispatcherFrameSettle();

                    var clipped = new System.Collections.Generic.List<string>();
                    foreach (Button b in FindAll(win, typeof(Button)))
                    {
                        if (!IsInsideWindow(win, b)) clipped.Add(Describe(win, b));
                    }
                    if (clipped.Count == 0)
                    {
                        Say("  tab " + t + "             : every button inside the window");
                    }
                    else
                    {
                        problems += clipped.Count;
                        Say("  tab " + t + "             : " + clipped.Count + " button(s) CLIPPED: " +
                            string.Join("; ", clipped.ToArray()));
                    }
                }

                // The destructive action specifically. It must be reachable, and its tab must be
                // scrollable - otherwise a short window clips it permanently and the operator
                // simply cannot commit the restore.
                tab.SelectedIndex = 2;
                vm.SelectedTab = 2;
                win.UpdateLayout();
                DispatcherFrameSettle();

                Button write = null;
                foreach (Button b in FindAll(win, typeof(Button)))
                {
                    object c = b.Content;
                    if (c is string && ((string)c).IndexOf("Write partition entry", StringComparison.OrdinalIgnoreCase) >= 0)
                        write = b;
                }
                if (write == null)
                {
                    problems++;
                    Say("  write button    : NOT FOUND on the Restore tab");
                    return problems;
                }

                bool visible = IsInsideWindow(win, write);
                Say("  write button    : " + Describe(win, write) +
                    " -> " + (visible ? "visible without scrolling" : "BELOW THE FOLD"));
                if (!visible)
                {
                    problems++;
                    Say("  write button    : UNREACHABLE - the operator cannot commit the restore");
                }

                // The write buttons are pinned outside the scroller on purpose, so the requirement
                // is instead that they are inside the window AND that the tall cards above them
                // have somewhere to scroll. Content that overflows with no ScrollViewer is what
                // originally hid the button in the first place.
                var scrollers = FindAll(win, typeof(ScrollViewer));
                Say("  tab scroll area : " + scrollers.Count + " ScrollViewer(s) on the Restore tab");
                bool contentScrolls = false;
                string detail = "";
                foreach (ScrollViewer sv in scrollers)
                {
                    if (ReferenceEquals(sv, null)) continue;
                    try
                    {
                        if (sv.ScrollableHeight > 0)
                        {
                            contentScrolls = true;
                            detail = "content " + Math.Round(sv.ExtentHeight) + "px in a " +
                                     Math.Round(sv.ViewportHeight) + "px viewport";
                            break;
                        }
                    }
                    catch { }
                }
                Say("  content scrolls : " + (contentScrolls ? "yes, " + detail : "no (content fits, or no scroller)"));
                if (!contentScrolls)
                {
                    problems++;
                    Say("  content scrolls : the Restore tab content cannot scroll - long content will be clipped");
                }
            }
            catch (Exception ex)
            {
                problems++;
                Say("  layout check failed: " + ex.GetType().Name + ": " + ex.Message);
            }
            return problems;
        }

        /// <summary>Lets WPF finish arranging and applying the tab change before we measure.</summary>
        private static void DispatcherFrameSettle()
        {
            try
            {
                var frame = new System.Windows.Threading.DispatcherFrame();
                System.Windows.Threading.Dispatcher.CurrentDispatcher.BeginInvoke(
                    System.Windows.Threading.DispatcherPriority.ContextIdle,
                    new Action(() => frame.Continue = false));
                System.Windows.Threading.Dispatcher.PushFrame(frame);
            }
            catch { }
        }

        private static string Describe(Window win, Button b)
        {
            string label = b.Content is string ? ((string)b.Content) : (b.Name ?? "(button)");
            if (label.Length > 28) label = label.Substring(0, 28) + "...";
            return "'" + label + "' bottom=" + Math.Round(BottomOf(win, b)) + "/" + Math.Round(win.ActualHeight);
        }

        private static double BottomOf(Window win, FrameworkElement e)
        {
            try
            {
                return e.TransformToAncestor(win).TransformBounds(
                    new System.Windows.Rect(0, 0, e.ActualWidth, e.ActualHeight)).Bottom;
            }
            catch { return -1; }
        }

        private static bool IsInsideWindow(Window win, FrameworkElement e)
        {
            try
            {
                if (!e.IsVisible || e.ActualHeight <= 0) return true;   // collapsed / not realised
                System.Windows.Rect r = e.TransformToAncestor(win).TransformBounds(
                    new System.Windows.Rect(0, 0, e.ActualWidth, e.ActualHeight));
                return r.Top >= -1 && r.Bottom <= win.ActualHeight + 1;
            }
            catch { return true; }   // not in this visual tree; not this check's business
        }

        private static System.Collections.Generic.List<DependencyObject> FindAll(DependencyObject root, Type type)
        {
            var found = new System.Collections.Generic.List<DependencyObject>();
            Collect(root, type, found);
            return found;
        }

        private static void Collect(DependencyObject root, Type type, System.Collections.Generic.List<DependencyObject> into)
        {
            if (type.IsInstanceOfType(root)) into.Add(root);
            int n = VisualTreeHelper.GetChildrenCount(root);
            for (int i = 0; i < n; i++) Collect(VisualTreeHelper.GetChild(root, i), type, into);
        }

        private static int Walk(DependencyObject root, string name, ref int problems)
        {
            int count = 0;
            try
            {
                int child = VisualTreeHelper.GetChildrenCount(root);
                for (int i = 0; i < child; i++)
                {
                    DependencyObject c = VisualTreeHelper.GetChild(root, i);
                    count += 1 + Walk(c, name, ref problems);
                }
            }
            catch (Exception ex)
            {
                problems++;
                Say("  tree walk failed at " + name + ": " + ex.Message);
            }
            return count;
        }
    }
}
