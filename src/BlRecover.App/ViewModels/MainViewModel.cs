using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using BlRecover;

namespace BlRecover.App
{
    internal sealed class LogLine
    {
        // Properties, not fields: these are bound from XAML.
        public LogLevel Level { get; }
        public string Text { get; }
        public LogLine(LogLevel level, string text) { Level = level; Text = text; }
    }

    internal sealed class DiskItem
    {
        public DiskInfoLite Info;
        public string Index => "#" + Info.Index;
        public string Title => string.IsNullOrWhiteSpace(Info.Model) ? ("Physical disk " + Info.Index) : Info.Model;
        public string Size => Fmt.HumanSize(Info.Size);

        /// <summary>Exposed as a property so XAML can bind it (WPF cannot see public fields).</summary>
        public bool IsBoot => Info.IsBoot;

        public string Subtitle
        {
            get
            {
                string s = (string.IsNullOrWhiteSpace(Info.BusType) ? "" : Info.BusType + "  ") +
                          Info.BytesPerSector + "B sectors  " + Fmt.HumanSize(Info.Size);
                if (!string.IsNullOrWhiteSpace(Info.Serial)) s += "   SN " + Info.Serial;
                return s;
            }
        }
    }

    internal sealed class RelayCommand : ICommand
    {
        private readonly Func<object, bool> _can;
        private readonly Action<object> _run;
        public RelayCommand(Action<object> run, Func<object, bool> can = null) { _run = run; _can = can; }
        public bool CanExecute(object p) { return _can == null || _can(p); }
        public void Execute(object p) { _run(p); }
        public event EventHandler CanExecuteChanged;
        public void Raise() { var h = CanExecuteChanged; if (h != null) h(this, EventArgs.Empty); }
    }

    internal sealed class MainViewModel : INotifyPropertyChanged
    {
        private readonly ObservableCollection<DiskItem> _disks = new ObservableCollection<DiskItem>();
        private readonly ObservableCollection<RecoveredVolume> _volumes = new ObservableCollection<RecoveredVolume>();
        private readonly ObservableCollection<PartitionRow> _partitions = new ObservableCollection<PartitionRow>();
        private readonly ObservableCollection<LogLine> _log = new ObservableCollection<LogLine>();
        private readonly List<string> _pendingLog = new List<string>();

        private DiskItem _selectedDisk;
        private DiskReport _report;
        private bool _isBusy;
        private string _status = "Select a disk on the left to begin.";
        private double _progress;
        private bool _logExpanded = true;
        private bool _scanWholeDevice;
        private int _alignKb = 1024;
        private int _maxOffsetMb = 0;
        private RecoveredVolume _selectedVolume;
        private string _firstLbaText = "";
        private string _lastLbaText = "";
        private string _partitionName = "Recovered BitLocker";
        private bool _hasKey;
        private bool _understands;
        private bool _force;
        private string _backupDir;

        public MainViewModel()
        {
            Log.Emitted += OnLog;
            _backupDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "blrecover-backups");

            RefreshDisksCommand = new RelayCommand(_ => RefreshDisks());
            InspectCommand = new RelayCommand(_ => Inspect(), _ => CanInspect());
            ScanCommand = new RelayCommand(_ => _ = ScanAsync(), _ => CanScan());
            RestoreFromBackupCommand = new RelayCommand(_ => _ = RestoreFromBackupAsync(), _ => CanRunRestoreFromBackup());
            AddEntryCommand = new RelayCommand(_ => _ = AddEntryAsync(), _ => CanAddEntry());
            BackupOnlyCommand = new RelayCommand(_ => BackupOnly(), _ => CanInspect());
            SelfTestCommand = new RelayCommand(_ => RunSelfTest());
            DiagnoseCommand = new RelayCommand(_ => RunDiagnose(), _ => !_isBusy);
            ReloadCommand = new RelayCommand(_ => Inspect());
            ElevateCommand = new RelayCommand(_ => RelaunchElevated());
            ToggleLogCommand = new RelayCommand(_ => LogExpanded = !LogExpanded);
            ClearLogCommand = new RelayCommand(_ => _log.Clear());
            CopyLogCommand = new RelayCommand(_ => CopyLog());
            CopyPlanCommand = new RelayCommand(_ => CopyPlan(), _ => SelectedVolume != null);
            NavigateRestoreCommand = new RelayCommand(_ => SelectedTab = 2, _ => SelectedVolume != null);
        }

        // ------------------------------------------------------------ state

        public ObservableCollection<DiskItem> Disks => _disks;
        public ObservableCollection<RecoveredVolume> Volumes => _volumes;
        public ObservableCollection<PartitionRow> Partitions => _partitions;
        public ObservableCollection<LogLine> LogLines => _log;

        public DiskItem SelectedDisk
        {
            get { return _selectedDisk; }
            set
            {
                if (!Set(ref _selectedDisk, value)) return;
                Report = null;
                Volumes.Clear();
                Partitions.Clear();
                SelectedVolume = null;
                Status = value == null
                    ? "Select a disk on the left to begin."
                    : "Disk " + value.Info.Index + " selected. Click Inspect.";
                // Backs the restore-gpt override checkbox, which only appears for the boot disk.
                OnPropertyChanged(nameof(SelectedIsBoot));
                RaiseCommands();
            }
        }

        public DiskReport Report
        {
            get { return _report; }
            private set
            {
                if (!Set(ref _report, value)) return;
                Partitions.Clear();
                if (value != null) foreach (PartitionRow p in value.PartitionList) Partitions.Add(p);
                OnPropertyChanged(nameof(HasReport));
                OnPropertyChanged(nameof(HealthText));
                OnPropertyChanged(nameof(RecoveryHint));
                OnPropertyChanged(nameof(MbrSummary));
                OnPropertyChanged(nameof(PrimaryGptSummary));
                OnPropertyChanged(nameof(BackupGptSummary));
                OnPropertyChanged(nameof(CanRestoreFromBackup));
            }
        }

        public bool HasReport => _report != null;

        // ---- pass-throughs so XAML never has to bind into DiskReport's members directly ----
        public string HealthText => _report?.HealthText ?? "No disk inspected yet";
        public string RecoveryHint => _report?.RecoveryHint;
        public string MbrSummary => _report?.MbrSummary ?? "";
        public string PrimaryGptSummary => _report?.PrimaryGptSummary ?? "";
        public string BackupGptSummary => _report?.BackupGptSummary ?? "";
        public bool CanRestoreFromBackup => _report != null && _report.CanRestoreFromBackup;

        public bool IsBusy
        {
            get { return _isBusy; }
            set { if (Set(ref _isBusy, value)) OnPropertyChanged(nameof(IsIdle)); }
        }

        public bool IsIdle => !_isBusy;

        public string Status
        {
            get { return _status; }
            set { Set(ref _status, value); }
        }

        public double Progress
        {
            get { return _progress; }
            set { Set(ref _progress, value); }
        }

        public bool LogExpanded
        {
            get { return _logExpanded; }
            set { if (Set(ref _logExpanded, value)) OnPropertyChanged(nameof(IsLogTall)); }
        }

        public bool IsLogTall => _logExpanded;

        public bool ScanWholeDevice
        {
            get { return _scanWholeDevice; }
            set { Set(ref _scanWholeDevice, value); }
        }

        public int AlignKb
        {
            get { return _alignKb; }
            set { Set(ref _alignKb, value); }
        }

        public int MaxOffsetMb
        {
            get { return _maxOffsetMb; }
            set { Set(ref _maxOffsetMb, value); }
        }

        public string BackupDirectory
        {
            get { return _backupDir; }
            set { Set(ref _backupDir, value); }
        }

        public bool IsElevated => Privileges.Elevated;
        public bool CanWrite => Privileges.CanUseRawDisks;

        /// <summary>
        /// True when the selected disk is the boot disk. The restore-gpt path refuses to write
        /// there without an explicit override, so its checkbox is only shown when it applies.
        /// </summary>
        public bool SelectedIsBoot { get { return _selectedDisk != null && _selectedDisk.Info.IsBoot; } }

        public RecoveredVolume SelectedVolume
        {
            get { return _selectedVolume; }
            set
            {
                if (!Set(ref _selectedVolume, value)) return;
                if (value != null)
                {
                    FirstLbaText = value.StartLba.ToString();
                    LastLbaText = value.SuggestedLastLba.ToString();
                }
                OnPropertyChanged(nameof(SelectedVolumeSummary));
                RaiseCommands();
            }
        }

        public string SelectedVolumeSummary
        {
            get
            {
                if (_selectedVolume == null) return null;
                return "LBA " + _selectedVolume.StartLba + " .. " + _selectedVolume.SuggestedLastLba +
                       "   (" + _selectedVolume.SuggestedSize + ")";
            }
        }

        public string FirstLbaText
        {
            get { return _firstLbaText; }
            set
            {
                if (Set(ref _firstLbaText, value))
                {
                    OnPropertyChanged(nameof(ComputedSizeText));
                    RaiseCommands();
                }
            }
        }

        public string LastLbaText
        {
            get { return _lastLbaText; }
            set
            {
                if (Set(ref _lastLbaText, value))
                {
                    OnPropertyChanged(nameof(ComputedSizeText));
                    RaiseCommands();
                }
            }
        }

        public string ComputedSizeText
        {
            get
            {
                ulong f, l;
                if (!ulong.TryParse(FirstLbaText, out f) || !ulong.TryParse(LastLbaText, out l) || l < f)
                    return "Enter a valid LBA range";
                long bytes = (long)(l - f + 1) * (SelectedDisk != null ? SelectedDisk.Info.BytesPerSector : 512);
                return Fmt.HumanSize(bytes) + "  (" + (l - f + 1) + " sectors)";
            }
        }

        public string PartitionName
        {
            get { return _partitionName; }
            set { Set(ref _partitionName, value); }
        }

        public bool HasKey
        {
            get { return _hasKey; }
            set { if (Set(ref _hasKey, value)) RaiseCommands(); }
        }

        public bool Understands
        {
            get { return _understands; }
            set { if (Set(ref _understands, value)) RaiseCommands(); }
        }

        public bool Force
        {
            get { return _force; }
            set { Set(ref _force, value); }
        }

        private int _selectedTab;
        public int SelectedTab
        {
            get { return _selectedTab; }
            set { Set(ref _selectedTab, value); }
        }

        /// <summary>Accurate state: elevation alone is not enough, SeManageVolume must be on too.</summary>
        public string ElevationText => Privileges.StatusText();

        public string ElevationBrushKey
        {
            get
            {
                if (!Privileges.Elevated) return "WarnBrush";
                return Privileges.ManageVolumeEnabled ? "GoodBrush" : "BadBrush";
            }
        }

        public string ElevationHelp => Privileges.StatusHelp();

        public bool ShowElevateButton => !Privileges.CanUseRawDisks;

        // ------------------------------------------------------------ commands

        public RelayCommand RefreshDisksCommand { get; }
        public RelayCommand InspectCommand { get; }
        public RelayCommand ScanCommand { get; }
        public RelayCommand RestoreFromBackupCommand { get; }
        public RelayCommand AddEntryCommand { get; }
        public RelayCommand BackupOnlyCommand { get; }
        public RelayCommand SelfTestCommand { get; }
        public RelayCommand DiagnoseCommand { get; }
        public RelayCommand ReloadCommand { get; }
        public RelayCommand ElevateCommand { get; }
        public RelayCommand ToggleLogCommand { get; }
        public RelayCommand ClearLogCommand { get; }
        public RelayCommand CopyLogCommand { get; }
        public RelayCommand CopyPlanCommand { get; }
        public RelayCommand NavigateRestoreCommand { get; }

        private bool CanInspect() => !_isBusy && _selectedDisk != null;
        private bool CanScan() => !_isBusy && _selectedDisk != null;

        private bool CanRunRestoreFromBackup()
        {
            return !_isBusy && Privileges.CanUseRawDisks && _report != null && _report.CanRestoreFromBackup;
        }

        private bool CanAddEntry()
        {
            return !_isBusy && Privileges.CanUseRawDisks && _selectedVolume != null
                   && ulong.TryParse(FirstLbaText, out ulong f) && ulong.TryParse(LastLbaText, out ulong l) && l >= f;
        }

        private void RaiseCommands()
        {
            RefreshDisksCommand.Raise();
            InspectCommand.Raise();
            ScanCommand.Raise();
            RestoreFromBackupCommand.Raise();
            AddEntryCommand.Raise();
            BackupOnlyCommand.Raise();
            SelfTestCommand.Raise();
            ReloadCommand.Raise();
            CopyPlanCommand.Raise();
            NavigateRestoreCommand.Raise();
        }

        // ------------------------------------------------------------ actions

        public void RefreshDisks()
        {
            _disks.Clear();
            try
            {
                foreach (DiskInfoLite d in RecoveryService.ListDisks()) _disks.Add(new DiskItem { Info = d });
                Status = _disks.Count + " physical disk(s) found. " + Privileges.StatusText() + ".";
            }
            catch (Exception ex)
            {
                Status = "Could not enumerate disks: " + ex.Message;
                Out.Bad("  " + ex.Message);
            }
        }

        /// <summary>Adds a synthetic image as a selectable "disk" (demo / rehearsal mode).</summary>
        public void DemoAddDisk(string imagePath)
        {
            var f = new FileInfo(imagePath);
            _disks.Add(new DiskItem
            {
                Info = new DiskInfoLite
                {
                    Index = 900,
                    DevicePath = imagePath,
                    Model = "DEMO: " + Path.GetFileName(imagePath),
                    Serial = "DEMO0001",
                    BusType = "file",
                    Size = f.Length,
                    BytesPerSector = 512,
                    SectorsNote = "synthetic image - nothing here is a real drive"
                }
            });
            RaiseCommands();
        }

        public void Inspect()
        {
            if (_selectedDisk == null) return;
            try
            {
                DiskReport r = RecoveryService.Inspect(_selectedDisk.Info, false);
                Out.Title("Disk " + r.Index + " - " + r.Model);
                Out.Indent("serial " + r.Serial + "   " + r.Size + "   " + r.SectorSize);
                Out.Indent("LBA 0  " + r.MbrSummary);
                Out.Indent(r.PrimaryGptSummary);
                Out.Indent(r.BackupGptSummary);
                foreach (string s in r.GptDifferences) Out.Warn("  GPT copies differ: " + s);
                if (r.RecoveryHint != null) Out.Info("  " + r.RecoveryHint);
                Report = r;
                Status = r.HealthText;
                SelectedTab = 0;
            }
            catch (Exception ex)
            {
                Status = "Inspect failed: " + ex.Message;
                Out.Bad("  inspect failed: " + ex.Message);
            }
            RaiseCommands();
        }

        public async Task ScanAsync()
        {
            if (_selectedDisk == null) return;
            DiskInfoLite info = _selectedDisk.Info;
            bool whole = _scanWholeDevice;
            int align = _alignKb, max = _maxOffsetMb;

            IsBusy = true;
            Progress = 0;
            Volumes.Clear();
            SelectedVolume = null;
            RaiseCommands();
            Out.Title("Scanning disk " + info.Index + " for deleted volume headers");
            Out.Dim("  alignment " + align + " KiB, " + (whole ? "whole device" : "unallocated space only"));

            var progress = new Progress<string>(s => { Progress += 4; if (Progress > 90) Progress = 90; });
            try
            {
                ScanReport rep = await RecoveryService.ScanAsync(info, whole, align, max, progress, CancellationToken.None);
                Progress = 100;

                Out.Dim("  scanned " + rep.Scanned + " in " + rep.Duration + ", " + rep.ReadErrors + " read error(s)");
                if (rep.DeletedCandidates == 0)
                {
                    Out.Warn("  No filesystem or BitLocker volume header found in unallocated space.");
                    Out.Dim("  If the space was also formatted or reused, the volume header is gone and the");
                    Out.Dim("  volume cannot be restored. Try turning on \"Scan the whole device\" or set");
                    Out.Dim("  alignment to 512 KiB for a much slower but exhaustive sweep.");
                    Status = "No deleted BitLocker volume found.";
                }
                else
                {
                    Out.Ok("  " + rep.DeletedCandidates + " candidate deleted volume(s) found.");
                    foreach (RecoveredVolume v in rep.Volumes) Volumes.Add(v);
                    Status = rep.DeletedCandidates + " recoverable volume(s) found.";
                }
                if (rep.InsideLivePartitions > 0)
                    Out.Dim("  " + rep.InsideLivePartitions + " BitLocker volume(s) sit inside live partitions (healthy).");

                SelectedTab = 1;
                if (Volumes.Count > 0) SelectedVolume = Volumes[0];
            }
            catch (Exception ex)
            {
                Status = "Scan failed: " + ex.Message;
                Out.Bad("  scan failed: " + ex.Message);
            }
            finally
            {
                IsBusy = false;
                Progress = 0;
                RaiseCommands();
            }
        }

        public async Task RestoreFromBackupAsync()
        {
            if (_selectedDisk == null || _report == null) return;
            if (!Privileges.CanUseRawDisks)
            {
                MessageBox.Show(Privileges.StatusHelp(), "Cannot write to a physical disk",
                                MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            if (!AskConsent("restore the primary GPT from the trailing backup")) return;

            IsBusy = true; RaiseCommands();
            Out.Title("Restore primary GPT from backup GPT");
            try
            {
                OperationResult r = await Task.Run(() => RecoveryService.RestoreFromBackup(
                    _selectedDisk.Info, _backupDir, _force, PromptConfirm)).ConfigureAwait(true);
                if (r.Success)
                {
                    Out.Ok("  done. " + r.Summary);
                    Status = "Primary GPT rebuilt from the backup copy.";
                    Inspect();
                }
                else
                {
                    foreach (string p in r.Problems) Out.Bad("  " + p);
                    Status = "Restore not performed.";
                }
            }
            catch (UserAbortException ex)
            {
                Out.Warn("  cancelled: " + ex.Message);
                Status = "Cancelled - nothing was written.";
            }
            catch (Exception ex)
            {
                Out.Bad("  restore failed: " + ex.Message);
                Status = "Restore failed: " + ex.Message;
            }
            finally { IsBusy = false; RaiseCommands(); }
        }

        public async Task AddEntryAsync()
        {
            if (_selectedDisk == null || _selectedVolume == null) return;
            ulong first, last;
            if (!ulong.TryParse(FirstLbaText, out first) || !ulong.TryParse(LastLbaText, out last) || last < first)
            {
                Status = "Enter a valid LBA range.";
                return;
            }
            if (!Privileges.CanUseRawDisks)
            {
                MessageBox.Show(Privileges.StatusHelp(), "Cannot write to a physical disk",
                                MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            if (!AskConsent("add a partition entry for LBA " + first + " .. " + last)) return;

            DiskInfoLite info = _selectedDisk.Info;
            string name = _partitionName;
            string dir = _backupDir;
            bool force = _force;

            IsBusy = true; RaiseCommands();
            Out.Title("Adding partition entry LBA " + first + " .. " + last);
            try
            {
                OperationResult r = await Task.Run(() => RecoveryService.AddPartitionEntry(
                    info, first, last, name, dir, force, PromptConfirm)).ConfigureAwait(true);
                if (r.Success)
                {
                    Out.Ok("  partition entry written.");
                    Status = "Partition entry written. Rescan or reboot, then unlock with BitLocker.";
                    Inspect();
                }
                else
                {
                    foreach (string p in r.Problems) Out.Bad("  " + p);
                    Status = "Nothing was written.";
                }
            }
            catch (UserAbortException ex)
            {
                Out.Warn("  cancelled: " + ex.Message);
                Status = "Cancelled - nothing was written.";
            }
            catch (Exception ex)
            {
                Out.Bad("  failed: " + ex.Message);
                Status = "Failed: " + ex.Message;
            }
            finally { IsBusy = false; RaiseCommands(); }
        }

        public void BackupOnly()
        {
            if (_selectedDisk == null) return;
            try
            {
                RecoveryService.CreateBackup(_selectedDisk.Info, _backupDir);
                Status = "Safety backup written to " + _backupDir;
            }
            catch (Exception ex)
            {
                Out.Bad("  backup failed: " + ex.Message);
                Status = "Backup failed: " + ex.Message;
            }
        }

        public void RunDiagnose()
        {
            Out.Title("Diagnostics (read-only)");
            try
            {
                // Everything Diagnose prints goes through Out, which the log picks up - so the
                // user can just hit "Copy log" and paste it into the conversation.
                int rc = Diagnose.Run();
                Status = "Diagnostics finished - use \"Copy log\" to paste the result.";
            }
            catch (Exception ex)
            {
                Out.Bad("  diagnose error: " + ex.Message);
                Status = "Diagnose failed: " + ex.Message;
            }
        }

        public void RunSelfTest()
        {
            Out.Title("Built-in self-test");
            try
            {
                int rc = SelfTest.Run();
                Status = rc == 0 ? "Self-test passed." : "Self-test FAILED - see log.";
            }
            catch (Exception ex)
            {
                Out.Bad("  self-test error: " + ex.Message);
            }
        }

        private bool AskConsent(string what)
        {
            if (!_hasKey)
            {
                MessageBox.Show("Tick \"I have the BitLocker password or 48-digit recovery key\" first.\n\n" +
                                "Restoring the partition table does not decrypt anything, but you will not be able " +
                                "to read the volume without a credential.", "Confirm first", MessageBoxButton.OK,
                                MessageBoxImage.Information);
                return false;
            }
            if (!_understands)
            {
                MessageBox.Show("Tick \"I understand this writes to the physical disk\" first.", "Confirm first",
                                MessageBoxButton.OK, MessageBoxImage.Information);
                return false;
            }
            return true;
        }

        /// <summary>Confirm gate handed to the engine. Runs on a background thread, so it posts to the UI thread.</summary>
        private void PromptConfirm(RawDisk disk, string action, string[] details)
        {
            bool ok = false;
            string token = Restorer.RequiredConfirmToken(disk);
            string path = disk.DevicePath, model = disk.Model, serial = disk.Serial;
            Application.Current.Dispatcher.Invoke(() =>
            {
                var w = new ConfirmWindow(token, path, model, serial, action, details);
                ok = w.ShowDialog() == true;
            });
            if (!ok) throw new UserAbortException("the confirmation dialog was cancelled");
        }

        /// <summary>
        /// The path of the running executable. Note that Assembly.Location returns the .dll for
        /// a .NET Core app, and asking the shell to elevate a .dll fails with "No application is
        /// associated with the specified file".
        /// </summary>
        internal static string CurrentExecutablePath()
        {
            try
            {
                string p = Environment.ProcessPath;
                if (!string.IsNullOrEmpty(p) &&
                    p.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) &&
                    File.Exists(p))
                    return p;
            }
            catch { }

            try
            {
                // Framework-dependent apphost: <assembly>.exe next to the dll we loaded.
                string name = System.Reflection.Assembly.GetEntryAssembly()?.GetName().Name;
                if (!string.IsNullOrEmpty(name))
                {
                    string candidate = System.IO.Path.Combine(AppContext.BaseDirectory, name + ".exe");
                    if (File.Exists(candidate)) return candidate;
                }
            }
            catch { }

            try
            {
                using (var me = Process.GetCurrentProcess())
                {
                    string m = me.MainModule?.FileName;
                    if (!string.IsNullOrEmpty(m) && m.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                        return m;
                }
            }
            catch { }

            return null;
        }

        private void RelaunchElevated()
        {
            string exe = CurrentExecutablePath();
            if (exe == null)
            {
                MessageBox.Show(
                    "Could not work out which executable this is.\n\n" +
                    "Close the app, open an Administrator command prompt, and run:\n\n" +
                    "    \"" + AppContext.BaseDirectory + "BlRecover.App.exe\"\n\n" +
                    "A safety net: use a context menu on the .exe and choose \"Run as administrator\".",
                    "Elevate failed", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = exe,
                    UseShellExecute = true,
                    Verb = "runas",
                    WorkingDirectory = AppContext.BaseDirectory
                });
                Application.Current.Shutdown();
            }
            catch (System.ComponentModel.Win32Exception ex)
            {
                MessageBox.Show(
                    "Windows refused to start an elevated copy.\n\n" +
                    "Attempted: \"" + exe + "\"\n\n" +
                    ex.Message + "\n\n" +
                    "This usually means the UAC prompt was declined. Right-click the .exe and choose " +
                    "\"Run as administrator\" instead, or launch it from an Administrator command prompt.",
                    "Elevate failed", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Could not restart elevated: " + ex.Message, "Elevate failed",
                                MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void CopyLog()
        {
            try
            {
                var sb = new System.Text.StringBuilder();
                foreach (LogLine l in _log) sb.AppendLine(l.Text);
                Clipboard.SetText(sb.ToString());
                Status = "Activity log copied to the clipboard (" + _log.Count + " lines).";
            }
            catch (Exception ex)
            {
                Status = "Could not copy the log: " + ex.Message;
            }
        }

        private void CopyPlan()
        {
            if (_selectedVolume == null) return;
            string cmd = "blrecover add-gpt --disk " + (_selectedDisk != null ? _selectedDisk.Info.Index : 0) +
                         " --first " + FirstLbaText + " --last " + LastLbaText +
                         " --name \"" + _partitionName + "\" --apply";
            try { Clipboard.SetText(cmd); Status = "Command copied to the clipboard."; }
            catch { Status = cmd; }
        }

        private void OnLog(LogLevel level, string text)
        {
            Application.Current?.Dispatcher.BeginInvoke(new Action(() =>
            {
                _log.Add(new LogLine(level, text));
                while (_log.Count > 2000) _log.RemoveAt(0);
            }));
        }

        // ------------------------------------------------------------ plumbing

        private bool Set<T>(ref T field, T value, [CallerMemberName] string name = null)
        {
            if (EqualityComparer<T>.Default.Equals(field, value)) return false;
            field = value;
            OnPropertyChanged(name);
            return true;
        }

        public event PropertyChangedEventHandler PropertyChanged;

        private void OnPropertyChanged([CallerMemberName] string name = null)
        {
            var h = PropertyChanged;
            if (h != null) h(this, new PropertyChangedEventArgs(name));
        }

        public void Boot()
        {
            RefreshDisks();
            Out.Title("BitLocker Partition Recovery");
            Out.Dim("  This tool restores PARTITION TABLES. It does not decrypt BitLocker and never handles keys.");
            Out.Dim("  Everything is read-only until you explicitly restore a partition entry.");
            OnPropertyChanged(nameof(IsElevated));
            OnPropertyChanged(nameof(CanWrite));
            OnPropertyChanged(nameof(ElevationText));
            OnPropertyChanged(nameof(ElevationBrushKey));
            OnPropertyChanged(nameof(ElevationHelp));
            OnPropertyChanged(nameof(ShowElevateButton));
            Out.Dim("  " + Privileges.StatusHelp());
        }
    }
}
