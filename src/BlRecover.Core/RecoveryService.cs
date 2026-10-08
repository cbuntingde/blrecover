using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace BlRecover
{
    // ---------------------------------------------------------------- view models

    internal enum TableHealth
    {
        Unknown,
        GptHealthy,
        GptPrimaryBroken,       // backup is intact - the original layout is recoverable
        GptBothBroken,
        GptNoEntries,
        Mbr,
        Blank
    }

    // These three are bound directly by WPF, so every member is a PROPERTY: the WPF binding
    // engine cannot see public fields.

    internal sealed class PartitionRow
    {
        public int Slot { get; set; }
        public string Range { get; set; } = "";
        public string Size { get; set; } = "";
        public string Name { get; set; } = "";
        public string Type { get; set; } = "";
        public bool OutOfBounds { get; set; }
    }

    internal sealed class RecoveredVolume
    {
        public ulong StartLba { get; set; }
        public long ByteOffset { get; set; }
        public string Variant { get; set; } = "";
        public string VolumeGuid { get; set; } = "";
        public string Encryption { get; set; } = "";
        public string Created { get; set; } = "";
        public int BlocksReadable { get; set; }
        public string EncryptedSize { get; set; } = "";
        public string Protectors { get; set; } = "";
        public string Credential { get; set; } = "";
        public string Note { get; set; } = "";
        public bool OnCleanBoundary { get; set; } = true;
        public bool InsideLivePartition { get; set; }
        public VolumeKind Kind { get; set; }

        public ulong SuggestedLastLba { get; set; }
        public long SuggestedSizeBytes { get; set; }
        public string SuggestedSize { get; set; } = "";
        public bool SizeFromMetadata { get; set; }
    }

    internal sealed class DiskReport
    {
        public int Index { get; set; }
        public string DevicePath { get; set; } = "";
        public string Model { get; set; } = "";
        public string Serial { get; set; } = "";
        public string Size { get; set; } = "";
        public string SectorSize { get; set; } = "";
        public bool CanWrite { get; set; }
        public string ReadOnlyReason { get; set; } = "";
        public bool IsBoot { get; set; }
        public TableHealth Health { get; set; }
        public string HealthText { get; set; } = "";
        public string MbrSummary { get; set; } = "";
        public string PrimaryGptSummary { get; set; } = "";
        public string BackupGptSummary { get; set; } = "";
        public string RecoveryHint { get; set; }
        public bool CanRestoreFromBackup { get; set; }
        public bool IsGpt { get; set; }
        public bool PrimaryUsable { get; set; }
        public bool BackupUsable { get; set; }
        public List<PartitionRow> PartitionList { get; } = new List<PartitionRow>();
        public List<string> GptDifferences { get; } = new List<string>();
    }

    internal sealed class ScanReport
    {
        public int DeletedCandidates;
        public int InsideLivePartitions;
        public int OrphanMetadataBlocks;
        public string Scanned;
        public string Duration;
        public int ReadErrors;
        public readonly List<RecoveredVolume> Volumes = new List<RecoveredVolume>();
    }

    internal sealed class OperationResult
    {
        public bool Success;
        public string Summary;
        public readonly List<string> Problems = new List<string>();
        public readonly List<string> Warnings = new List<string>();
        public string BackupDirectory;
    }

    // ---------------------------------------------------------------- service

    /// <summary>
    /// Everything the WPF front end needs, expressed without any UI types. Long operations are
    /// asynchronous and report progress through <see cref="IProgress{T}"/>.
    /// </summary>
    internal static class RecoveryService
    {
        public static List<DiskInfoLite> ListDisks()
        {
            return DiskList.Enumerate();
        }

        private static RawDisk Open(DiskInfoLite info, bool forWrite)
        {
            return RawDisk.OpenDevice(info.Index, info.DevicePath, info.Model, info.Serial,
                                      info.BusType, info.IsBoot, info.Size, info.BytesPerSector, forWrite);
        }

        public static DiskReport Inspect(DiskInfoLite info, bool forWrite)
        {
            var r = new DiskReport();
            r.Index = info.Index;
            r.DevicePath = info.DevicePath;
            r.Model = info.Model;
            r.Serial = info.Serial;
            r.Size = Fmt.HumanSize(info.Size);
            r.SectorSize = info.BytesPerSector + " B";
            r.IsBoot = info.IsBoot;

            using (RawDisk d = Open(info, forWrite))
            {
                r.CanWrite = d.CanWrite;
                r.ReadOnlyReason = d.ReadOnlyReason;
                MbrDisk mbr = MbrDisk.Read(d);
                GptImage primary = Gpt.ReadPrimary(d);
                GptImage backup = Gpt.ReadBackup(d);

                r.IsGpt = (primary != null && primary.Header.SignatureOk) || (backup != null && backup.Header.SignatureOk);
                r.PrimaryUsable = primary != null && primary.Usable;
                r.BackupUsable = backup != null && backup.Usable;
                r.CanRestoreFromBackup = r.BackupUsable && (!r.PrimaryUsable || !TablesMatch(primary, backup));

                r.MbrSummary = SummariseMbr(mbr, d);
                r.PrimaryGptSummary = SummariseGpt(primary, d, "primary GPT");
                r.BackupGptSummary = SummariseGpt(backup, d, "backup GPT");

                foreach (string s in Gpt.Compare(primary, backup, d)) r.GptDifferences.Add(s);

                if (r.PrimaryUsable)
                {
                    foreach (GptEntry e in primary.Entries)
                    {
                        if (!e.InUse) continue;
                        r.PartitionList.Add(new PartitionRow
                        {
                            Slot = e.SlotIndex,
                            Range = e.FirstLba + " .. " + e.LastLba,
                            Size = Fmt.HumanSize((long)e.SectorCount * d.BytesPerSector),
                            Name = string.IsNullOrEmpty(e.Name) ? "(unnamed)" : e.Name,
                            Type = GptTypes.Name(e.TypeGuid),
                            OutOfBounds = e.LastLba < e.FirstLba ||
                                          e.FirstLba < primary.Header.FirstUsableLba ||
                                          e.LastLba > primary.Header.LastUsableLba
                        });
                    }
                }
                else if (r.BackupUsable)
                {
                    foreach (GptEntry e in backup.Entries)
                    {
                        if (!e.InUse) continue;
                        r.PartitionList.Add(new PartitionRow
                        {
                            Slot = e.SlotIndex,
                            Range = e.FirstLba + " .. " + e.LastLba,
                            Size = Fmt.HumanSize((long)e.SectorCount * d.BytesPerSector),
                            Name = string.IsNullOrEmpty(e.Name) ? "(backup copy) " + e.Name : e.Name,
                            Type = GptTypes.Name(e.TypeGuid)
                        });
                    }
                }
                else if (!r.IsGpt)
                {
                    for (int i = 0; i < mbr.Entries.Count; i++)
                    {
                        MbrEntry e = mbr.Entries[i];
                        if (!e.InUse) continue;
                        r.PartitionList.Add(new PartitionRow
                        {
                            Slot = i,
                            Range = e.StartLba + " .. " + (e.StartLba + e.SectorCount - 1),
                            Size = Fmt.HumanSize((long)e.SectorCount * d.BytesPerSector),
                            Name = e.TypeName(),
                            Type = "MBR 0x" + e.Type.ToString("X2", System.Globalization.CultureInfo.InvariantCulture)
                        });
                    }
                }

                // health verdict
                if (r.IsGpt && r.PrimaryUsable && r.BackupUsable)
                {
                    if (r.GptDifferences.Count > 0)
                    {
                        r.Health = TableHealth.GptHealthy;
                        r.HealthText = "GPT valid, but the two copies disagree";
                        r.RecoveryHint = "The backup copy lists partitions the primary copy does not. " +
                                         "Restoring from the backup is usually the cleanest fix.";
                    }
                    else if (r.PartitionList.Count == 0)
                    {
                        r.Health = TableHealth.GptNoEntries;
                        r.HealthText = "GPT valid but empty - every partition was deleted";
                        r.RecoveryHint = "The partition table is healthy but has no entries, which is exactly " +
                                         "what `diskpart clean` leaves behind. Scan for the BitLocker volume and " +
                                         "add a partition entry for it.";
                    }
                    else
                    {
                        r.Health = TableHealth.GptHealthy;
                        r.HealthText = "GPT healthy - " + r.PartitionList.Count + " partition(s)";
                        r.RecoveryHint = null;
                    }
                }
                else if (r.IsGpt && !r.PrimaryUsable && r.BackupUsable)
                {
                    r.Health = TableHealth.GptPrimaryBroken;
                    r.HealthText = "Primary GPT destroyed, trailing backup intact";
                    r.RecoveryHint = "Excellent news: the original partition layout still exists at the end of " +
                                     "the disk. Use \"Restore from backup GPT\" - it will bring every partition " +
                                     "back exactly as it was, no guessing needed.";
                }
                else if (r.IsGpt && r.PrimaryUsable && !r.BackupUsable)
                {
                    r.Health = TableHealth.GptBothBroken;
                    r.HealthText = "Primary GPT valid, trailing backup missing";
                    r.RecoveryHint = "The backup copy at the end of the disk is gone. The table can still be " +
                                     "rebuilt from the primary copy, but there is no safety net.";
                }
                else if (r.IsGpt)
                {
                    r.Health = TableHealth.GptBothBroken;
                    r.HealthText = "Both GPT copies are unreadable";
                    r.RecoveryHint = "The partition table is destroyed. Scan unallocated space for the BitLocker " +
                                     "volume header and recreate an entry from the metadata.";
                }
                else if (!mbr.HasBootSignature && !mbr.HasCode)
                {
                    r.Health = TableHealth.Blank;
                    r.HealthText = "LBA 0 is blank - no partition table at all";
                    r.RecoveryHint = "Scan for the BitLocker volume header, then create a partition from its " +
                                     "metadata.";
                }
                else
                {
                    r.Health = TableHealth.Mbr;
                    r.HealthText = "MBR partitioned";
                    r.RecoveryHint = null;
                }
            }
            return r;
        }

        private static bool TablesMatch(GptImage a, GptImage b)
        {
            if (a == null || b == null || !a.Usable || !b.Usable) return false;
            return Gpt.Compare(a, b, null).Count == 0;
        }

        public static async Task<ScanReport> ScanAsync(DiskInfoLite info, bool wholeDevice, int alignKb,
                                                      int maxOffsetMb, IProgress<string> progress,
                                                      CancellationToken cancel)
        {
            var report = new ScanReport();
            var sw = System.Diagnostics.Stopwatch.StartNew();
            using (RawDisk d = Open(info, false))
            {
                MbrDisk mbr = MbrDisk.Read(d);
                GptImage primary = Gpt.ReadPrimary(d);
                GptImage backup = Gpt.ReadBackup(d);
                List<LbaRange> inUse = Scanner.CollectInUse(d, primary, backup, mbr);
                bool isGpt = (primary != null && primary.Header.SignatureOk)
                          || (backup != null && backup.Header.SignatureOk)
                          || mbr.IsProtectiveForGpt;

                var opt = new ScanOptions
                {
                    ScanWholeDevice = wholeDevice,
                    Alignment = Math.Max(512, alignKb * 1024),
                    MaxOffset = (ulong)Math.Max(0, maxOffsetMb) * 1024UL * 1024UL,
                    Progress = progress != null
                };

                ScanResult res = await Task.Run(
                    () => Scanner.Scan(d, inUse, opt, s => { if (progress != null) progress.Report(s); }),
                    cancel).ConfigureAwait(false);

                report.DeletedCandidates = res.VolumeHeaders.Count;
                report.InsideLivePartitions = res.InUse.Count;
                report.OrphanMetadataBlocks = res.OrphanMetadataBlocks.Count;
                report.Scanned = Fmt.HumanSize(res.BytesScanned);
                report.ReadErrors = res.ReadErrors;

                foreach (FveHit h in res.InUse)
                {
                    RecoveredVolume v = Describe(d, h, false, isGpt);
                    v.InsideLivePartition = true;
                    report.Volumes.Add(v);
                }
                foreach (FveHit h in res.VolumeHeaders)
                    report.Volumes.Add(Describe(d, h, true, isGpt));
            }
            sw.Stop();
            report.Duration = sw.Elapsed.TotalSeconds.ToString("0.0", System.Globalization.CultureInfo.InvariantCulture) + " s";
            return report;
        }

        private static RecoveredVolume Describe(RawDisk d, FveHit h, bool orphan, bool isGpt)
        {
            var v = new RecoveredVolume();
            v.StartLba = h.Lba;
            v.ByteOffset = h.Offset;
            v.OnCleanBoundary = h.OnCleanBoundary;
            v.Kind = h.Kind;

            // An unencrypted volume is the easy case and needs none of the FVE machinery.
            if (h.Kind != VolumeKind.Fve)
            {
                return DescribePlainVolume(d, h, v, isGpt);
            }

            v.Variant = h.Variant == FveVariant.ToGo ? "BitLocker To Go (FAT)"
                      : h.Variant == FveVariant.Vista ? "Windows Vista layout"
                      : h.Variant == FveVariant.Win7Plus ? "Windows 7/10+ layout" : "unknown";

            string note;
            Fve.Resolve(d, h, out note);
            FveMetadata m = h.Meta;
            if (m != null)
            {
                v.VolumeGuid = m.VolumeGuid == Guid.Empty ? "(not recorded)" : m.VolumeGuid.ToString();
                v.Encryption = FveMethods.Name(m.EncryptionMethod);
                v.Created = Fmt.FileTimeToIso(m.CreationFileTime);
                v.BlocksReadable = m.BlocksWithSignature;
                v.EncryptedSize = m.EncryptedVolumeSize == 0
                    ? "0 (whole volume flagged)"
                    : Fmt.HumanSize(m.EncryptedVolumeSize);
                if (m.ParseNote != null && m.ParseNote.Length > 0) v.Note = m.ParseNote;
                if (note != null && note.Length > 0)
                    v.Note = string.IsNullOrEmpty(v.Note) ? note : v.Note + "; " + note;

                var names = new List<string>();
                var creds = new List<string>();
                foreach (FveEntryInfo e in m.Entries)
                {
                    if (e.EntryType != 0x0002 || !e.ProtectorType.HasValue) continue;
                    ushort pt = e.ProtectorType.Value;
                    string n = FveProtectors.Name(pt) ?? ("0x" + pt.ToString("X4", System.Globalization.CultureInfo.InvariantCulture));
                    if (!names.Contains(n)) names.Add(n);
                    string c = FveProtectors.LikelyCredential(pt);
                    if (!creds.Contains(c)) creds.Add(c);
                }
                v.Protectors = names.Count > 0 ? string.Join(", ", names.ToArray()) : "(none parsed)";
                v.Credential = creds.Count > 0 ? string.Join(" or ", creds.ToArray()) : "unknown";

                ulong? size = Fve.SuggestPartitionSize(m, d.BytesPerSector, d.SizeBytes, h.Offset);
                if (size.HasValue)
                {
                    v.SizeFromMetadata = true;
                    v.SuggestedSizeBytes = (long)size.Value;
                    v.SuggestedLastLba = h.Lba + (size.Value / (ulong)d.BytesPerSector) - 1;
                    if (v.SuggestedLastLba >= (ulong)d.SectorCount) v.SuggestedLastLba = (ulong)d.SectorCount - 1;
                    ClampToGptEnd(d, isGpt, v);
                    v.SuggestedSize = Fmt.HumanSize((long)(v.SuggestedLastLba - h.Lba + 1) * d.BytesPerSector);
                }
            }
            else
            {
                v.VolumeGuid = "(unreadable)";
                v.Encryption = "(unreadable)";
                v.Created = "";
                v.BlocksReadable = 0;
                v.EncryptedSize = "(unreadable)";
                v.Protectors = "(unreadable)";
                v.Credential = "unknown";
                v.SuggestedLastLba = h.Lba + 2047;
                v.SuggestedSize = Fmt.HumanSize(2048L * d.BytesPerSector);
                v.SizeFromMetadata = false;
                if (!string.IsNullOrEmpty(note)) v.Note = note;
            }
            return v;
        }

        /// <summary>
        /// Describes a volume that is NOT encrypted. Its own boot sector is the surviving
        /// witness, and the BIOS parameter block gives the exact size Windows itself used -
        /// which is better evidence than any reconstruction.
        /// </summary>
        private static RecoveredVolume DescribePlainVolume(RawDisk d, FveHit h, RecoveredVolume v, bool isGpt)
        {
            byte[] sector = d.ReadAt(h.Offset, d.BytesPerSector);

            v.Variant = VolumeProbe.Describe(h.Kind) + " (not encrypted)";
            v.VolumeGuid = h.Kind == VolumeKind.Ntfs && VolumeProbe.SerialNumber(sector, 0) != null
                ? "serial " + VolumeProbe.SerialNumber(sector, 0)
                : "(not applicable)";
            v.Encryption = "none - this volume is not encrypted";
            v.Created = "";
            v.BlocksReadable = 0;
            v.Protectors = "none";
            v.Credential = "NOTHING - the files are readable as soon as the partition entry is back";

            if (h.BpbSize.HasValue && h.BpbSize.Value > 0)
            {
                v.EncryptedSize = Fmt.HumanSize(h.BpbSize.Value) + "  (from the filesystem's own BPB)";
                v.SizeFromMetadata = true;
                v.SuggestedSizeBytes = (long)h.BpbSize.Value;
                v.SuggestedLastLba = h.Lba + (h.BpbSize.Value / (ulong)d.BytesPerSector) - 1;
                if (v.SuggestedLastLba >= (ulong)d.SectorCount) v.SuggestedLastLba = (ulong)d.SectorCount - 1;
                ClampToGptEnd(d, isGpt, v);
                v.SuggestedSize = Fmt.HumanSize((long)(v.SuggestedLastLba - h.Lba + 1) * d.BytesPerSector);
            }
            else
            {
                v.EncryptedSize = "(BPB unreadable - size is a guess)";
                v.SizeFromMetadata = false;
                v.SuggestedLastLba = h.Lba + 2047;
                v.SuggestedSize = Fmt.HumanSize(2048L * d.BytesPerSector);
                v.Note = "could not read a usable size from the boot sector - set the range by hand";
            }
            return v;
        }

        /// <summary>
        /// Caps a suggested range at the last LBA a GPT partition may occupy. A volume whose own
        /// metadata claims it runs to the final sector of the disk is common - the FVE encrypted
        /// size covers the whole device - but those last sectors belong to the backup GPT, so the
        /// raw figure can never be written. Suggesting it anyway hands the operator a range the
        /// writer rejects, which is a dead end with no way forward. Clamping costs nothing real:
        /// those sectors were the backup table, never user data.
        /// </summary>
        private static void ClampToGptEnd(RawDisk d, bool isGpt, RecoveredVolume v)
        {
            if (!isGpt) return;
            ulong ceiling = Gpt.LastUsableLba(Gpt.StandardArraySectors, d.SectorCount);
            if (v.SuggestedLastLba <= ceiling) return;
            if (v.SuggestedLastLba >= (ulong)d.SectorCount) v.SuggestedLastLba = (ulong)d.SectorCount - 1;
            if (v.SuggestedLastLba <= ceiling) return;

            v.SuggestedLastLba = ceiling;
            v.SuggestedSize = Fmt.HumanSize((long)(v.SuggestedLastLba - v.StartLba + 1) * d.BytesPerSector);
            string cap = "the volume's own recorded size runs to the end of the disk, but the final " +
                         Gpt.BackupReserveSectors(Gpt.StandardArraySectors) +
                         " sectors are reserved for the backup GPT, so the range is capped at LBA " +
                         ceiling;
            v.Note = string.IsNullOrEmpty(v.Note) ? cap : v.Note + "; " + cap;
        }

        /// <summary>Recreates the primary GPT from the trailing backup GPT.</summary>
        public static OperationResult RestoreFromBackup(DiskInfoLite info, string backupDir, bool force,
                                                       ConfirmGate gate)
        {
            var result = new OperationResult();
            using (RawDisk d = Open(info, true))
            {
                GptImage backup = Gpt.ReadBackup(d);
                if (backup == null || !backup.Usable)
                {
                    result.Problems.Add("The backup GPT at the end of the disk is not usable, so there is " +
                                        "nothing to restore from. Use \"Add partition entry\" instead.");
                    return result;
                }
                result.Summary = Restorer.RestoreGptFromBackup(d, backup, true, backupDir, force, gate);
                result.BackupDirectory = backupDir;
                result.Success = true;
            }
            return result;
        }

        /// <summary>Adds a partition entry covering a recovered BitLocker volume.</summary>
        public static OperationResult AddPartitionEntry(DiskInfoLite info, ulong first, ulong last,
                                                       string name, string backupDir, bool force,
                                                       ConfirmGate gate)
        {
            var result = new OperationResult();
            using (RawDisk d = Open(info, true))
            {
                GptImage primary = Gpt.ReadPrimary(d);
                GptImage backup = Gpt.ReadBackup(d);
                MbrDisk mbr = MbrDisk.Read(d);
                List<LbaRange> inUse = Scanner.CollectInUse(d, primary, backup, mbr);
                result.Summary = Restorer.AddGptPartition(d, primary, backup, first, last, name,
                                                          GptTypes.BasicData, true, force, backupDir, inUse, gate);
                result.BackupDirectory = backupDir;
                result.Success = true;
            }
            return result;
        }

        public static string CreateBackup(DiskInfoLite info, string backupDir)
        {
            using (RawDisk d = Open(info, false))
                return Restorer.BackupEnds(d, backupDir);
        }

        private static string SummariseMbr(MbrDisk mbr, RawDisk d)
        {
            if (mbr.IsProtectiveForGpt) return "protective MBR (GPT disk)";
            if (!mbr.HasBootSignature && !mbr.HasCode) return "blank - no partition table";
            int used = 0;
            foreach (MbrEntry e in mbr.Entries) if (e.InUse) used++;
            return "0x55AA " + (mbr.HasBootSignature ? "present" : "absent") + ", " + used + " of 4 slots in use";
        }

        private static string SummariseGpt(GptImage img, RawDisk d, string label)
        {
            if (img == null || !img.Header.SignatureOk) return label + ": absent";
            GptHeader h = img.Header;
            int used = 0;
            foreach (GptEntry e in img.Entries) if (e.InUse) used++;
            return label + ": " + (h.HeaderCrcOk && h.ArrayCrcOk ? "valid" : "CORRUPT") +
                   ", " + used + " entries in use";
        }
    }
}
