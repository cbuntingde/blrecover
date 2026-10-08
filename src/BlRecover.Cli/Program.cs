using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;

namespace BlRecover
{
    internal static class Program
    {
        private static int Main(string[] args)
        {
            Out.SetPlain(Console.IsOutputRedirected || HasFlag(args, "--no-color"));
            Console.OutputEncoding = new UTF8Encoding(false);

            // Necessary but not sufficient: elevation alone does not grant raw disk access.
            Privileges.EnableForRawDiskAccess();

            if (args.Length == 0 || HasFlag(args, "--help") || HasFlag(args, "-h") || args[0] == "help")
            {
                Usage();
                return args.Length == 0 ? 2 : 0;
            }

            try
            {
                string cmd = args[0].ToLowerInvariant();
                var rest = new List<string>();
                for (int i = 1; i < args.Length; i++) rest.Add(args[i]);
                var o = new Args(rest);

                switch (cmd)
                {
                    case "list": return CmdList();
                    case "inspect": return CmdInspect(o);
                    case "scan": return CmdScan(o, false);
                    case "analyze": return CmdScan(o, true);
                    case "backup": return CmdBackup(o);
                    case "restore-gpt": return CmdRestoreGpt(o);
                    case "add-gpt": return CmdAddGpt(o);
                    case "add-mbr": return CmdAddMbr(o);
                    case "verify": return CmdVerify(o);
                    case "dump": return CmdDump(o);
                    case "mkimage": return CmdMkImage(o);
                    case "diagnose": return Diagnose.Run();
                    case "selftest": return SelfTest.Run();
                    default:
                        Out.Bad("Unknown command: " + cmd);
                        Usage();
                        return 2;
                }
            }
            catch (UserAbortException ex)
            {
                Out.Bad("");
                Out.Bad("ABORTED: " + ex.Message);
                return 3;
            }
            catch (Exception ex)
            {
                Out.Bad("");
                Out.Bad("ERROR: " + ex.GetType().Name + ": " + ex.Message);
                if (HasFlag(args, "--verbose")) Out.Dim(ex.ToString());
                return 1;
            }
        }

        // -------------------------------------------------------------- commands

        private static int CmdList()
        {
            Out.Title("Physical disks");
            List<DiskInfoLite> disks = DiskList.Enumerate();
            if (disks.Count == 0) { Out.Warn("  no disks found"); return 1; }
            Console.WriteLine("  {0,-4} {1,-12} {2,-10} {3,14}  {4,-5} {5}", "#", "SIZE", "SECTOR", "SERIAL", "BOOT", "MODEL / PATH");
            Out.Dim(new string('-', 96));
            foreach (DiskInfoLite d in disks)
            {
                Console.WriteLine("  {0,-4} {1,-12} {2,-10} {3,14}  {4,-5} {5}",
                    d.Index, Fmt.HumanSize(d.Size), d.BytesPerSector + "B",
                    string.IsNullOrEmpty(d.Serial) ? "-" : d.Serial,
                    d.IsBoot ? "yes" : "-", d.Model);
                Out.Dim("       " + d.DevicePath + "   " + d.BusType + (d.SectorsNote == "" ? "" : "   (" + d.SectorsNote + ")"));
            }
            Out.Dim("");
            Out.Dim("  Read-only use: --disk N.  Writing requires an elevated prompt and --apply.");
            return 0;
        }

        private static int CmdInspect(Args o)
        {
            using (RawDisk d = o.OpenDisk(false))
            {
                Out.Title("Device " + d.DevicePath);
                DescribeDevice(d);
                MbrDisk mbr = MbrDisk.Read(d);
                GptImage primary = Gpt.ReadPrimary(d);
                GptImage backup = Gpt.ReadBackup(d);

                Out.Title("LBA 0 - MBR");
                Console.Write(MbrDisk.Describe(mbr, d));

                Out.Title("GPT");
                bool anyGpt = (primary != null && primary.Header.SignatureOk) || (backup != null && backup.Header.SignatureOk);
                if (!anyGpt) Out.Indent("no GPT structures found - this is an MBR disk");
                else
                {
                    Gpt.Describe(primary, d, "primary");
                    Gpt.Describe(backup, d, "backup ");
                }

                List<string> diffs = Gpt.Compare(primary, backup, d);
                if (diffs.Count > 0)
                {
                    Out.Warn("  the two GPT copies DISAGREE - strong evidence of a deleted/rebuilt partition:");
                    foreach (string s in diffs) Out.Indent(s, 4);
                }
                else if (anyGpt && primary != null && backup != null && primary.Usable && backup.Usable)
                {
                    Out.Ok("  primary and backup GPT agree.");
                }

                if (primary != null && primary.Usable)
                {
                    Out.Title("GPT partitions (primary)");
                    Gpt.PrintEntries(primary, d, "  ");
                }
                if (backup != null && backup.Usable && (primary == null || !primary.Usable))
                {
                    Out.Title("GPT partitions (backup only - primary is unusable)");
                    Gpt.PrintEntries(backup, d, "  ");
                }
                if (!primary.Usable && backup.Usable)
                {
                    Out.H("");
                    Out.Info("  RECOVERY PATH: the primary GPT is unusable but the trailing backup is intact.");
                    Out.Info("  Run:  blrecover restore-gpt --disk " + d.Index + " --apply");
                }
                if (mbr.Entries.Count > 0 && !mbr.IsProtectiveForGpt)
                {
                    Out.Title("MBR partitions");
                    Console.Write(MbrDisk.Describe(mbr, d));
                }
                return 0;
            }
        }

        private static int CmdScan(Args o, bool includeInspect)
        {
            using (RawDisk d = o.OpenDisk(false))
            {
                if (includeInspect)
                {
                    Out.Title("Device " + d.DevicePath);
                    DescribeDevice(d);
                    MbrDisk mbr0 = MbrDisk.Read(d);
                    GptImage p0 = Gpt.ReadPrimary(d);
                    GptImage b0 = Gpt.ReadBackup(d);
                    Out.Title("Partition tables");
                    if (p0 != null && p0.Header.SignatureOk) Gpt.Describe(p0, d, "primary GPT");
                    else Out.Indent("primary GPT: absent or destroyed");
                    if (b0 != null && b0.Header.SignatureOk) Gpt.Describe(b0, d, "backup  GPT");
                    else Out.Indent("backup  GPT: absent or destroyed");
                    if (mbr0 != null && !mbr0.IsProtectiveForGpt) Console.Write(MbrDisk.Describe(mbr0, d));
                }

                MbrDisk mbr = MbrDisk.Read(d);
                GptImage primary = Gpt.ReadPrimary(d);
                GptImage backup = Gpt.ReadBackup(d);
                List<LbaRange> inUse = Scanner.CollectInUse(d, primary, backup, mbr);

                Out.Title("Space in use");
                foreach (LbaRange r in inUse) Out.Indent("LBA " + r.First + ".." + r.Last + "  " + r.Source);
                if (inUse.Count == 0) Out.Indent("(none - the whole device is unallocated)");

                var opt = new ScanOptions();
                opt.ScanWholeDevice = o.Has("full");
                opt.Progress = !o.Has("quiet");
                int alignKb = o.GetInt("align-kb", 1024);
                opt.Alignment = alignKb * 1024;
                opt.MaxOffset = (ulong)o.GetInt("max-offset-mb", 0) * 1024UL * 1024UL;
                if (!o.Has("full"))
                    Out.Dim("  (only unallocated space is scanned; use --full to scan everything)");

                Out.Title("Scanning for deleted volume headers (BitLocker, NTFS, exFAT, FAT)");
                var sw = System.Diagnostics.Stopwatch.StartNew();
                ScanResult res = Scanner.Scan(d, inUse, opt, s => Out.Dim(s));
                sw.Stop();
                Out.Dim("  scanned " + Fmt.HumanSize(res.BytesScanned) + ", skipped " + Fmt.HumanSize(res.BytesSkipped) +
                        ", " + res.ReadErrors + " read error(s) in " + sw.Elapsed.TotalSeconds.ToString("0.0", CultureInfo.InvariantCulture) + "s");

                Out.Title("Results");
                if (res.InUse.Count > 0)
                {
                    Out.Info("  " + res.InUse.Count + " BitLocker volume(s) inside live partitions (expected - these are healthy):");
                    foreach (FveHit h in res.InUse) ReportVolume(d, h, false);
                }

                if (res.VolumeHeaders.Count == 0)
                {
                    Out.Warn("  No filesystem or BitLocker volume header found in unallocated space.");
                    Out.Dim("  If the partition was deleted AND the space reused/formatted, its header is gone and");
                    Out.Dim("  there is nothing left to restore. Try --full, or --align-kb 1 for a 512-byte sweep.");
                    return 4;
                }

                Out.Ok("  " + res.VolumeHeaders.Count + " candidate deleted BitLocker volume(s) found in unallocated space:");
                int n = 0;
                foreach (FveHit h in res.VolumeHeaders)
                {
                    n++;
                    Out.H("  [" + n + "] start LBA " + h.Lba + "  (byte offset " + h.Offset + ")");
                    ReportVolume(d, h, true);
                    PrintPlan(d, h, primary, backup, mbr, inUse);
                }
                return 0;
            }
        }

        private static void ReportVolume(RawDisk d, FveHit hit, bool resolve)
        {
            string note = null;
            bool plain = hit.Kind != VolumeKind.Fve;

            if (hit.Kind == VolumeKind.Fve && resolve) Fve.Resolve(d, hit, out note);

            Out.Indent("filesystem    : " + VolumeProbe.Describe(hit.Kind) +
                       (plain ? "   <-- NOT encrypted" : ""));

            if (plain)
            {
                // No FVE metadata to read. Report what the volume's own boot sector says.
                if (hit.BpbSize.HasValue)
                    Out.Indent("volume size   : " + Fmt.HumanSize(hit.BpbSize.Value) +
                               "  (from the filesystem's own BPB - this is the size Windows used)");
                else
                    Out.Indent("volume size   : (BPB unreadable - pick the range by hand)");

                byte[] sec = d.ReadAt(hit.Offset, Math.Min(d.BytesPerSector, 512));
                string serial = VolumeProbe.SerialNumber(sec, 0);
                if (serial != null) Out.Indent("volume serial : " + serial);
                Out.Ok("  no BitLocker key is needed - restoring the partition entry makes the files readable");
                if (note != null && note.Length > 0) Out.Indent("note          : " + note);
                return;
            }

            FveMetadata m = hit.Meta;
            if (m == null) { Out.Indent("metadata      : could not read FVE metadata blocks"); return; }
            Out.Indent("volume GUID   : " + Fmt.GuidOr(m.VolumeGuid, "(none)"));
            Out.Indent("encryption    : " + FveMethods.Name(m.EncryptionMethod));
            Out.Indent("created       : " + Fmt.FileTimeToIso(m.CreationFileTime));
            Out.Indent("metadata blks : " + m.BlocksWithSignature + " of 3 readable" +
                       (m.ParseNote == "" ? "" : "  (" + m.ParseNote + ")"));
            Out.Indent("encrypt size  : " + (m.EncryptedVolumeSize == 0
                        ? "0 (flag: whole volume is encrypted)"
                        : Fmt.HumanSize(m.EncryptedVolumeSize)));
            if (!m.LooksSane && m.BlocksWithSignature > 0)
                Out.Warn("metadata looks unusual - treat the size below as a hint, not a fact");

            var protTypes = new List<ushort>();
            foreach (FveEntryInfo e in m.Entries)
            {
                if (e.EntryType == 0x0002 && e.ProtectorType.HasValue && !protTypes.Contains(e.ProtectorType.Value))
                    protTypes.Add(e.ProtectorType.Value);
            }
            if (protTypes.Count > 0)
            {
                var names = new List<string>();
                var creds = new List<string>();
                foreach (ushort pt in protTypes)
                {
                    string n = FveProtectors.Name(pt) ?? ("0x" + pt.ToString("X4", CultureInfo.InvariantCulture));
                    if (!names.Contains(n)) names.Add(n);
                    string c = FveProtectors.LikelyCredential(pt);
                    if (!creds.Contains(c)) creds.Add(c);
                }
                Out.Indent("protectors    : " + string.Join(", ", names.ToArray()) +
                           "   -> unlock with: " + string.Join(" or ", creds.ToArray()));
            }
            else
            {
                Out.Indent("protectors    : (no VMK protector entries parsed - the header may be damaged)");
            }

            if (!string.IsNullOrEmpty(note)) Out.Indent("note          : " + note);
        }

        private static void PrintPlan(RawDisk d, FveHit hit, GptImage primary, GptImage backup,
                                      MbrDisk mbr, List<LbaRange> inUse)
        {
            ulong? size = Fve.SuggestPartitionSize(hit.Meta, d.BytesPerSector, d.SizeBytes, hit.Offset);
            if (hit.Kind != VolumeKind.Fve)
                size = hit.BpbSize.HasValue && hit.BpbSize.Value > 0 ? hit.BpbSize : (ulong?)null;
            if (size == null) { Out.Warn("  cannot determine a size from metadata - you must pass --first/--last manually"); return; }
            ulong firstLba = hit.Lba;
            ulong lastLba = firstLba + (size.Value / (ulong)d.BytesPerSector) - 1;
            if (lastLba >= (ulong)d.SectorCount) lastLba = (ulong)d.SectorCount - 1;

            // Never suggest a range our own writer will reject. A volume whose recorded size fills
            // the disk has a last LBA that lands on the backup GPT, which is unwritable. Uses the
            // same shared formula as the GUI and the writer so the two cannot drift apart again.
            bool isGpt = (primary != null && primary.Header.SignatureOk)
                      || (backup != null && backup.Header.SignatureOk)
                      || (mbr != null && mbr.IsProtectiveForGpt);
            if (isGpt)
            {
                ulong ceiling = Gpt.LastUsableLba(Gpt.StandardArraySectors, d.SectorCount);
                if (lastLba > ceiling)
                {
                    lastLba = ceiling;
                    Out.Warn("  note: the volume's recorded size runs to the end of the disk, but the final " +
                             Gpt.BackupReserveSectors(Gpt.StandardArraySectors) +
                             " sectors are reserved for the backup GPT. Range capped at LBA " + ceiling + ".");
                }
            }

            Out.Indent("-> suggested  : LBA " + firstLba + ".." + lastLba +
                       "  (" + Fmt.HumanSize((long)(lastLba - firstLba + 1) * d.BytesPerSector) + ")");
            string selector = d.IsImage
                ? "--image \"" + d.DevicePath + "\""
                : "--disk " + d.Index.ToString(CultureInfo.InvariantCulture);
            Out.Indent("   restore with: blrecover add-gpt " + selector +
                       " --first " + firstLba + " --last " + lastLba + " --name \"Recovered\" --apply");
        }

        private static int CmdMkImage(Args o)
        {
            string path = o.GetString("path", "");
            if (path.Length == 0) { Out.Bad("  --path FILE is required"); return 2; }
            path = Path.GetFullPath(path);

            var spec = new ImageFactory.Spec();
            spec.Path = path;
            spec.BytesPerSector = o.GetInt("sector-size", 512);
            spec.SizeBytes = o.Has("size-bytes") ? o.GetLong("size-bytes", 0)
                                                 : o.GetLong("size-mb", 256) * 1024L * 1024L;
            spec.Mbr = o.Has("mbr");
            spec.DestroyPrimaryGpt = o.Has("clean");
            spec.VolumeStartLba = o.Has("volume-start") ? o.GetUlong("volume-start") : 2048;
            spec.VolumeSectors = o.Has("volume-size")
                ? o.GetUlong("volume-size") / (ulong)spec.BytesPerSector
                : (ulong)Math.Max(1, (spec.SizeBytes / spec.BytesPerSector) - (long)spec.VolumeStartLba - 34);
            string fs = o.GetString("filesystem", "bitlocker").ToLowerInvariant();
            if (fs == "ntfs") spec.Filesystem = VolumeKind.Ntfs;
            else if (fs == "exfat") spec.Filesystem = VolumeKind.ExFat;
            else spec.Filesystem = VolumeKind.Fve;

            // The image is sparse, so a huge apparent size is fine - but never silently.
            if (spec.SizeBytes > 4L * 1024 * 1024 * 1024 && !o.Has("force-large"))
            {
                Out.Bad("  Refusing to create an image larger than 4 GiB without --force-large.");
                Out.Indent("It is created as a sparse file, so it should only occupy a few hundred KB,");
                Out.Indent("but if the file system cannot make it sparse the size would be real.");
                return 2;
            }

            Out.Title("Creating a synthetic test image");
            Out.Indent("path          : " + path);
            Out.Indent("size          : " + Fmt.HumanSize(spec.SizeBytes) +
                       "  (" + (spec.SizeBytes / spec.BytesPerSector) + " LBAs)");
            Out.Indent("layout        : " + (spec.Mbr ? "MBR" : "GPT") +
                       (spec.DestroyPrimaryGpt ? ", primary GPT destroyed (like diskpart clean)" : ", one entry deleted"));
            Out.Indent("volume        : LBA " + spec.VolumeStartLba + " .. " +
                       (spec.VolumeStartLba + spec.VolumeSectors - 1) + "  (" + Fmt.HumanSize((long)spec.VolumeSectors * spec.BytesPerSector) + ")");
            Out.Indent("filesystem    : " + VolumeProbe.Describe(spec.Filesystem) +
                       (spec.Filesystem == VolumeKind.Fve
                           ? "  (an unlock key will be required to read the files)"
                           : "  (NOT encrypted - no key will be required)"));

            try { ImageFactory.BuildFile(spec); }
            catch (Exception ex) { Out.Bad("  failed: " + ex.Message); return 1; }

            Out.Ok("  image written (sparse - only the metadata blocks occupy real space)");
            Out.Dim("  Rehearse the whole recovery on it:");
            Out.Dim("    blrecover analyze --image \"" + path + "\"");
            Out.Dim("    blrecover add-gpt --image \"" + path + "\" --first " + spec.VolumeStartLba +
                    " --last " + (spec.VolumeStartLba + spec.VolumeSectors - 1) + " --apply");
            return 0;
        }

        private static int CmdBackup(Args o)
        {
            using (RawDisk d = o.OpenDisk(false))
            {
                // Documented spelling is --backup-dir, matching every other write command.
                // --out is kept as an alias so older scripts keep working.
                string outDir = o.Has("backup-dir")
                    ? o.GetString("backup-dir", "blrecover-backups")
                    : o.GetString("out", "blrecover-backups");
                Out.Title("Backing up partition table regions");
                Out.Indent("device : " + d.DevicePath + "  " + d.Model);
                string dir = Restorer.BackupEnds(d, outDir);
                Out.Ok("  done.");
                Out.Dim("  Keep this folder. To put the table back later, see README.md (restore-gpt / manual).");
                return 0;
            }
        }

        private static int CmdRestoreGpt(Args o)
        {
            using (RawDisk d = o.OpenDisk(o.Has("apply")))
            {
                Out.Title("Restore primary GPT from the trailing backup GPT");
                DescribeDevice(d);
                GptImage primary = Gpt.ReadPrimary(d);
                GptImage backup = Gpt.ReadBackup(d);
                if (primary != null) Gpt.Describe(primary, d, "current primary");
                if (backup != null) Gpt.Describe(backup, d, "trailing backup");

                if (primary != null && primary.Usable && backup != null && backup.Usable)
                {
                    List<string> diffs = Gpt.Compare(primary, backup, d);
                    if (diffs.Count == 0)
                    {
                        Out.Ok("  both GPT copies are valid and identical - there is nothing to restore.");
                        Out.Dim("  If your BitLocker partition is still missing, run: blrecover scan --disk " + d.Index);
                        return 0;
                    }
                    Out.Warn("  the copies differ; the backup will win:");
                    foreach (string s in diffs) Out.Indent(s, 4);
                }

                if (!o.Has("apply"))
                {
                    Out.H("");
                    Out.Info("  This was a dry run. Re-run with --apply from an elevated prompt to write.");
                    return 0;
                }
                Restorer.RestoreGptFromBackup(d, backup, o.Has("apply"), o.GetString("backup-dir", "blrecover-backups"), o.Has("force"), Restorer.ConsoleConfirm);
                Out.Title("Next steps");
                Out.Dim("  1. Run:  blrecover scan --disk " + d.Index);
                Out.Dim("  2. If your BitLocker volume is listed, add its partition entry with add-gpt.");
                Out.Dim("  3. Run:  manage-bde -status  to confirm BitLocker sees the volume again.");
                return 0;
            }
        }

        private static int CmdAddGpt(Args o)
        {
            using (RawDisk d = o.OpenDisk(o.Has("apply")))
            {
                Out.Title("Add a GPT partition entry");
                DescribeDevice(d);
                GptImage primary = Gpt.ReadPrimary(d);
                GptImage backup = Gpt.ReadBackup(d);
                MbrDisk mbr = MbrDisk.Read(d);
                if (primary != null && primary.Header.SignatureOk) Gpt.Describe(primary, d, "primary");
                else Out.Indent("primary GPT: absent or destroyed");
                if (backup != null && backup.Header.SignatureOk) Gpt.Describe(backup, d, "backup ");
                else Out.Indent("backup  GPT: absent or destroyed");

                if (primary == null || !primary.Usable)
                {
                    if (backup == null || !backup.Usable)
                        throw new UserAbortException("neither GPT copy is usable. Run 'restore-gpt --apply' first, or 'diskpart' is not your problem.");
                    Out.Warn("  the primary GPT is unusable. Run 'restore-gpt --apply' first - it is safer and it");
                    Out.Warn("  reconstructs the original table, which may already include your lost partition.");
                }

                ulong first = o.GetUlong("first");
                ulong last = o.GetUlong("last");
                if (last < first)
                {
                    if (!o.Has("first")) throw new UserAbortException("--first is required");
                    ulong sizeBytes = o.GetUlong("size");
                    last = first + sizeBytes / (ulong)d.BytesPerSector - 1;
                }
                string name = o.GetString("name", null);
                Guid type = o.Has("type") ? new Guid(o.GetString("type", "")) : GptTypes.BasicData;

                if (!o.Has("apply"))
                {
                    Out.H("");
                    Out.Info("  DRY RUN. Would write:");
                    Out.Indent("LBA " + first + ".." + last + "  (" + Fmt.HumanSize((long)(last - first + 1) * d.BytesPerSector) + ")", 4);
                    Out.Indent("type " + GptTypes.Name(type) + "  (" + type + ")", 4);
                    Out.Indent("name " + (name ?? "(none)"), 4);
                    Out.Dim("  Re-run with --apply from an elevated prompt to perform it.");
                    return 0;
                }

                List<LbaRange> inUse = Scanner.CollectInUse(d, primary, backup, mbr);
                Restorer.AddGptPartition(d, primary, backup, first, last, name, type,
                                        o.Has("apply"), o.Has("force"), o.GetString("backup-dir", "blrecover-backups"), inUse, Restorer.ConsoleConfirm);
                Out.Title("Next steps");
                Out.Dim("  1. Reboot, or:  diskpart  ->  rescan");
                Out.Dim("  2. manage-bde -status   should list the volume again, locked.");
                Out.Dim("  3. Unlock with your password or 48-digit recovery key.");
                return 0;
            }
        }

        private static int CmdAddMbr(Args o)
        {
            using (RawDisk d = o.OpenDisk(o.Has("apply")))
            {
                Out.Title("Add an MBR partition entry");
                DescribeDevice(d);
                MbrDisk mbr = MbrDisk.Read(d);
                Console.Write(MbrDisk.Describe(mbr, d));
                if (mbr.IsProtectiveForGpt)
                    throw new UserAbortException("this disk is GPT-partitioned - use add-gpt instead");

                int slot = o.GetInt("slot", -1);
                if (slot < 0) { Out.Bad("  --slot 0..3 is required"); return 2; }
                ulong first = o.GetUlong("first");
                ulong sectors = o.Has("sectors") ? o.GetUlong("sectors")
                                                  : o.GetUlong("size") / (ulong)d.BytesPerSector;
                byte type = 0;
                if (o.Has("type")) type = Convert.ToByte(o.GetString("type", "0x07").Replace("0x", ""), 16);
                else type = 0x07;

                if (!o.Has("apply"))
                {
                    Out.H("");
                    Out.Info("  DRY RUN. Would write MBR slot " + slot + ": LBA " + first + ", " +
                             sectors + " sectors, type 0x" + type.ToString("X2", CultureInfo.InvariantCulture));
                    Out.Dim("  Re-run with --apply from an elevated prompt to perform it.");
                    return 0;
                }

                List<LbaRange> inUse = Scanner.CollectInUse(d, Gpt.ReadPrimary(d), Gpt.ReadBackup(d), mbr);
                Restorer.AddMbrPartition(d, mbr, slot, first, sectors, type, o.Has("apply"), o.Has("force"),
                                         o.GetString("backup-dir", "blrecover-backups"), inUse, Restorer.ConsoleConfirm);
                return 0;
            }
        }

        private static int CmdVerify(Args o)
        {
            using (RawDisk d = o.OpenDisk(false))
            {
                Out.Title("Verify " + d.DevicePath);
                GptImage p = Gpt.ReadPrimary(d);
                GptImage b = Gpt.ReadBackup(d);
                bool gptOk = false;
                if (p != null && p.Header.SignatureOk)
                {
                    Gpt.Describe(p, d, "primary");
                    gptOk = p.Usable;
                }
                if (b != null && b.Header.SignatureOk) Gpt.Describe(b, d, "backup ");
                if (!gptOk && (b == null || !b.Usable))
                {
                    MbrDisk m = MbrDisk.Read(d);
                    Console.Write(MbrDisk.Describe(m, d));
                }
                if (p != null && p.Usable) { Out.Title("Partitions"); Gpt.PrintEntries(p, d, "  "); }
                return (gptOk || (b != null && b.Usable)) ? 0 : 5;
            }
        }

        private static int CmdDump(Args o)
        {
            using (RawDisk d = o.OpenDisk(false))
            {
                // --lba and --offset are two spellings of the same thing; --lba wins when both are given.
                long offset = o.Has("lba") ? d.LbaToOffset(o.GetLong("lba", 0)) : o.GetLong("offset", 0);
                int len = o.GetInt("length", 512);
                Out.Title("Dump " + d.DevicePath + " offset " + offset + " length " + len);
                byte[] buf = d.ReadAt(offset, len);
                for (int i = 0; i < len; i += 16)
                {
                    int n = Math.Min(16, len - i);
                    var ascii = new StringBuilder();
                    for (int j = 0; j < n; j++)
                    {
                        byte c = buf[i + j];
                        ascii.Append(c >= 0x20 && c < 0x7F ? (char)c : '.');
                    }
                    Console.WriteLine("  {0:x10}  {1,-47}  |{2}|", offset + i, Fmt.Hex(buf, i, n), ascii);
                }
                if (len >= 512)
                {
                    Out.Dim("  signature @0  : " + SafeAscii(buf, 0, 8));
                    Out.Dim("  signature @3  : " + SafeAscii(buf, 3, 8));
                    Out.Dim("  u64 @16       : " + Bin.U64(buf, 16));
                    Out.Dim("  u64 @24       : " + Bin.U64(buf, 24));
                    Out.Dim("  u64 @32       : " + Bin.U64(buf, 32));
                }
                return 0;
            }
        }

        private static string SafeAscii(byte[] b, int off, int n)
        {
            var sb = new StringBuilder();
            for (int i = 0; i < n; i++)
            {
                if (off + i >= b.Length) break;
                byte c = b[off + i];
                sb.Append(c >= 0x20 && c < 0x7F ? (char)c : '.');
            }
            return sb.ToString();
        }

        private static void DescribeDevice(RawDisk d)
        {
            Out.Indent("model  : " + d.Model);
            Out.Indent("serial : " + d.Serial);
            Out.Indent("size   : " + Fmt.HumanSize(d.SizeBytes) + "  (" + d.SectorCount + " LBAs of " + d.BytesPerSector + "B)");
            Out.Indent("write  : " + (d.CanWrite ? "yes" : "no - " + d.ReadOnlyReason));
        }

        // -------------------------------------------------------------- args

        private static bool HasFlag(string[] args, string name)
        {
            foreach (string a in args) if (string.Equals(a, name, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        private static void Usage()
        {
            Console.WriteLine(@"blrecover - locate and restore deleted BitLocker partitions

READ-ONLY BY DEFAULT. Nothing is written without --apply, an elevated prompt, a
safety backup of both ends of the disk, and a typed confirmation token.

USAGE
  blrecover <command> [options]

COMMANDS
  list                     enumerate physical disks
  inspect --disk N         parse MBR + both GPT copies, report health and disagreement
  scan --disk N            find BitLocker volume headers in unallocated space
  analyze --disk N         inspect + scan + print a restore command
  backup --disk N          save the first and last 1 MiB to a folder
  restore-gpt --disk N     rebuild the primary GPT from the trailing backup GPT (--force on a boot disk)
  add-gpt --disk N         add a partition entry for a recovered volume
  add-mbr --disk N         add an MBR entry for a recovered volume
  verify --disk N          re-read and check the partition table
  dump --disk N            hex dump a region (--offset BYTES or --lba N)
  mkimage --path FILE      create a synthetic BitLocker disk image to rehearse on
  diagnose                 read-only: test every disk-access route, print exact Win32 errors
  selftest                 run built-in tests on synthetic disk images

DEVICE SELECTION
  --disk N                 physical disk N  (\\.\PhysicalDriveN)
  --image PATH             a raw image file instead (.img/.dd) - safe to test on
  --sector-size N          override logical sector size (512/4096)

SCAN OPTIONS
  --align-kb N             sector-alignment granularity for the sweep (default 1024)
  --full                   scan allocated space too
  --max-offset-mb N        stop after N MB
  --quiet                  no progress output

IMAGE OPTIONS (mkimage)
  --path FILE              where to write the image
  --size-mb N              image size in MB (default 256)
  --volume-start LBA       where the synthetic BitLocker volume begins (default 2048)
  --volume-size BYTES      its size
  --mbr                    make it an MBR disk instead of GPT
  --clean                  wipe the primary GPT (reproduce the diskpart-clean case)
  --filesystem NAME        bitlocker (default) | ntfs | exfat

WRITE OPTIONS (only honoured with --apply)
  --first LBA              first sector of the recovered partition
  --last LBA               last sector, inclusive
  --size BYTES             alternative to --last
  --name TEXT              GPT partition name
  --type GUID              GPT type GUID (default EBD0A0A2-... Basic data)
  --slot 0..3              MBR slot
  --sectors N              MBR length in sectors
  --type 0x07              MBR type byte
  --force                  proceed despite warnings (e.g. boot disk)
  --backup-dir DIR         where safety backups go (default blrecover-backups)
  --no-color               plain output

EXAMPLES
  blrecover list
  blrecover inspect --disk 2
  blrecover analyze --disk 2
  blrecover add-gpt --disk 2 --first 2048 --last 1050623 --name ""Recovered"" --apply
");
        }
    }

    internal sealed class Args
    {
        private readonly Dictionary<string, string> _values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _flags = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        public Args(List<string> args)
        {
            for (int i = 0; i < args.Count; i++)
            {
                string a = args[i];
                if (!a.StartsWith("--", StringComparison.Ordinal)) continue;
                string key = a.Substring(2);
                if (key.Length == 0) continue;
                if (i + 1 < args.Count && !args[i + 1].StartsWith("--", StringComparison.Ordinal))
                {
                    _values[key] = args[i + 1];
                    i++;
                }
                else _flags.Add(key);
            }
        }

        public bool Has(string k) { return _flags.Contains(k) || _values.ContainsKey(k); }

        public string GetString(string k, string fallback)
        {
            string v;
            return _values.TryGetValue(k, out v) ? v : fallback;
        }

        public int GetInt(string k, int fallback)
        {
            string v;
            int r;
            if (_values.TryGetValue(k, out v) && int.TryParse(v, NumberStyles.Integer, CultureInfo.InvariantCulture, out r)) return r;
            return fallback;
        }

        public long GetLong(string k, long fallback)
        {
            string v;
            long r;
            if (_values.TryGetValue(k, out v) && long.TryParse(v, NumberStyles.Integer, CultureInfo.InvariantCulture, out r)) return r;
            return fallback;
        }

        public ulong GetUlong(string k)
        {
            string v;
            if (_values.TryGetValue(k, out v))
            {
                ulong r;
                if (ulong.TryParse(v, NumberStyles.Integer, CultureInfo.InvariantCulture, out r)) return r;
                throw new UserAbortException("--" + k + " must be a non-negative integer, got '" + v + "'");
            }
            if (Has(k)) throw new UserAbortException("--" + k + " needs a value");
            throw new UserAbortException("--" + k + " is required");
        }

        public RawDisk OpenDisk(bool allowWrite)
        {
            if (Has("image"))
            {
                string path = GetString("image", "");
                if (!File.Exists(path)) throw new UserAbortException("image not found: " + path);
                int imgBps = GetInt("sector-size", 512);
                return RawDisk.OpenDevice(0, Path.GetFullPath(path),
                    "image: " + Path.GetFileName(path), "", "file", false,
                    new FileInfo(path).Length, imgBps, allowWrite);
            }

            int idx = GetInt("disk", -1);
            if (idx < 0) throw new UserAbortException("--disk N or --image PATH is required");

            DiskInfoLite info = null;
            foreach (DiskInfoLite d in DiskList.Enumerate()) if (d.Index == idx) { info = d; break; }
            if (info == null) throw new UserAbortException("no physical disk with index " + idx);

            int sectorOverride = GetInt("sector-size", 0);
            int bps = sectorOverride > 0 ? sectorOverride : info.BytesPerSector;
            return RawDisk.OpenDevice(info.Index, info.DevicePath, info.Model, info.Serial,
                                      info.BusType, info.IsBoot, info.Size, bps, allowWrite);
        }
    }
}
