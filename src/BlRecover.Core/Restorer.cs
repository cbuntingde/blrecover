using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace BlRecover
{
    internal sealed class SafetyBlock
    {
        public string Reason;
    }

    /// <summary>
    /// Host-supplied confirmation. The engine calls it after preflight and the safety backup
    /// have succeeded and immediately before the first write; the host must throw to abort.
    /// </summary>
    internal delegate void ConfirmGate(RawDisk disk, string action, string[] details);

    internal static class Restorer
    {
        public const int RegionBytes = 1024 * 1024;   // 1 MiB from each end

        // ------------------------------------------------------------ pre-flight

        /// <summary>Everything that must hold before a single byte is written.</summary>
        public static void Preflight(RawDisk d, bool allowWrite, IList<LbaRange> inUse,
                                     ulong first, ulong last, bool force, bool isImage)
        {
            var problems = new List<SafetyBlock>();
            var warnings = new List<SafetyBlock>();

            if (!allowWrite)
                problems.Add(new SafetyBlock { Reason = "--apply was not passed. This is a read-only invocation." });
            if (!d.CanWrite)
                problems.Add(new SafetyBlock
                {
                    Reason = "device could not be opened for writing: " +
                             (d.ReadOnlyReason ?? "unknown") +
                             ". Run from an elevated (Administrator) command prompt."
                });
            if (d.IsBoot && !isImage)
                warnings.Add(new SafetyBlock
                {
                    Reason = "this is the BOOT disk. Writing here can make Windows unbootable and can destroy " +
                             "the very volume you are trying to rescue."
                });
            if (last < first)
                problems.Add(new SafetyBlock { Reason = "last LBA (" + last + ") is before first LBA (" + first + ")." });
            if (last >= (ulong)d.SectorCount)
                problems.Add(new SafetyBlock
                {
                    Reason = "target ends at LBA " + last + " but the device only has " + d.SectorCount + " LBAs."
                });
            if (first < 2)
                problems.Add(new SafetyBlock
                {
                    Reason = "first LBA " + first + " would overwrite the partition table itself. " +
                             "A GPT disk always starts user partitions at LBA 34 or later."
                });
            if (last >= first && last - first < 2)
                warnings.Add(new SafetyBlock
                {
                    Reason = "the recovered range covers only " + (last - first + 1) +
                             " sector(s) - that is almost certainly wrong."
                });

            if (inUse != null)
            {
                foreach (LbaRange r in inUse)
                {
                    if (!r.Overlaps(first, last)) continue;
                    string msg = "target LBA " + first + ".." + last + " overlaps " + r.Source +
                                 " (LBA " + r.First + ".." + r.Last + ")";
                    if (r.Structural)
                        problems.Add(new SafetyBlock
                        {
                            Reason = msg + " - that is partition table data, not free space. " +
                                     "It cannot be overridden with --force; pick a smaller range."
                        });
                    else
                        warnings.Add(new SafetyBlock
                        {
                            Reason = msg + " - that space is claimed by a live partition. If the recovered " +
                                     "range is authoritative, re-run with --force."
                        });
                }
            }

            foreach (SafetyBlock p in problems)
            {
                Out.Bad("  BLOCKED: " + p.Reason);
            }
            foreach (SafetyBlock w in warnings)
            {
                Out.Warn("  WARNING: " + w.Reason);
            }

            if (problems.Count > 0)
                throw new UserAbortException("Refusing to write: " + problems.Count + " blocking problem(s).");
            if (warnings.Count > 0 && !force)
                throw new UserAbortException("Refusing to write with warnings present. Re-run with --force if you are certain.");
        }

        /// <summary>Checks that apply to writes that only touch the partition table, not a partition range.</summary>
        /// <remarks>
        /// The boot disk is a warning here, not a silent one: like <see cref="Preflight"/> it blocks
        /// the write unless the operator passes --force. Rebuilding the primary GPT is the most
        /// destructive thing this tool does, so it must not be the one command that skips the guard.
        /// </remarks>
        public static void PreflightTableWrite(RawDisk d, bool allowWrite, bool force, bool isImage)
        {
            var problems = new List<SafetyBlock>();
            var warnings = new List<SafetyBlock>();
            if (!allowWrite)
                problems.Add(new SafetyBlock { Reason = "--apply was not passed. This is a read-only invocation." });
            if (!d.CanWrite)
                problems.Add(new SafetyBlock
                {
                    Reason = "device could not be opened for writing: " +
                             (d.ReadOnlyReason ?? "unknown") +
                             ". Run from an elevated (Administrator) command prompt."
                });
            if (d.IsBoot && !isImage)
                warnings.Add(new SafetyBlock
                {
                    Reason = "this is the BOOT disk. Writing here can make Windows unbootable and can " +
                             "destroy the very volume you are trying to rescue."
                });
            foreach (SafetyBlock p in problems) Out.Bad("  BLOCKED: " + p.Reason);
            foreach (SafetyBlock w in warnings) Out.Warn("  WARNING: " + w.Reason);
            if (problems.Count > 0)
                throw new UserAbortException("Refusing to write: " + problems.Count + " blocking problem(s).");
            if (warnings.Count > 0 && !force)
                throw new UserAbortException("Refusing to write with warnings present. Re-run with --force if you are certain.");
        }

        // ------------------------------------------------------------ backup

        public static string BackupEnds(RawDisk d, string outDir)
        {
            Directory.CreateDirectory(outDir);
            string stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
            string baseName = d.IsImage
                ? "image" + d.Index.ToString(CultureInfo.InvariantCulture)
                : "disk" + d.Index.ToString(CultureInfo.InvariantCulture);
            string dir = Path.Combine(outDir, baseName + "-" + stamp);
            Directory.CreateDirectory(dir);

            long first = Math.Min(RegionBytes, d.SizeBytes);
            long lastStart = Math.Max(0, d.SizeBytes - RegionBytes);
            long lastLen = d.SizeBytes - lastStart;

            byte[] head = d.ReadAt(0, (int)first);
            byte[] tail = d.ReadAt(lastStart, (int)lastLen);
            string headName = "head-" + first + ".bin";
            string tailName = "tail-" + lastLen + ".bin";
            string headFile = Path.Combine(dir, headName);
            string tailFile = Path.Combine(dir, tailName);
            File.WriteAllBytes(headFile, head);
            File.WriteAllBytes(tailFile, tail);

            // This backup is the operator's only undo, so never take the write on trust: read both
            // files back and prove they are byte-identical to what came off the device. A truncated
            // or corrupted file aborts the destructive step instead of being discovered afterwards.
            RequireIntact(headFile, head);
            RequireIntact(tailFile, tail);

            var manifest = new StringBuilder();
            manifest.AppendLine("blrecover partition-table safety backup");
            manifest.AppendLine("created     : " + DateTime.UtcNow.ToString("u", CultureInfo.InvariantCulture));
            manifest.AppendLine("device      : " + d.DevicePath);
            manifest.AppendLine("model       : " + d.Model);
            manifest.AppendLine("serial      : " + d.Serial);
            manifest.AppendLine("size bytes  : " + d.SizeBytes.ToString(CultureInfo.InvariantCulture));
            manifest.AppendLine("sector size : " + d.BytesPerSector.ToString(CultureInfo.InvariantCulture));
            manifest.AppendLine("head region : offset 0 length " + first.ToString(CultureInfo.InvariantCulture));
            manifest.AppendLine("  file      : " + headName);
            manifest.AppendLine("  sha256    : " + Sha256Hex(head));
            manifest.AppendLine("tail region : offset " + lastStart.ToString(CultureInfo.InvariantCulture) +
                                " length " + lastLen.ToString(CultureInfo.InvariantCulture));
            manifest.AppendLine("  file      : " + tailName);
            manifest.AppendLine("  sha256    : " + Sha256Hex(tail));
            manifest.AppendLine("verified    : both regions re-read from disk and matched after writing");
            File.WriteAllText(Path.Combine(dir, "MANIFEST.txt"), manifest.ToString(), new UTF8Encoding(false));

            Out.Ok("  safety backup written to: " + dir);
            return dir;
        }

        /// <summary>Re-reads a written backup file and compares it to what was read off the device.</summary>
        private static void RequireIntact(string path, byte[] expected)
        {
            byte[] actual = File.ReadAllBytes(path);
            if (actual.Length != expected.Length)
                throw new IOException("safety backup " + Path.GetFileName(path) + " is " +
                                      actual.Length + " bytes but should be " + expected.Length +
                                      " - aborting before any write to the device.");
            for (int i = 0; i < actual.Length; i++)
            {
                if (actual[i] == expected[i]) continue;
                throw new IOException("safety backup " + Path.GetFileName(path) + " does not match the " +
                                      "device at byte " + i + " - aborting before any write to the device.");
            }
        }

        private static string Sha256Hex(byte[] data)
        {
            using (SHA256 sha = SHA256.Create())
            {
                return BitConverter.ToString(sha.ComputeHash(data)).Replace("-", "").ToLowerInvariant();
            }
        }

        // ------------------------------------------------------------ confirmation

        /// <summary>
        /// The string the operator must type before anything is written. Shown by the host,
        /// which is what makes the gate meaningful - the engine never reads stdin itself.
        /// </summary>
        public static string RequiredConfirmToken(RawDisk d)
        {
            return Fmt.DiskConfirmToken(d.Serial, d.Model, d.Index, d.IsImage);
        }

        public static bool ConfirmTokenMatches(RawDisk d, string typed)
        {
            return typed != null &&
                   string.Equals(typed.Trim(), RequiredConfirmToken(d), StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>Announces a destructive action. Throws to abort.</summary>
        public static void DescribeAction(RawDisk d, string action, params string[] lines)
        {
            Out.H("");
            Out.H("  *** DESTRUCTIVE ACTION: " + action + " ***");
            foreach (string l in lines) Out.Indent(l, 4);
            Out.Indent("device : " + d.DevicePath, 4);
            Out.Indent("model  : " + d.Model, 4);
            Out.Indent("serial : " + d.Serial, 4);
        }

        /// <summary>Console implementation of the confirmation gate.</summary>
        public static void ConsoleConfirm(RawDisk d, string action, string[] lines)
        {
            DescribeAction(d, action, lines);
            Out.Warn("  Type " + RequiredConfirmToken(d) + " and press Enter to continue, anything else to abort:");
            Console.Out.Write("> ");
            Console.Out.Flush();
            string typed = Console.ReadLine();
            if (typed == null) throw new UserAbortException("aborted (no input)");
            if (!ConfirmTokenMatches(d, typed))
                throw new UserAbortException("aborted - confirmation token did not match");
        }

        // ------------------------------------------------------------ GPT operations

        /// <summary>
        /// Rebuilds the primary GPT from the trailing backup GPT. This is the big win after
        /// `diskpart clean`, which only destroys the copy at the start of the disk.
        /// </summary>
        public static string RestoreGptFromBackup(RawDisk d, GptImage backup, bool allowWrite, string backupDir,
                                                  bool force, ConfirmGate gate)
        {
            if (backup == null || !backup.Usable)
                throw new UserAbortException("the backup GPT at the end of the device is not usable, so there is nothing to restore from");

            GptHeader bh = backup.Header;
            Out.Info("  source backup GPT:");
            Out.Indent("LBA " + bh.MyLba + ", alt LBA " + bh.AlternateLba, 4);
            Out.Indent("disk GUID " + bh.DiskGuid, 4);
            Out.Indent(bh.EntryCount + " entries x " + bh.EntrySize + " bytes, array CRC " +
                       (bh.ArrayCrcOk ? "valid" : "INVALID"), 4);

            var layout = new Gpt.Layout();
            layout.DiskGuid = bh.DiskGuid;
            layout.EntryCount = bh.EntryCount;
            layout.EntrySize = bh.EntrySize;
            layout.FirstUsable = bh.FirstUsableLba;
            layout.LastUsable = bh.LastUsableLba;
            foreach (GptEntry e in backup.Entries) layout.Entries.Add(e);

            PreflightTableWrite(d, allowWrite, force, d.IsImage);
            BackupEnds(d, backupDir);
            gate(d, "rebuild the primary GPT from the backup GPT", new[]
            {
                "This rewrites LBA 0 (protective MBR), LBA 1 (header), the entry array,",
                "and the trailing backup GPT. Partition data is never touched."
            });

            Gpt.Write(d, layout);
            Out.Ok("  primary GPT rebuilt from backup.");
            return VerifyGpt(d);
        }

        /// <summary>
        /// Fixes the usable LBA range so it agrees with the device. The range is pure geometry - it
        /// is fully determined by the device size and the size of the entry array - so a header
        /// that disagrees with the device is describing a table that cannot physically exist.
        /// A partially wiped disk commonly leaves exactly that: a primary header with a valid CRC
        /// whose LastUsableLba points into (or past) the backup GPT. Copying those values forward
        /// makes every subsequent write fail validation, which strands the operator. Recomputing
        /// them is safe: nothing is lost, because the range carries no data of its own.
        /// </summary>
        private static void RepairUsableRange(RawDisk d, Gpt.Layout lay, int arrSectors)
        {
            // The last usable LBA is the sector before the backup entry array, which itself sits
            // just before the backup header on the final LBA. This uses the one shared formula so
            // the range we compute here can never disagree with the range we validate against.
            ulong needFirst = (ulong)(2 + arrSectors);
            long maxLastL = (long)Gpt.LastUsableLba(arrSectors, d.SectorCount);
            if (maxLastL < (long)needFirst) maxLastL = (long)needFirst;
            ulong maxLast = (ulong)maxLastL;

            bool bad = lay.FirstUsable < needFirst          // overlaps the primary GPT
                     || lay.LastUsable > maxLast            // overlaps the backup GPT
                     || lay.LastUsable < lay.FirstUsable    // inverted
                     || lay.FirstUsable == 0 || lay.LastUsable == 0;

            if (!bad) return;

            if (lay.FirstUsable != 0 || lay.LastUsable != 0)
                Out.Warn("  the existing GPT header's usable LBA range does not match this device " +
                         "(" + lay.FirstUsable + ".." + lay.LastUsable + "); recomputing it as " +
                         needFirst + ".." + maxLast + ".");
            lay.FirstUsable = needFirst;
            lay.LastUsable = maxLast;
        }

        public static string AddGptPartition(RawDisk d, GptImage source, GptImage other,
                                            ulong first, ulong last, string name, Guid typeGuid,
                                            bool allowWrite, bool force, string backupDir,
                                            IList<LbaRange> inUse, ConfirmGate gate)
        {
            var layout = new Gpt.Layout();

            if (source != null && source.Usable)
            {
                layout.DiskGuid = source.Header.DiskGuid;
                layout.EntryCount = source.Header.EntryCount;
                layout.EntrySize = source.Header.EntrySize;
                layout.FirstUsable = source.Header.FirstUsableLba;
                layout.LastUsable = source.Header.LastUsableLba;
                layout.Entries.AddRange(source.Entries);
            }
            else if (other != null && other.Usable)
            {
                layout.DiskGuid = other.Header.DiskGuid;
                layout.EntryCount = other.Header.EntryCount;
                layout.EntrySize = other.Header.EntrySize;
                layout.FirstUsable = other.Header.FirstUsableLba;
                layout.LastUsable = other.Header.LastUsableLba;
                layout.Entries.AddRange(other.Entries);
                Out.Warn("  no usable primary GPT - rebuilding the whole table from the backup copy.");
            }
            else
            {
                layout.EntryCount = 128;
                layout.EntrySize = 128;
                Out.Warn("  no usable GPT found - creating a fresh 128-entry table with this one partition.");
            }

            int arrSectors = (int)(((long)layout.EntryCount * layout.EntrySize + d.BytesPerSector - 1) / d.BytesPerSector);
            RepairUsableRange(d, layout, arrSectors);

            int slot = -1;
            for (int i = 0; i < layout.Entries.Count; i++)
            {
                if (!layout.Entries[i].InUse) { slot = i; break; }
            }
            if (slot < 0) throw new UserAbortException("no free GPT entry slots - the table is full");

            Preflight(d, allowWrite, inUse, first, last, force, d.IsImage);
            BackupEnds(d, backupDir);
            gate(d, "add a GPT partition entry for the recovered BitLocker volume", new[]
            {
                "Range  : LBA " + first + ".." + last + "  (" + Fmt.HumanSize((long)(last - first + 1) * d.BytesPerSector) + ")",
                "Slot   : " + slot,
                "Type   : " + GptTypes.Name(typeGuid) + "  (" + typeGuid + ")",
                "Name   : " + (string.IsNullOrEmpty(name) ? "(none)" : name),
                "This rewrites both GPT copies. No partition data is written."
            });

            var e = new GptEntry
            {
                SlotIndex = slot,
                TypeGuid = typeGuid,
                UniqueGuid = Guid.NewGuid(),
                FirstLba = first,
                LastLba = last,
                Attributes = 0,
                Name = name ?? ""
            };
            layout.Entries[slot] = e;

            Gpt.Write(d, layout);
            Out.Ok("  partition entry " + slot + " written (LBA " + first + ".." + last + ").");
            return VerifyGpt(d);
        }

        public static string AddMbrPartition(RawDisk d, MbrDisk mbr, int slot, ulong first,
                                             ulong sectors, byte type, bool allowWrite, bool force,
                                             string backupDir, IList<LbaRange> inUse, ConfirmGate gate)
        {
            if (mbr.IsProtectiveForGpt)
                throw new UserAbortException("this disk is GPT-partitioned; use the add-gpt command instead");
            if (sectors > uint.MaxValue)
                throw new UserAbortException("MBR partition length must fit in 32 bits (max " + uint.MaxValue + " sectors)");
            ulong last = first + sectors - 1;

            Preflight(d, allowWrite, inUse, first, last, force, d.IsImage);
            BackupEnds(d, backupDir);
            gate(d, "add an MBR partition entry for the recovered BitLocker volume", new[]
            {
                "Range  : LBA " + first + ".." + last + "  (" + Fmt.HumanSize((long)sectors * d.BytesPerSector) + ")",
                "Slot   : " + slot,
                "Type   : 0x" + type.ToString("X2", CultureInfo.InvariantCulture),
                "This rewrites LBA 0 only. No partition data is written."
            });

            var entry = new MbrEntry
            {
                BootFlag = 0x00,
                Type = type,
                StartLba = (uint)first,
                SectorCount = (uint)sectors
            };
            mbr.WriteEntry(d, slot, entry);
            Out.Ok("  MBR entry " + slot + " written (LBA " + first + ".." + last + ").");
            return VerifyMbr(d);
        }

        // ------------------------------------------------------------ verification

        public static string VerifyGpt(RawDisk d)
        {
            Out.H("  verification (re-read from device):");
            GptImage p = Gpt.ReadPrimary(d);
            GptImage b = Gpt.ReadBackup(d);
            Gpt.Describe(p, d, "primary");
            Gpt.Describe(b, d, "backup ");

            if (p != null && p.Usable && p.Header.ArrayCrcOk) Out.Ok("  primary GPT is structurally valid and CRC-clean.");
            else Out.Bad("  primary GPT still does not verify.");

            var sb = new StringBuilder();
            if (p != null && p.Usable)
            {
                Out.H("  partitions now present:");
                Gpt.PrintEntries(p, d, "    ");
                foreach (GptEntry e in p.Entries)
                {
                    if (!e.InUse) continue;
                    sb.AppendLine("  slot " + e.SlotIndex + " LBA " + e.FirstLba + ".." + e.LastLba);
                }
            }
            List<string> diffs = Gpt.Compare(p, b, d);
            if (diffs.Count == 0 && p != null && b != null && p.Usable && b.Usable)
                Out.Ok("  primary and backup GPT copies agree.");
            else if (diffs.Count > 0)
            {
                Out.Warn("  primary and backup GPT still differ:");
                foreach (string s in diffs) Out.Indent(s, 4);
            }
            return sb.ToString();
        }

        public static string VerifyMbr(RawDisk d)
        {
            Out.H("  verification (re-read from device):");
            MbrDisk m = MbrDisk.Read(d);
            Out.Indent(MbrDisk.Describe(m, d).TrimEnd());
            return string.Empty;
        }
    }
}
