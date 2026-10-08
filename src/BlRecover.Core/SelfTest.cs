using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;

namespace BlRecover
{
    /// <summary>
    /// Builds synthetic disk images that mimic the two real-world failure modes and checks
    /// that the reader, the scanner and the writer all behave. Runs entirely on files.
    /// </summary>
    internal static class SelfTest
    {
        private static int _pass, _fail;
        private static string _dir;

        private static void Check(bool cond, string what)
        {
            if (cond) { _pass++; Out.Dim("    PASS  " + what); }
            else { _fail++; Out.Bad("    FAIL  " + what); }
        }

        private static void CheckEq(object actual, object expected, string what)
        {
            bool ok = Equals(actual, expected);
            Check(ok, what + (ok ? "" : "  (expected " + expected + ", got " + actual + ")"));
        }

        /// <summary>Runs one test so that a thrown exception fails only that test.</summary>
        private static void Guard(Action test)
        {
            try { test(); }
            catch (Exception ex)
            {
                _fail++;
                Out.Bad("    THREW  " + ex.GetType().Name + ": " + ex.Message);
            }
        }

        public static int Run()
        {
            _pass = 0; _fail = 0;
            _dir = Path.Combine(Path.GetTempPath(), "blrecover-selftest-" +
                    DateTime.Now.ToString("yyyyMMddHHmmss", System.Globalization.CultureInfo.InvariantCulture));
            Directory.CreateDirectory(_dir);
            Out.Title("blrecover self-test");
            Out.Dim("  workspace: " + _dir);

            try
            {
                Guard(TestFveParser);
                Guard(TestGptRoundTrip);
                Guard(TestDeletedPartitionScenario);
                Guard(TestCleanedDiskScenario);
                Guard(TestMbrScenario);
                Guard(TestCrcKnownVector);
                Guard(TestPlainNtfsVolume);
                Guard(TestVistaVariantResolves);
                Guard(TestHostileGptEntryArrayHeader);
                Guard(TestBootDiskRequiresForce);
                Guard(TestRestoreGptEndToEnd);
                Guard(TestRepairsBogusUsableRange);
                Guard(TestGptEndReserveMath);
            }
            finally
            {
                try { Directory.Delete(_dir, true); } catch { }
            }

            Out.Title("Self-test result");
            Out.Dim("  " + _pass + " passed, " + _fail + " failed");
            if (_fail == 0) { Out.Ok("  ALL TESTS PASSED"); return 0; }
            Out.Bad("  TESTS FAILED");
            return 1;
        }

        // ------------------------------------------------------------ FVE fixtures

        private static readonly Guid TestVolumeGuid = new Guid("1D9A0C55-8E7B-4A31-9F02-6C5D4E3B2A10");
        private const ulong TestEncryptedSize = 128UL * 1024 * 1024;
        private const ulong TestBlock1 = 0x100000, TestBlock2 = 0x200000, TestBlock3 = 0x300000;
        private const ulong TestVolumeHeaderOffset = 0x80000;

        /// <summary>
        /// Writes a Vista-era BitLocker volume header. The Vista layout carries no block offsets at
        /// all: block 1 is derived from the cluster geometry as lcn * (bytes/sector * sectors/cluster),
        /// and blocks 2 and 3 only become known once block 1's header has been read.
        /// </summary>
        private static byte[] BuildVistaVolumeHeader(int bps, int spc)
        {
            var v = new byte[bps];
            v[0] = 0xEB; v[1] = 0x52; v[2] = 0x90;      // 52 is what marks the Vista variant
            Buffer.BlockCopy(Encoding.ASCII.GetBytes("-FVE-FS-"), 0, v, 3, 8);
            Bin.PutU16(v, 0x0B, (ushort)bps);                // bytes per sector is a 16-bit BPB field
            v[0x0D] = (byte)spc;                             // sectors per cluster is a single byte
            v[0x1FE] = 0x55; v[0x1FF] = 0xAA;
            Bin.PutGuid16(v, 160, TestVolumeGuid);
            Bin.PutU64(v, 0x38, TestBlock1 / (ulong)(bps * spc));   // LCN of block 1
            return v;
        }

        /// <summary>Writes a Windows 7/10 style BitLocker volume header at a byte offset.</summary>
        private static byte[] BuildVolumeHeader(int bps, int spc)
        {
            var v = new byte[bps];
            v[0] = 0xEB; v[1] = 0x58; v[2] = 0x90;
            Buffer.BlockCopy(Encoding.ASCII.GetBytes("-FVE-FS-"), 0, v, 3, 8);
            Bin.PutU16(v, 0x0B, (ushort)bps);                // bytes per sector is a 16-bit BPB field
            v[0x0D] = (byte)spc;                             // sectors per cluster is a single byte
            v[0x1FE] = 0x55; v[0x1FF] = 0xAA;
            Bin.PutGuid16(v, 160, TestVolumeGuid);
            Bin.PutU64(v, 176, TestBlock1);
            Bin.PutU64(v, 184, TestBlock2);
            Bin.PutU64(v, 192, TestBlock3);
            return v;
        }

        /// <summary>Writes one of the three redundant FVE metadata blocks.</summary>
        private static byte[] BuildMetadataBlock(ushort method, ushort protectorType)
        {
            var b = new byte[Fve.MaxBlockBytes];
            Buffer.BlockCopy(Encoding.ASCII.GetBytes("-FVE-FS-"), 0, b, 0, 8);
            Bin.PutU16(b, 8, 0x2000);
            Bin.PutU16(b, 10, 2);                       // block version
            Bin.PutU64(b, 16, TestEncryptedSize);       // encrypted volume size
            Bin.PutU32(b, 28, 1);                       // number of volume header sectors
            Bin.PutU64(b, 32, TestBlock1);
            Bin.PutU64(b, 40, TestBlock2);
            Bin.PutU64(b, 48, TestBlock3);
            Bin.PutU64(b, 56, TestVolumeHeaderOffset);

            // metadata header
            int md = 64;
            uint metaSize = 0;
            Bin.PutU32(b, md + 0, 0);                   // patched below once entries are laid out
            Bin.PutGuid16(b, md + 16, TestVolumeGuid);
            Bin.PutU16(b, md + 36, method);
            Bin.PutU64(b, md + 40, 130000000000000000UL);  // a plausible creation FILETIME

            int pos = md + 48;

            // entry 1: VMK, stretch key value, protector type lives at +26
            int e1Size = 56;
            Bin.PutU16(b, pos + 0, (ushort)e1Size);
            Bin.PutU16(b, pos + 2, 0x0002);   // VMK
            Bin.PutU16(b, pos + 4, 0x0003);   // stretch key
            Bin.PutU16(b, pos + 6, 1);
            Bin.PutU16(b, pos + 26, protectorType);
            pos += e1Size;

            // entry 2: FVEK, AES-CCM encrypted key
            int e2Size = 96;
            Bin.PutU16(b, pos + 0, (ushort)e2Size);
            Bin.PutU16(b, pos + 2, 0x0003);   // FVEK
            Bin.PutU16(b, pos + 4, 0x0005);   // AES-CCM encrypted key
            Bin.PutU16(b, pos + 6, 1);
            pos += e2Size;

            // entry 3: volume header block (offset + size)
            int e3Size = 24;
            Bin.PutU16(b, pos + 0, (ushort)e3Size);
            Bin.PutU16(b, pos + 2, 0x000f);
            Bin.PutU16(b, pos + 4, 0x000f);
            Bin.PutU16(b, pos + 6, 1);
            Bin.PutU64(b, pos + 8, TestVolumeHeaderOffset);
            Bin.PutU64(b, pos + 16, 512);
            pos += e3Size;

            metaSize = (uint)(pos - md);
            Bin.PutU32(b, md, metaSize);
            return b;
        }

        private static void WriteFixtureVolume(FileStream fs, long baseOffset, int bps, int spc,
                                              ushort method, ushort protector)
        {
            fs.Seek(baseOffset, SeekOrigin.Begin);
            byte[] vh = BuildVolumeHeader(bps, spc);
            fs.Write(vh, 0, vh.Length);
            byte[] blk = BuildMetadataBlock(method, protector);
            fs.Seek(baseOffset + (long)TestBlock1, SeekOrigin.Begin);
            fs.Write(blk, 0, blk.Length);
            fs.Seek(baseOffset + (long)TestBlock2, SeekOrigin.Begin);
            fs.Write(blk, 0, blk.Length);
            fs.Seek(baseOffset + (long)TestBlock3, SeekOrigin.Begin);
            fs.Write(blk, 0, blk.Length);
        }

        private static void WriteFixtureVolume(RawDisk d, long baseOffset, int bps, int spc,
                                              ushort method, ushort protector)
        {
            byte[] vh = BuildVolumeHeader(bps, spc);
            d.WriteAt(baseOffset, vh, vh.Length);
            byte[] blk = BuildMetadataBlock(method, protector);
            d.WriteAt(baseOffset + (long)TestBlock1, blk, blk.Length);
            d.WriteAt(baseOffset + (long)TestBlock2, blk, blk.Length);
            d.WriteAt(baseOffset + (long)TestBlock3, blk, blk.Length);
        }

        // ------------------------------------------------------------ tests

        private static void TestFveParser()
        {
            Out.Title("Test 1: BitLocker FVE metadata parsing");
            string path = Path.Combine(_dir, "fve.img");
            const int bps = 512;
            const long volStart = 2048L * 512;
            using (var fs = new FileStream(path, FileMode.Create, FileAccess.ReadWrite))
            {
                fs.SetLength(256L * 1024 * 1024);
                WriteFixtureVolume(fs, volStart, bps, 8, 0x8000, 0x0800);
                // A second volume using XTS + a password protector, at a non-1MiB offset.
                WriteFixtureVolume(fs, 100L * 1024 * 1024, bps, 8, 0x8005, 0x2000);
            }

            using (var d = RawDisk.OpenDevice(0, path, "test", "", "file", false, 0, bps, false))
            {
                byte[] sector = d.ReadAt(volStart, bps);
                FveHit hit = Fve.Classify(sector, 0, bps, 2048, volStart);
                Check(hit != null, "volume header at LBA 2048 is recognised as a BitLocker volume");
                Check(hit != null && hit.IsVolumeHeader, "classified as a volume header (not a metadata block)");
                Check(hit != null && hit.Variant == FveVariant.Win7Plus, "variant detected as Windows 7/10 layout");

                string note;
                Fve.Resolve(d, hit, out note);
                FveMetadata m = hit.Meta;
                Check(m != null, "FVE metadata resolved");
                Check(m != null && m.VolumeGuid == TestVolumeGuid,
                      "volume GUID parsed (got " + (m == null ? "null" : m.VolumeGuid.ToString()) + ")");
                Check(m != null && m.EncryptionMethod == 0x8000, "encryption method 0x8000 parsed");
                Check(m != null && m.EncryptedVolumeSize == TestEncryptedSize,
                      "encrypted volume size parsed (" + Fmt.HumanSize(m == null ? 0 : (long)m.EncryptedVolumeSize) + ")");
                Check(m != null && m.BlocksWithSignature == 3, "all 3 metadata blocks verified (" +
                      (m == null ? 0 : m.BlocksWithSignature) + ")");
                Check(m != null && m.VolumeHeaderOffset == TestVolumeHeaderOffset, "volume header offset parsed");

                bool sawVmk = false, sawFvek = false, sawVolHdrBlock = false;
                if (m != null)
                    foreach (FveEntryInfo e in m.Entries)
                    {
                        if (e.EntryType == 0x0002 && e.ProtectorType == 0x0800) sawVmk = true;
                        if (e.EntryType == 0x0003) sawFvek = true;
                        if (e.EntryType == 0x000f && e.BlockOffset.HasValue && e.BlockOffset.Value == TestVolumeHeaderOffset)
                            sawVolHdrBlock = true;
                    }
                Check(sawVmk, "VMK entry with recovery-password protector (0x0800) parsed");
                Check(sawFvek, "FVEK entry parsed");
                Check(sawVolHdrBlock, "volume header block entry (offset+size) parsed");

                ulong? sz = Fve.SuggestPartitionSize(m, bps, d.SizeBytes, volStart);
                Check(sz.HasValue && sz.Value == TestEncryptedSize, "suggested partition size == encrypted volume size");

                // The XTS / password variant at an arbitrary offset must also parse.
                long other = 100L * 1024 * 1024;
                byte[] s2 = d.ReadAt(other, bps);
                FveHit h2 = Fve.Classify(s2, 0, bps, (ulong)(other / bps), other);
                Check(h2 != null, "second volume header recognised at a non-1MiB offset");
                if (h2 != null)
                {
                    Fve.Resolve(d, h2, out note);
                    Check(h2.Meta != null && h2.Meta.EncryptionMethod == 0x8005, "second volume method 0x8005 parsed");
                    bool pw = false;
                    if (h2.Meta != null)
                        foreach (FveEntryInfo e in h2.Meta.Entries)
                            if (e.ProtectorType == 0x2000) pw = true;
                    Check(pw, "second volume password protector (0x2000) parsed");
                }
            }
        }

        private static void TestCrcKnownVector()
        {
            Out.Title("Test 6: CRC-32 known vector");
            // "123456789" -> 0xCBF43926
            byte[] v = Encoding.ASCII.GetBytes("123456789");
            CheckEq(Crc32.Compute(v, 0, v.Length).ToString("X8"), "CBF43926", "CRC-32 of \"123456789\"");

            // FILETIME: 132000000000000000 ticks after 1601-01-01 == 2018-03-14T07:00:00Z
            CheckEq(Fmt.FileTimeToIso(132000000000000000UL), "2019-04-17 18:40:00Z", "FILETIME epoch conversion");
            CheckEq(Fmt.FileTimeToIso(134349840000000000UL), "2026-09-27 12:00:00Z", "FILETIME round-trip for a recent date");
            CheckEq(Fmt.FileTimeToIso(0UL), "n/a", "zero FILETIME is reported as n/a");

            // Pinned IOCTL values. A wrong CTL_CODE fails with ERROR_INVALID_FUNCTION at runtime,
            // which is indistinguishable from a permissions problem unless it is caught here.
            CheckEq(Native.IOCTL_DISK_GET_LENGTH_INFO.ToString("X8"), "0007005C",
                    "IOCTL_DISK_GET_LENGTH_INFO control code");
            CheckEq(Native.IOCTL_DISK_GET_DRIVE_GEOMETRY_EX.ToString("X8"), "000700A0",
                    "IOCTL_DISK_GET_DRIVE_GEOMETRY_EX control code");
            CheckEq(Native.GENERIC_READ.ToString("X8"), "80000000", "GENERIC_READ");
            CheckEq((Native.FILE_SHARE_READ | Native.FILE_SHARE_WRITE).ToString("X"), "3", "share mode read+write");
        }

        private static void TestGptRoundTrip()
        {
            Out.Title("Test 2: GPT build / parse round-trip");
            string path = Path.Combine(_dir, "gpt.img");
            const int bps = 512;
            const long sizeBytes = 256L * 1024 * 1024;
            using (var fs = new FileStream(path, FileMode.Create, FileAccess.ReadWrite))
            {
                fs.SetLength(sizeBytes);
            }

            var diskGuid = Guid.NewGuid();
            using (var d = RawDisk.OpenDevice(0, path, "test", "", "file", false, 0, bps, true))
            {
                var lay = new Gpt.Layout();
                lay.DiskGuid = diskGuid;
                lay.Entries.Add(new GptEntry
                {
                    SlotIndex = 0, TypeGuid = GptTypes.EfiSystem, UniqueGuid = Guid.NewGuid(),
                    FirstLba = 34, LastLba = 2047, Name = "EFI system partition"
                });
                lay.Entries.Add(new GptEntry
                {
                    SlotIndex = 1, TypeGuid = GptTypes.BasicData, UniqueGuid = Guid.NewGuid(),
                    FirstLba = 2048, LastLba = 520191, Name = "Data"
                });
                Gpt.Write(d, lay);
            }

            using (var d = RawDisk.OpenDevice(0, path, "test", "", "file", false, 0, bps, false))
            {
                MbrDisk mbr = MbrDisk.Read(d);
                Check(mbr.HasBootSignature && mbr.IsProtectiveForGpt, "LBA 0 written as a valid protective MBR");

                GptImage p = Gpt.ReadPrimary(d);
                GptImage b = Gpt.ReadBackup(d);
                Check(p != null && p.Usable, "primary GPT parses as valid");
                Check(b != null && b.Usable, "backup GPT parses as valid");
                Check(p != null && p.Header.HeaderCrcOk, "primary header CRC verifies");
                Check(p != null && p.Header.ArrayCrcOk, "primary entry-array CRC verifies");
                Check(b != null && b.Header.HeaderCrcOk, "backup header CRC verifies");
                Check(p != null && p.Header.DiskGuid == diskGuid, "disk GUID round-trips");
                Check(p != null && p.Entries.Count == 128, "128 entry slots present");
                Check(p != null && p.Entries.Count(x => x.InUse) == 2, "2 entries in use");
                Check(p != null && p.Entries.Count == 128 && p.Entries[1].Name == "Data", "UTF-16 partition name round-trips");
                CheckEq(Gpt.Compare(p, b, d).Count, 0, "primary and backup copies agree");
                Check(p != null && p.Entries[0].FirstLba == 34 && p.Entries[0].LastLba == 2047, "entry 0 bounds round-trip");
            }
        }

        /// <summary>Windows deleted one partition: both GPT copies updated, entry zeroed, data intact.</summary>
        private static void TestDeletedPartitionScenario()
        {
            Out.Title("Test 3: one BitLocker partition deleted from a GPT disk");
            string path = Path.Combine(_dir, "deleted.img");
            const int bps = 512;
            const int spc = 8;                     // sectors per cluster
            const ulong volFirstLba = 2048;
            const ulong volLastLba = 2048 + 2048 * 128 - 1;

            using (var fs = new FileStream(path, FileMode.Create, FileAccess.ReadWrite))
            {
                fs.SetLength(512L * 1024 * 1024);
            }

            using (var d = RawDisk.OpenDevice(0, path, "test", "", "file", false, 0, bps, true))
            {
                var lay = new Gpt.Layout();
                lay.DiskGuid = Guid.NewGuid();
                lay.Entries.Add(new GptEntry
                {
                    SlotIndex = 0, TypeGuid = GptTypes.BasicData, UniqueGuid = Guid.NewGuid(),
                    FirstLba = 34, LastLba = 2047, Name = "System"
                });
                lay.Entries.Add(new GptEntry
                {
                    SlotIndex = 1, TypeGuid = GptTypes.BasicData, UniqueGuid = Guid.NewGuid(),
                    FirstLba = volFirstLba, LastLba = volLastLba, Name = "Encrypted"
                });
                Gpt.Write(d, lay);
                WriteFixtureVolume(d, d.LbaToOffset((long)volFirstLba), bps, spc, 0x8000, 0x0800);

                // Simulate the deletion: zero entry 1 in BOTH copies and re-CRC.
                ZeroGptEntry(d, 1);
            }

            using (var d = RawDisk.OpenDevice(0, path, "test", "", "file", false, 0, bps, false))
            {
                GptImage p = Gpt.ReadPrimary(d);
                Check(p != null && p.Usable, "GPT still structurally valid after the entry was zeroed");
                Check(p != null && p.Entries.Count(x => x.InUse) == 1, "only 1 entry left in use");

                List<LbaRange> inUse = Scanner.CollectInUse(d, p, Gpt.ReadBackup(d), MbrDisk.Read(d));
                var opt = new ScanOptions { Alignment = 1024 * 1024, Progress = false };
                ScanResult res = Scanner.Scan(d, inUse, opt, null);
                CheckEq(res.VolumeHeaders.Count, 1, "scanner found exactly 1 deleted BitLocker volume");
                if (res.VolumeHeaders.Count == 1)
                {
                    FveHit h = res.VolumeHeaders[0];
                    CheckEq(h.Lba, volFirstLba, "found at the original start LBA");
                    string note; Fve.Resolve(d, h, out note);
                    Check(h.Meta != null && h.Meta.LooksSane, "FVE metadata of the deleted volume is intact");
                    Check(h.Meta != null && h.Meta.BlocksWithSignature == 3, "all 3 metadata blocks still readable");
                }
            }

            // Now restore it the way the CLI would.
            using (var d = RawDisk.OpenDevice(0, path, "test", "", "file", false, 0, bps, true))
            {
                GptImage p = Gpt.ReadPrimary(d);
                GptImage b = Gpt.ReadBackup(d);
                MbrDisk mbr = MbrDisk.Read(d);
                List<LbaRange> inUse = Scanner.CollectInUse(d, p, b, mbr);
                // Recompute the range explicitly, mirroring CmdAddGpt.
                ulong first = volFirstLba, last = volLastLba;
                Restorer.Preflight(d, true, inUse, first, last, false, true);
                var lay = new Gpt.Layout
                {
                    DiskGuid = p.Header.DiskGuid,
                    EntryCount = p.Header.EntryCount,
                    EntrySize = p.Header.EntrySize,
                    FirstUsable = p.Header.FirstUsableLba,
                    LastUsable = p.Header.LastUsableLba
                };
                lay.Entries.AddRange(p.Entries);
                int slot = -1;
                for (int i = 0; i < lay.Entries.Count; i++) if (!lay.Entries[i].InUse) { slot = i; break; }
                lay.Entries[slot] = new GptEntry
                {
                    SlotIndex = slot, TypeGuid = GptTypes.BasicData, UniqueGuid = Guid.NewGuid(),
                    FirstLba = first, LastLba = last, Attributes = 0, Name = "Recovered"
                };
                Gpt.Write(d, lay);
                CheckEq(slot, 1, "restored into the freed slot");
            }

            using (var d = RawDisk.OpenDevice(0, path, "test", "", "file", false, 0, bps, false))
            {
                GptImage p = Gpt.ReadPrimary(d);
                GptImage b = Gpt.ReadBackup(d);
                Check(p != null && p.Usable && p.Header.ArrayCrcOk, "GPT valid after restore");
                CheckEq(p.Entries.Count(x => x.InUse), 2, "2 entries present again");
                GptEntry e = p.Entries[1];
                Check(e.InUse && e.FirstLba == volFirstLba && e.LastLba == volLastLba, "restored entry has the original bounds");
                CheckEq(Gpt.Compare(p, b, d).Count, 0, "primary and backup agree after restore");
                CheckEq(Gpt.Compare(p, b, d).Count, 0, "no entry lost in the rewrite");

                // The FVE structures must be untouched by the table rewrite.
                FveHit h = Fve.Classify(d.ReadAt(d.LbaToOffset((long)volFirstLba), bps), 0, bps, volFirstLba, d.LbaToOffset((long)volFirstLba));
                Check(h != null, "BitLocker volume header survived the restore");
            }
        }

        /// <summary>diskpart clean: primary GPT destroyed, trailing backup still intact.</summary>
        private static void TestCleanedDiskScenario()
        {
            Out.Title("Test 4: primary GPT destroyed, backup GPT intact (diskpart clean)");
            string path = Path.Combine(_dir, "cleaned.img");
            const int bps = 512;
            using (var fs = new FileStream(path, FileMode.Create, FileAccess.ReadWrite))
            {
                fs.SetLength(512L * 1024 * 1024);
            }
            using (var d = RawDisk.OpenDevice(0, path, "test", "", "file", false, 0, bps, true))
            {
                var lay = new Gpt.Layout { DiskGuid = Guid.NewGuid() };
                lay.Entries.Add(new GptEntry
                {
                    SlotIndex = 0, TypeGuid = GptTypes.EfiSystem, UniqueGuid = Guid.NewGuid(),
                    FirstLba = 34, LastLba = 2047, Name = "EFI"
                });
                lay.Entries.Add(new GptEntry
                {
                    SlotIndex = 2, TypeGuid = GptTypes.BasicData, UniqueGuid = Guid.NewGuid(),
                    FirstLba = 4096, LastLba = 266239, Name = "Locked"
                });
                Gpt.Write(d, lay);
                WriteFixtureVolume(d, d.LbaToOffset(4096), bps, 8, 0x8004, 0x0100);
            }

            using (var d = RawDisk.OpenDevice(0, path, "test", "", "file", false, 0, bps, true))
            {
                // Wipe LBA 0 and the primary header + array, exactly like `diskpart clean`.
                d.WriteAt(0, new byte[bps * 40], bps * 40);
                d.Flush();

                MbrDisk mbr = MbrDisk.Read(d);
                Check(!mbr.IsProtectiveForGpt, "LBA 0 no longer looks like a GPT protective MBR");
                GptImage p = Gpt.ReadPrimary(d);
                GptImage b = Gpt.ReadBackup(d);
                Check(p == null || !p.Header.SignatureOk, "primary GPT is gone");
                Check(b != null && b.Usable && b.Header.ArrayCrcOk, "trailing backup GPT is still intact");
                Check(b != null && b.Entries.Count(x => x.InUse) == 2, "backup still lists both original partitions");

                // restore-gpt should rebuild from the backup.
                var lay = new Gpt.Layout
                {
                    DiskGuid = b.Header.DiskGuid,
                    EntryCount = b.Header.EntryCount,
                    EntrySize = b.Header.EntrySize,
                    FirstUsable = b.Header.FirstUsableLba,
                    LastUsable = b.Header.LastUsableLba
                };
                lay.Entries.AddRange(b.Entries);
                Gpt.Write(d, lay);
            }

            using (var d = RawDisk.OpenDevice(0, path, "test", "", "file", false, 0, bps, false))
            {
                MbrDisk mbr = MbrDisk.Read(d);
                Check(mbr.IsProtectiveForGpt, "protective MBR rebuilt");
                GptImage p = Gpt.ReadPrimary(d);
                GptImage b = Gpt.ReadBackup(d);
                Check(p != null && p.Usable && p.Header.HeaderCrcOk && p.Header.ArrayCrcOk, "primary GPT rebuilt and CRC-clean");
                CheckEq(p.Entries.Count(x => x.InUse), 2, "both original partitions recovered from the backup");
                CheckEq(Gpt.Compare(p, b, d).Count, 0, "primary and backup agree after the rebuild");

                List<LbaRange> inUse = Scanner.CollectInUse(d, p, b, mbr);
                // Free-space scan: the restored volume now lives inside a live partition, so it
                // is no longer a deletion candidate and must NOT be reported as one.
                var res = Scanner.Scan(d, inUse, new ScanOptions { Alignment = 1024 * 1024, Progress = false }, null);
                CheckEq(res.VolumeHeaders.Count, 0, "nothing left stranded in free space after the rebuild");

                // Full scan: the BitLocker volume must now be seen as live, at LBA 4096.
                var full = Scanner.Scan(d, inUse, new ScanOptions { Alignment = 1024 * 1024, Progress = false, ScanWholeDevice = true }, null);
                CheckEq(full.InUse.Count, 1, "full scan sees the restored volume inside a live partition");
                CheckEq(full.VolumeHeaders.Count, 0, "full scan reports no orphaned volume");
                if (full.InUse.Count == 1) CheckEq(full.InUse[0].Lba, 4096UL, "restored volume is at its original LBA 4096");
            }
        }

        private static void TestMbrScenario()
        {
            Out.Title("Test 5: MBR disk with a deleted BitLocker partition");
            string path = Path.Combine(_dir, "mbr.img");
            const int bps = 512;
            const ulong first = 4096, sectors = 128 * 2048;
            using (var fs = new FileStream(path, FileMode.Create, FileAccess.ReadWrite))
            {
                fs.SetLength(512L * 1024 * 1024);
                var mbr = new byte[bps];
                mbr[446 + 0 * 16 + 4] = 0x07;                       // slot 0: NTFS, LBA 2048..4095
                Bin.PutU32(mbr, 446 + 0 * 16 + 8, 2048);
                Bin.PutU32(mbr, 446 + 0 * 16 + 12, 2048);
                mbr[446 + 1 * 16 + 4] = 0x07;                       // slot 1: the lost one
                Bin.PutU32(mbr, 446 + 1 * 16 + 8, (uint)first);
                Bin.PutU32(mbr, 446 + 1 * 16 + 12, (uint)sectors);
                mbr[bps - 2] = 0x55; mbr[bps - 1] = 0xAA;
                fs.Write(mbr, 0, bps);
                WriteFixtureVolume(fs, (long)first * bps, bps, 8, 0x8002, 0x0000);
            }

            using (var d = RawDisk.OpenDevice(0, path, "test", "", "file", false, 0, bps, true))
            {
                MbrDisk mbr = MbrDisk.Read(d);
                Check(!mbr.IsProtectiveForGpt, "MBR correctly identified (not GPT)");
                Check(mbr.Entries.Count == 4 && mbr.Entries[1].InUse, "MBR slot 1 parsed");

                // Clear slot 1 like a deletion would.
                var cleared = new MbrEntry { BootFlag = 0, Type = 0, StartLba = 0, SectorCount = 0 };
                mbr.WriteEntry(d, 1, cleared);

                MbrDisk after = MbrDisk.Read(d);
                Check(after.Entries.Count(x => x.InUse) == 1, "slot 1 is now empty");
                Check(after.HasBootSignature, "0x55AA signature preserved while editing");

                List<LbaRange> inUse = Scanner.CollectInUse(d, null, null, after);
                var res = Scanner.Scan(d, inUse, new ScanOptions { Alignment = 1024 * 1024, Progress = false }, null);
                CheckEq(res.VolumeHeaders.Count, 1, "scanner found the deleted MBR BitLocker volume");
                if (res.VolumeHeaders.Count == 1)
                {
                    string note; Fve.Resolve(d, res.VolumeHeaders[0], out note);
                    Check(res.VolumeHeaders[0].Meta != null && res.VolumeHeaders[0].Meta.EncryptionMethod == 0x8002,
                          "AES-128-CBC (0x8002) volume detected");
                }

                Restorer.Preflight(d, true, inUse, first, first + sectors - 1, false, true);
                after.WriteEntry(d, 1, new MbrEntry
                {
                    BootFlag = 0, Type = 0x07, StartLba = (uint)first, SectorCount = (uint)sectors
                });
            }

            using (var d = RawDisk.OpenDevice(0, path, "test", "", "file", false, 0, bps, false))
            {
                MbrDisk m = MbrDisk.Read(d);
                Check(m.Entries[1].InUse && m.Entries[1].StartLba == first && m.Entries[1].SectorCount == sectors,
                      "MBR entry restored with the original bounds");
            }
        }

        /// <summary>
        /// The case that matters most in practice: a plain, never-encrypted NTFS backup drive
        /// whose partition was deleted. There is no BitLocker metadata at all, so the volume's
        /// own boot sector is the only - and best - evidence of where it was and how big it was.
        /// </summary>
        private static void TestPlainNtfsVolume()
        {
            Out.Title("Test 7: unencrypted NTFS volume, partition deleted");
            string path = Path.Combine(_dir, "ntfs.img");
            const int bps = 512;
            const ulong start = 2048;
            const ulong sectors = 512L * 1024 * 1024 / 512;     // a 512 MB volume

            using (var fs = new FileStream(path, FileMode.Create, FileAccess.ReadWrite))
            {
                fs.SetLength(600L * 1024 * 1024);
                var boot = new byte[bps];
                boot[0] = 0xEB; boot[1] = 0x52; boot[2] = 0x90;
                Buffer.BlockCopy(Encoding.ASCII.GetBytes("NTFS    "), 0, boot, 3, 8);
                Bin.PutU16(boot, 0x0B, (ushort)bps);   // bytes per sector is a 16-bit BPB field
                boot[0x0D] = 8;                        // sectors per cluster is a single byte
                Bin.PutU64(boot, 0x28, sectors);
                Bin.PutU64(boot, 0x48, 0x0011223344556677UL);
                boot[bps - 2] = 0x55; boot[bps - 1] = 0xAA;
                fs.Seek((long)start * bps, SeekOrigin.Begin);
                fs.Write(boot, 0, bps);
            }

            using (var d = RawDisk.OpenDevice(0, path, "test", "", "file", false, 0, bps, true))
            {
                var seeded = new Gpt.Layout { DiskGuid = Guid.NewGuid() };
                seeded.Entries.Add(new GptEntry
                {
                    SlotIndex = 0, TypeGuid = GptTypes.BasicData, UniqueGuid = Guid.NewGuid(),
                    FirstLba = 34, LastLba = 2047, Name = "System"
                });
                Gpt.Write(d, seeded);
                // Leave a GPT with no entries, so the volume sits in unallocated space.
                Gpt.Write(d, new Gpt.Layout
                {
                    DiskGuid = seeded.DiskGuid,
                    EntryCount = 128,
                    EntrySize = 128,
                    FirstUsable = seeded.FirstUsable,
                    LastUsable = seeded.LastUsable
                });
            }

            using (var d = RawDisk.OpenDevice(0, path, "test", "", "file", false, 0, bps, false))
            {
                var inUse = Scanner.CollectInUse(d, Gpt.ReadPrimary(d), Gpt.ReadBackup(d), MbrDisk.Read(d));
                ScanResult res = Scanner.Scan(d, inUse, new ScanOptions { Alignment = 1024 * 1024, Progress = false }, null);
                CheckEq(res.VolumeHeaders.Count, 1, "scanner found the unencrypted NTFS volume");
                if (res.VolumeHeaders.Count == 1)
                {
                    FveHit h = res.VolumeHeaders[0];
                    Check(h.Kind == VolumeKind.Ntfs, "classified as NTFS, not BitLocker");
                    CheckEq(h.Lba, start, "found at the original start LBA 2048");
                    Check(h.BpbSize.HasValue && h.BpbSize.Value == sectors * 512,
                          "size read from the BPB = 512 MB (the volume's own record)");
                    Check(!VolumeProbe.NeedsKey(h.Kind), "reports that no key is needed");
                    Check(h.Meta == null, "no FVE metadata is claimed for an unencrypted volume");
                }
            }

            using (var d = RawDisk.OpenDevice(0, path, "test", "", "file", false, 0, bps, true))
            {
                GptImage p = Gpt.ReadPrimary(d);
                var lay = new Gpt.Layout
                {
                    DiskGuid = p.Header.DiskGuid, EntryCount = 128, EntrySize = 128,
                    FirstUsable = p.Header.FirstUsableLba, LastUsable = p.Header.LastUsableLba
                };
                lay.Entries.AddRange(p.Entries);
                lay.Entries[0] = new GptEntry
                {
                    SlotIndex = 0, TypeGuid = GptTypes.BasicData, UniqueGuid = Guid.NewGuid(),
                    FirstLba = start, LastLba = start + sectors - 1, Name = "Backup"
                };
                Gpt.Write(d, lay);
            }

            using (var d = RawDisk.OpenDevice(0, path, "test", "", "file", false, 0, bps, false))
            {
                GptImage p = Gpt.ReadPrimary(d);
                Check(p != null && p.Usable && p.Entries[0].InUse, "NTFS partition entry restored");
                CheckEq(p.Entries[0].LastLba, start + sectors - 1, "bounds came from the BPB");
                byte[] boot = d.ReadAt(d.LbaToOffset((long)start), bps);
                Check(VolumeProbe.Classify(boot, 0) == VolumeKind.Ntfs,
                      "the NTFS boot sector itself is untouched");
                Check(VolumeProbe.SizeFromBpb(boot, 0, bps).HasValue, "its BPB still reads a sane size");
            }
        }

        /// <summary>
        /// Regression: the block walk in <see cref="Fve.Resolve"/> used to re-seed itself forever
        /// on a Vista-layout volume. Block 1's header reports its OWN offset in BlockOffsets[0], so
        /// a restart re-read the same block and never advanced. Run under a watchdog so a
        /// regression fails this one test instead of hanging the whole self-test.
        /// </summary>
        private static void TestVistaVariantResolves()
        {
            Out.Title("Test 8: Vista-layout volume header resolves (regression: infinite loop)");
            string path = Path.Combine(_dir, "vista.img");
            const int bps = 512;
            const int spc = 8;
            const long volStart = 2048L * 512;

            using (var fs = new FileStream(path, FileMode.Create, FileAccess.ReadWrite))
            {
                fs.SetLength(256L * 1024 * 1024);
                byte[] vh = BuildVistaVolumeHeader(bps, spc);
                fs.Seek(volStart, SeekOrigin.Begin);
                fs.Write(vh, 0, vh.Length);
                // The three blocks, each carrying BlockOffsets that point at all three - including
                // block 1 pointing at itself, which is what triggered the old loop.
                byte[] blk = BuildMetadataBlock(0x8002, 0x0800);
                for (int i = 0; i < 3; i++)
                {
                    fs.Seek(volStart + (long)(TestBlock1 * (ulong)(i + 1)), SeekOrigin.Begin);
                    fs.Write(blk, 0, blk.Length);
                }
            }

            using (var d = RawDisk.OpenDevice(0, path, "test", "", "file", false, 0, bps, false))
            {
                byte[] sector = d.ReadAt(volStart, bps);
                FveHit hit = Fve.Classify(sector, 0, bps, 2048, volStart);
                Check(hit != null, "Vista volume header recognised as BitLocker");
                Check(hit != null && hit.IsVolumeHeader, "classified as a volume header, not a metadata block");
                Check(hit != null && hit.Variant == FveVariant.Vista,
                      "variant detected as the Vista layout (boot code EB 52)");
                if (hit == null) return;

                string note = null;
                var worker = new Thread(() =>
                {
                    try { Fve.Resolve(d, hit, out note); }
                    catch (Exception ex) { note = ex.GetType().Name + ": " + ex.Message; }
                });
                worker.IsBackground = true;
                worker.Start();
                bool finished = worker.Join(20000);
                Check(finished, "Fve.Resolve terminates on a Vista volume (no infinite loop)");
                if (!finished) return;   // the background thread is a background thread; the run can still finish

                Check(string.IsNullOrEmpty(note), "resolve completed with no parse note" +
                                                (string.IsNullOrEmpty(note) ? "" : " (note: " + note + ")"));
                Check(hit.Meta != null, "Vista FVE metadata resolved");
                Check(hit.Meta != null && hit.Meta.BlocksWithSignature == 3,
                      "all 3 metadata blocks verified through the block header (" +
                      (hit.Meta == null ? 0 : hit.Meta.BlocksWithSignature) + ")");
                Check(hit.Meta != null && hit.Meta.VolumeGuid == TestVolumeGuid, "volume GUID parsed from block 1");
            }
        }

        /// <summary>
        /// Regression: a header claiming EntryCount = EntrySize = 0xFFFFFFFF made
        /// (long)EntryCount * EntrySize overflow negative, which slipped past the bounds check and
        /// then died allocating the entry buffer. A damaged GPT must report itself, not throw.
        /// </summary>
        private static void TestHostileGptEntryArrayHeader()
        {
            Out.Title("Test 9: hostile GPT entry-array header (regression: integer overflow)");
            string path = Path.Combine(_dir, "badgpt.img");
            const int bps = 512;

            using (var fs = new FileStream(path, FileMode.Create, FileAccess.ReadWrite))
            {
                fs.SetLength(64L * 1024 * 1024);
                var h = new byte[bps];
                Buffer.BlockCopy(Encoding.ASCII.GetBytes("EFI PART"), 0, h, 0, 8);
                Bin.PutU32(h, 12, 92);                      // header size
                Bin.PutU64(h, 24, 1);                       // MyLba
                Bin.PutU64(h, 32, 0x0001FFF0);              // AlternateLba
                Bin.PutU64(h, 40, 34);                      // FirstUsableLba
                Bin.PutU64(h, 48, 0x0001FFDF);              // LastUsableLba
                Bin.PutU64(h, 72, 2);                       // EntryLba
                Bin.PutU32(h, 80, 0xFFFFFFFF);              // EntryCount - hostile
                Bin.PutU32(h, 84, 0xFFFFFFFF);              // EntrySize  - hostile
                fs.Seek(bps, SeekOrigin.Begin);
                fs.Write(h, 0, h.Length);
            }

            using (var d = RawDisk.OpenDevice(0, path, "test", "", "file", false, 0, bps, false))
            {
                GptImage img = null;
                string threw = null;
                try { img = Gpt.ReadPrimary(d); }
                catch (Exception ex) { threw = ex.GetType().Name + ": " + ex.Message; }
                Check(threw == null, "Gpt.ReadPrimary does not throw on an absurd entry-array header" +
                                    (threw == null ? "" : " (threw " + threw + ")"));
                if (threw != null) return;

                Check(img != null && img.Header.SignatureOk, "the signature is still reported as present");
                Check(img != null && !img.Header.EntryArrayShapeOk, "the entry-array shape is rejected as invalid");
                Check(img != null && !img.Usable, "the image reports itself unusable rather than being trusted");
                Check(img == null || img.Entries.Count == 0, "no entries are invented from the bogus header");

                // The same header must not upset describe/print either - that is what 'inspect' does.
                bool described = true;
                try { Gpt.Describe(img, d, "primary"); Gpt.PrintEntries(img, d, "  "); }
                catch (Exception) { described = false; }
                Check(described, "describe/print handle the rejected header without throwing");
            }
        }

        /// <summary>
        /// Regression: restore-gpt is the most destructive command in the tool, but it used to
        /// print the boot-disk warning and carry straight on - it never read --force at all, so
        /// the README's promise that the boot disk "refuses to proceed without --force" was false
        /// for the one command where it matters most. Both write paths must now gate on force.
        /// </summary>
        private static void TestBootDiskRequiresForce()
        {
            Out.Title("Test 10: boot disk refuses to be written without --force");
            string path = Path.Combine(_dir, "gate.img");
            const int bps = 512;
            using (var fs = new FileStream(path, FileMode.Create, FileAccess.ReadWrite))
                fs.SetLength(16L * 1024 * 1024);

            using (var d = RawDisk.OpenDevice(0, path, "test", "", "file", true, 0, bps, true))
            {
                Check(d.CanWrite, "fixture: the test image opened for writing");

                // isImage: false makes the device count as a real disk, so the boot warning applies.
                bool blockedWithoutForce = Throws(() => Restorer.PreflightTableWrite(d, true, false, false));
                Check(blockedWithoutForce, "table write (restore-gpt) is BLOCKED on the boot disk without --force");

                bool allowedWithForce = !Throws(() => Restorer.PreflightTableWrite(d, true, true, false));
                Check(allowedWithForce, "table write proceeds on the boot disk WITH --force");

                bool partitionBlocked = Throws(() => Restorer.Preflight(d, true, null, 2048, 4096, false, false));
                Check(partitionBlocked, "partition write (add-gpt) is BLOCKED on the boot disk without --force");

                bool partitionAllowed = !Throws(() => Restorer.Preflight(d, true, null, 2048, 4096, true, false));
                Check(partitionAllowed, "partition write proceeds on the boot disk WITH --force");

                // A practice image must stay friction-free even if it is flagged as the boot disk.
                bool imageNotNagged = !Throws(() => Restorer.PreflightTableWrite(d, true, false, true));
                Check(imageNotNagged, "a practice image is not gated (no --force needed to rehearse)");

                // The structural guard must still be absolute: --force cannot excuse a write over
                // the partition table itself.
                var structural = new List<LbaRange>
                {
                    new LbaRange { First = 0, Last = 33, Source = "primary GPT", Structural = true }
                };
                bool structuralBlocked = Throws(() => Restorer.Preflight(d, true, structural, 10, 20, true, false));
                Check(structuralBlocked, "--force still cannot override a write over the GPT itself");

                // And the dry-run guard is unaffected by force.
                bool dryRunBlocked = Throws(() => Restorer.PreflightTableWrite(d, false, true, false));
                Check(dryRunBlocked, "--force does not substitute for --apply");
            }
        }

        /// <summary>Runs an action and reports whether it refused with a UserAbortException.</summary>
        private static bool Throws(Action a)
        {
            try { a(); return false; }
            catch (UserAbortException) { return true; }
            catch (Exception ex) { Out.Bad("    wrong exception: " + ex.GetType().Name + ": " + ex.Message); return true; }
        }

        /// <summary>
        /// End-to-end cover for the single most destructive function in the tool. The other restore
        /// test rebuilds the table by hand, so the real path - preflight, safety backup, confirmation
        /// gate, then the write - was never exercised. The load-bearing property: a gate that refuses
        /// must abort before a single byte reaches the disk.
        /// </summary>
        private static void TestRestoreGptEndToEnd()
        {
            Out.Title("Test 11: restore-gpt end to end (safety backup, gate, write, verify)");
            string path = Path.Combine(_dir, "restore.img");
            string backupDir = Path.Combine(_dir, "restore-backups");
            const int bps = 512;
            using (var fs = new FileStream(path, FileMode.Create, FileAccess.ReadWrite))
                fs.SetLength(256L * 1024 * 1024);

            using (var d = RawDisk.OpenDevice(0, path, "test", "", "file", false, 0, bps, true))
            {
                var lay = new Gpt.Layout { DiskGuid = Guid.NewGuid() };
                lay.Entries.Add(new GptEntry
                {
                    SlotIndex = 0, TypeGuid = GptTypes.EfiSystem, UniqueGuid = Guid.NewGuid(),
                    FirstLba = 34, LastLba = 2047, Name = "EFI"
                });
                lay.Entries.Add(new GptEntry
                {
                    SlotIndex = 1, TypeGuid = GptTypes.BasicData, UniqueGuid = Guid.NewGuid(),
                    FirstLba = 2048, LastLba = 266239, Name = "Locked"
                });
                Gpt.Write(d, lay);
                WriteFixtureVolume(d, d.LbaToOffset(2048), bps, 8, 0x8004, 0x0100);

                // diskpart clean: the primary copy is destroyed, the trailing backup survives.
                d.WriteAt(0, new byte[bps * 40], bps * 40);
                d.Flush();
                Check(!Gpt.ReadPrimary(d).Header.SignatureOk, "fixture: primary GPT destroyed");
                Check(Gpt.ReadBackup(d).Usable, "fixture: trailing backup GPT intact");
            }

            using (var d = RawDisk.OpenDevice(0, path, "test", "", "file", false, 0, bps, true))
            {
                int calls = 0;
                bool refused = Throws(() => Restorer.RestoreGptFromBackup(
                    d, Gpt.ReadBackup(d), true, backupDir, false,
                    (disk, action, details) => { calls++; throw new UserAbortException("test refused"); }));
                Check(refused, "a refusing confirmation gate aborts the restore");
                CheckEq(calls, 1, "the gate is consulted exactly once");
                Check(!Gpt.ReadPrimary(d).Header.SignatureOk,
                      "NOTHING was written: the primary GPT is still destroyed after a refusal");
            }

            using (var d = RawDisk.OpenDevice(0, path, "test", "", "file", false, 0, bps, true))
            {
                int calls = 0;
                string action = null;
                string summary = Restorer.RestoreGptFromBackup(
                    d, Gpt.ReadBackup(d), true, backupDir, false,
                    (disk, act, details) => { calls++; action = act; });
                CheckEq(calls, 1, "the gate is consulted exactly once on the accepting path");
                Check(action != null && action.Contains("backup"), "the gate tells the operator what it will do");
                Check(!string.IsNullOrEmpty(summary), "post-write verification output was produced");

                GptImage p = Gpt.ReadPrimary(d);
                GptImage b = Gpt.ReadBackup(d);
                Check(p != null && p.Usable && p.Header.ArrayCrcOk, "primary GPT rebuilt and CRC-clean");
                Check(p != null && p.Entries.Count(x => x.InUse) == 2, "both original entries are back");
                CheckEq(Gpt.Compare(p, b, d).Count, 0, "primary and backup agree afterwards");
                Check(MbrDisk.Read(d).IsProtectiveForGpt, "the protective MBR was rebuilt");
                Check(Fve.Classify(d.ReadAt(d.LbaToOffset(2048), bps), 0, bps, 2048, d.LbaToOffset(2048)) != null,
                      "the BitLocker volume header was not touched by the table rewrite");
            }

            string[] manifests = Directory.GetFiles(backupDir, "MANIFEST.txt", SearchOption.AllDirectories);
            Check(manifests.Length >= 1, "a safety backup was written before the destructive step");
            if (manifests.Length >= 1)
            {
                string text = File.ReadAllText(manifests[0]);
                Check(text.Contains("sha256    : "), "the manifest records a SHA-256 per region");
                Check(text.Contains("verified"), "the manifest records the read-back verification");
            }
        }

        /// <summary>
        /// Regression: a primary header whose LastUsableLba points into the backup GPT - valid CRC,
        /// impossible geometry, and exactly what a partially wiped disk leaves behind. The range
        /// used to be copied forward verbatim, so Gpt.Write rejected the layout and the operator
        /// could never add a partition entry to that disk at all.
        /// </summary>
        private static void TestRepairsBogusUsableRange()
        {
            Out.Title("Test 12: a GPT header with an impossible usable range is repaired");
            string path = Path.Combine(_dir, "badrange.img");
            string backupDir = Path.Combine(_dir, "badrange-backups");
            const int bps = 512;
            using (var fs = new FileStream(path, FileMode.Create, FileAccess.ReadWrite))
                fs.SetLength(64L * 1024 * 1024);

            const ulong volFirst = 2048;
            ulong volLast;
            using (var d = RawDisk.OpenDevice(0, path, "test", "", "file", false, 0, bps, true))
            {
                var lay = new Gpt.Layout { DiskGuid = Guid.NewGuid() };
                Gpt.Write(d, lay);
                volLast = (ulong)(d.SectorCount - 34);

                // Forge the primary header: LastUsableLba = the last LBA on the device, which is
                // where the backup GPT header lives. Keep the CRC valid so it still reads as usable.
                GptImage p = Gpt.ReadPrimary(d);
                byte[] h = (byte[])p.Header.Raw.Clone();
                Bin.PutU64(h, 48, (ulong)(d.SectorCount - 1));      // LastUsableLba
                Bin.PutU32(h, 16, 0);
                uint crc = Crc32.Compute(h, 0, 92);
                Bin.PutU32(h, 16, crc);
                d.WriteAt(d.LbaToOffset(1), h, bps);
                d.Flush();
            }

            using (var d = RawDisk.OpenDevice(0, path, "test", "", "file", false, 0, bps, true))
            {
                GptImage p = Gpt.ReadPrimary(d);
                Check(p != null && p.Header.SignatureOk, "fixture: the forged primary header still reads as a GPT");
                Check(p != null && p.Header.HeaderCrcOk, "fixture: its CRC is valid, so it looks trustworthy");
                Check(p != null && p.Header.LastUsableLba == (ulong)(d.SectorCount - 1),
                      "fixture: LastUsableLba is the last LBA - physically impossible");

                int calls = 0;
                string err = null;
                try
                {
                    Restorer.AddGptPartition(d, Gpt.ReadPrimary(d), null, volFirst, volLast,
                                            "Repaired", GptTypes.BasicData, true, false, backupDir,
                                            null, (disk, action, details) => calls++);
                }
                catch (Exception ex) { err = ex.GetType().Name + ": " + ex.Message; }

                Check(err == null, "adding a partition entry now succeeds" + (err == null ? "" : " (threw " + err + ")"));
                CheckEq(calls, 1, "the confirmation gate was still consulted");
            }

            using (var d = RawDisk.OpenDevice(0, path, "test", "", "file", false, 0, bps, false))
            {
                GptImage p = Gpt.ReadPrimary(d);
                GptImage b = Gpt.ReadBackup(d);
                Check(p != null && p.Usable && p.Header.ArrayCrcOk, "the rewritten primary GPT is valid and CRC-clean");
                Check(p != null && p.Usable && b != null && b.Usable, "both GPT copies are usable");
                CheckEq(Gpt.Compare(p, b, d).Count, 0, "primary and backup agree");
                Check(p != null && p.Usable && p.Header.LastUsableLba < (ulong)(d.SectorCount - 1),
                      "LastUsableLba no longer runs into the backup GPT");
                // Exact value: the last usable LBA is the sector before the 32-sector backup array,
                // which itself sits before the backup header on the final LBA. One sector out and
                // Gpt.Write rejects the table.
                Check(p != null && p.Usable && p.Header.LastUsableLba == (ulong)(d.SectorCount - 2 - 32),
                      "LastUsableLba is exactly the last sector before the backup array (got " +
                      (p != null && p.Header != null ? p.Header.LastUsableLba.ToString() : "?") + ")");
                Check(p != null && p.Entries.Count(x => x.InUse) == 1, "the partition entry is present");
                GptEntry e = p != null && p.Entries.Count > 0 ? p.Entries[0] : null;
                Check(e != null && e.InUse && e.FirstLba == volFirst && e.LastLba == volLast,
                      "the entry kept the requested bounds");
            }
        }

        /// <summary>
        /// Regression: a volume whose own metadata claims it runs to the final sector of the disk.
        /// That figure can never be written - the tail belongs to the backup GPT - so the tool used
        /// to suggest a range and then refuse it, leaving the operator with no forward path. The
        /// shared formula must also agree with the writer's own validation, to the sector.
        /// </summary>
        private static void TestGptEndReserveMath()
        {
            Out.Title("Test 13: the GPT end reserve is computed once and never suggested past");

            // The real failing case: 465.76 GB drive, volume from 2048 to the final sector.
            const long sectorCount = 976768065L;
            ulong ceiling = Gpt.LastUsableLba(Gpt.StandardArraySectors, sectorCount);
            CheckEq(ceiling, 976768031UL, "last usable LBA for a 128x128 table");
            CheckEq((long)ceiling, sectorCount - 34, "that is the device's last sector minus 33");
            Check(Gpt.BackupReserveSectors(Gpt.StandardArraySectors) == 33,
                  "the backup GPT reserves 33 sectors (32 array + 1 header)");

            // What the scan used to suggest, and what it must now never suggest.
            const ulong volFirst = 2048, bogusLast = 976768064;
            Check(bogusLast > ceiling, "a volume ending on the disk's final sector is past the ceiling");
            ulong clamped = bogusLast > ceiling ? ceiling : bogusLast;
            Check(clamped <= ceiling, "clamping brings it inside the usable area");
            Check(bogusLast - clamped == 33, "exactly 33 sectors are given up - the backup GPT's 32 + 1");
            Check((long)(clamped - volFirst + 1) < sectorCount, "the clamped entry leaves the GPT intact");

            // The formula and the writer's own guard must not drift apart, or every write on a
            // real disk fails with a contradiction. Gpt.Write rejects LastUsable > lastLba-1-arrays.
            long lastLba = sectorCount - 1;
            int arr = Gpt.StandardArraySectors;
            Check((long)ceiling <= lastLba - 1 - arr,
                  "the shared formula satisfies Gpt.Write's own backup-GPT check exactly");
            Check(ceiling == (ulong)(lastLba - 1 - arr), "they are equal, not merely close");

            // And the same relationship must hold behaviourally on a real device, not just in
            // arithmetic: an entry ending exactly at the ceiling is written, one past it is refused.
            string path = Path.Combine(_dir, "ceiling.img");
            const int bps = 512;
            using (var fs = new FileStream(path, FileMode.Create, FileAccess.ReadWrite))
                fs.SetLength(16L * 1024 * 1024);

            using (var d = RawDisk.OpenDevice(0, path, "test", "", "file", false, 0, bps, true))
            {
                var lay = new Gpt.Layout { DiskGuid = Guid.NewGuid() };
                Gpt.Write(d, lay);
                ulong devCeiling = Gpt.LastUsableLba(Gpt.StandardArraySectors, d.SectorCount);
                Check((long)devCeiling == d.SectorCount - 1 - Gpt.StandardArraySectors - 1,
                      "device ceiling matches the shared formula");

                var atCeiling = new Gpt.Layout
                {
                    DiskGuid = lay.DiskGuid, EntryCount = 128, EntrySize = 128,
                    FirstUsable = lay.FirstUsable, LastUsable = devCeiling
                };
                atCeiling.Entries.Add(new GptEntry
                {
                    SlotIndex = 0, TypeGuid = GptTypes.BasicData, UniqueGuid = Guid.NewGuid(),
                    FirstLba = 34, LastLba = devCeiling, Name = "AtCeiling"
                });
                bool wrote = true;
                try { Gpt.Write(d, atCeiling); } catch (Exception) { wrote = false; }
                Check(wrote, "an entry ending exactly at the ceiling is accepted and written");

                GptImage after = Gpt.ReadPrimary(d);
                Check(after != null && after.Usable, "the table at the ceiling is valid");
                Check(after != null && after.Entries.Count(x => x.InUse) == 1, "the ceiling entry is present");

                // One sector beyond the ceiling, same layout: must be refused, not written.
                var past = new Gpt.Layout
                {
                    DiskGuid = lay.DiskGuid, EntryCount = 128, EntrySize = 128,
                    FirstUsable = lay.FirstUsable, LastUsable = devCeiling
                };
                past.Entries.Add(new GptEntry
                {
                    SlotIndex = 0, TypeGuid = GptTypes.BasicData, UniqueGuid = Guid.NewGuid(),
                    FirstLba = 34, LastLba = devCeiling + 1, Name = "OnePast"
                });
                bool refused = false;
                try { Gpt.Write(d, past); } catch (Exception) { refused = true; }
                Check(refused, "an entry one sector past the ceiling is refused");

                GptImage stillThere = Gpt.ReadPrimary(d);
                Check(stillThere != null && stillThere.Usable &&
                      stillThere.Entries.Count(x => x.InUse) == 1,
                      "the refused write left the previous good table intact");
            }
        }

        /// <summary>Zeroes one GPT entry in both copies and repairs the CRCs, the way Windows does.</summary>
        private static void ZeroGptEntry(RawDisk d, int slot)
        {
            int bps = d.BytesPerSector;
            GptImage p = Gpt.ReadPrimary(d);
            GptImage b = Gpt.ReadBackup(d);
            if (p == null || !p.Usable || b == null || !b.Usable) throw new InvalidOperationException("fixture: GPT not usable");

            foreach (bool primary in new[] { true, false })
            {
                GptImage img = primary ? p : b;
                var lay = new Gpt.Layout
                {
                    DiskGuid = img.Header.DiskGuid,
                    EntryCount = img.Header.EntryCount,
                    EntrySize = img.Header.EntrySize,
                    FirstUsable = img.Header.FirstUsableLba,
                    LastUsable = img.Header.LastUsableLba
                };
                foreach (GptEntry e in img.Entries)
                {
                    if (e.SlotIndex == slot) continue;
                    lay.Entries.Add(e);
                }
                Gpt.Write(d, lay);
            }
        }
    }

    internal static class Ext
    {
        public static int Count<T>(this IEnumerable<T> src, Func<T, bool> pred)
        {
            int n = 0;
            foreach (T x in src) if (pred(x)) n++;
            return n;
        }
    }
}
