using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace BlRecover
{
    internal static class GptTypes
    {
        public static readonly Guid Unused = Guid.Empty;
        public static readonly Guid BasicData = new Guid("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7");
        public static readonly Guid EfiSystem = new Guid("C12A7328-F81F-11D2-BA4B-00A0C93EC93B");
        public static readonly Guid MsftReserved = new Guid("E3C9E316-0B5C-4DB8-817D-F92DF00215AE");
        public static readonly Guid MsftRecovery = new Guid("DE94BBA4-06D1-4D40-A16A-BFD50179D6AC");
        public static readonly Guid MsftBasicDataMirror = new Guid("3AACC7D7-93E3-4967-821C-ABC4E2D7699A");
        public static readonly Guid LinuxFilesystem = new Guid("0FC63DAF-8483-4772-8E79-3D69D8477DE4");
        public static readonly Guid LinuxSwap = new Guid("0657FD6D-A4AB-43C4-84E5-0933C84B4F4F");
        public static readonly Guid LinuxLvm = new Guid("E6D6D379-F507-44C2-A23C-238F2A3DF928");
        public static readonly Guid BiosBoot = new Guid("21686148-6449-6E6F-744E-656564454649");
        public static readonly Guid LdmMetadata = new Guid("5808C8AA-7E8F-42E0-85D2-E1E90434CFB3");
        public static readonly Guid LdmData = new Guid("AF9B60A0-1431-4F62-BC68-3311714A69AD");

        public static string Name(Guid type)
        {
            if (type == Guid.Empty) return "unused";
            if (type == BasicData) return "Basic data (what Windows uses - incl. BitLocker)";
            if (type == EfiSystem) return "EFI system";
            if (type == MsftReserved) return "Microsoft reserved";
            if (type == MsftRecovery) return "Microsoft recovery";
            if (type == MsftBasicDataMirror) return "Basic data mirror";
            if (type == LinuxFilesystem) return "Linux filesystem";
            if (type == LinuxSwap) return "Linux swap";
            if (type == LinuxLvm) return "Linux LVM";
            if (type == BiosBoot) return "BIOS boot";
            if (type == LdmMetadata) return "LDM metadata";
            if (type == LdmData) return "LDM data";
            return "type " + type.ToString();
        }
    }

    internal sealed class GptEntry
    {
        public Guid TypeGuid;
        public Guid UniqueGuid;
        public ulong FirstLba;
        public ulong LastLba;
        public ulong Attributes;
        public string Name = "";
        public byte[] Raw;                 // verbatim 128-byte record when parsed from disk
        public int SlotIndex = -1;

        public bool InUse { get { return TypeGuid != Guid.Empty; } }
        public ulong SectorCount { get { return LastLba >= FirstLba ? LastLba - FirstLba + 1 : 0; } }

        public static GptEntry Parse(byte[] array, int off, int entrySize, int index)
        {
            var e = new GptEntry();
            e.SlotIndex = index;
            e.Raw = new byte[entrySize];
            Buffer.BlockCopy(array, off, e.Raw, 0, entrySize);
            e.TypeGuid = Bin.Guid16(array, off);
            e.UniqueGuid = Bin.Guid16(array, off + 16);
            e.FirstLba = Bin.U64(array, off + 32);
            e.LastLba = Bin.U64(array, off + 40);
            e.Attributes = Bin.U64(array, off + 48);
            int nameLen = Math.Min(36, Math.Max(0, (entrySize - 56) / 2));
            var sb = new StringBuilder(nameLen);
            for (int i = 0; i < nameLen; i++)
            {
                ushort c = Bin.U16(array, off + 56 + i * 2);
                if (c == 0) break;
                sb.Append((char)c);
            }
            e.Name = sb.ToString();
            return e;
        }

        public byte[] Build(int entrySize)
        {
            if (Raw != null && Raw.Length == entrySize && SlotIndex >= 0) return Raw;
            var b = new byte[entrySize];
            Bin.PutGuid16(b, 0, TypeGuid);
            Bin.PutGuid16(b, 16, UniqueGuid);
            Bin.PutU64(b, 32, FirstLba);
            Bin.PutU64(b, 40, LastLba);
            Bin.PutU64(b, 48, Attributes);
            string n = Name ?? "";
            int max = Math.Min(36, Math.Max(0, (entrySize - 56) / 2));
            if (n.Length > max) n = n.Substring(0, max);
            for (int i = 0; i < n.Length; i++) Bin.PutU16(b, 56 + i * 2, (char)n[i]);
            return b;
        }
    }

    internal sealed class GptHeader
    {
        public bool SignatureOk;
        public uint Revision;
        public uint HeaderSize;
        public uint HeaderCrcStored;
        public uint HeaderCrcComputed;
        public bool HeaderCrcOk;
        public ulong MyLba;
        public ulong AlternateLba;
        public ulong FirstUsableLba;
        public ulong LastUsableLba;
        public Guid DiskGuid;
        public ulong EntryLba;
        public uint EntryCount;
        public uint EntrySize;
        public uint ArrayCrcStored;
        public uint ArrayCrcComputed;
        public bool ArrayCrcOk;
        public byte[] Raw;
        public int SourceLba;

        /// <summary>
        /// True when EntryCount/EntrySize sit inside the range UEFI allows. These two fields size
        /// the partition entry array, so they must be validated before they are allowed to take
        /// part in arithmetic: a header on a damaged disk carries whatever bytes happened to be
        /// there, and 0xFFFFFFFF * 0xFFFFFFFF overflows a signed multiply.
        /// </summary>
        public bool EntryArrayShapeOk
        {
            get { return EntryCount > 0 && EntryCount <= 8192 && EntrySize >= 128 && EntrySize <= 4096; }
        }

        public bool StructurallyValid
        {
            get { return SignatureOk && HeaderCrcOk && EntryArrayShapeOk; }
        }

        public int ArraySectors(int bps)
        {
            ulong bytes = (ulong)EntryCount * EntrySize;
            ulong sectors = (bytes + (ulong)bps - 1) / (ulong)bps;
            return sectors > int.MaxValue ? int.MaxValue : (int)sectors;
        }
    }

    internal sealed class GptImage
    {
        public GptHeader Header;
        public byte[] EntryArray;
        public readonly List<GptEntry> Entries = new List<GptEntry>();
        public bool IsPrimary;

        public bool Usable { get { return Header != null && Header.StructurallyValid; } }
    }

    /// <summary>
    /// GPT reader/writer. Only ever touches LBA 0, the primary header+array, and the trailing
    /// backup header+array - never the body of any partition.
    /// </summary>
    internal static class Gpt
    {
        private static readonly byte[] Sig = Encoding.ASCII.GetBytes("EFI PART");

        /// <summary>
        /// Sectors the backup GPT occupies at the end of the device: the entry array plus its
        /// own header. For the standard 128-entry x 128-byte table this is 33 sectors.
        /// </summary>
        public static int BackupReserveSectors(int arraySectors) { return arraySectors + 1; }

        /// <summary>
        /// The last LBA a partition may legally occupy: the sector before the backup entry array,
        /// which itself sits before the backup header on the final LBA. Suggesting anything beyond
        /// this hands the operator a range our own writer will reject, which is exactly the
        /// dead end this method exists to prevent.
        /// </summary>
        public static ulong LastUsableLba(int arraySectors, long sectorCount)
        {
            long limit = sectorCount - 1 - BackupReserveSectors(arraySectors);
            return limit < 0 ? 0UL : (ulong)limit;
        }

        /// <summary>Array sectors of the near-universal 128-entry x 128-byte table.</summary>
        public const int StandardArraySectors = 32;

        public static GptHeader ParseHeader(byte[] sector, int sourceLba)
        {
            var h = new GptHeader();
            h.SourceLba = sourceLba;
            h.Raw = sector;
            h.SignatureOk = Bin.BytesEqual(sector, 0, Sig);
            if (!h.SignatureOk) return h;
            h.Revision = Bin.U32(sector, 8);
            h.HeaderSize = Bin.U32(sector, 12);
            h.HeaderCrcStored = Bin.U32(sector, 16);
            h.MyLba = Bin.U64(sector, 24);
            h.AlternateLba = Bin.U64(sector, 32);
            h.FirstUsableLba = Bin.U64(sector, 40);
            h.LastUsableLba = Bin.U64(sector, 48);
            h.DiskGuid = Bin.Guid16(sector, 56);
            h.EntryLba = Bin.U64(sector, 72);
            h.EntryCount = Bin.U32(sector, 80);
            h.EntrySize = Bin.U32(sector, 84);
            h.ArrayCrcStored = Bin.U32(sector, 88);

            int hs = (int)h.HeaderSize;
            if (hs >= 92 && hs <= sector.Length)
            {
                var tmp = (byte[])sector.Clone();
                Bin.PutU32(tmp, 16, 0);
                h.HeaderCrcComputed = Crc32.Compute(tmp, 0, hs);
                h.HeaderCrcOk = h.HeaderCrcComputed == h.HeaderCrcStored;
            }
            return h;
        }

        private static GptImage ReadImage(RawDisk d, long headerLba, bool primary)
        {
            var img = new GptImage();
            img.IsPrimary = primary;
            long headerOffset = d.LbaToOffset(headerLba);
            byte[] sector = d.ReadAt(headerOffset, d.BytesPerSector);
            img.Header = ParseHeader(sector, (int)headerLba);
            if (!img.Header.SignatureOk) return img;

            // Reject an absurd entry-array shape before it is allowed to size a read. Without
            // this the sector count below can come back negative, which passes the bounds check
            // and then blows up allocating the buffer.
            if (!img.Header.EntryArrayShapeOk) return img;

            int bps = d.BytesPerSector;
            long arraySectors = img.Header.ArraySectors(bps);
            long arrayOffset = d.LbaToOffset((long)img.Header.EntryLba);
            if (arrayOffset < 0 || arrayOffset + arraySectors * bps > d.SizeBytes) return img;

            byte[] array = d.ReadAt(arrayOffset, (int)(arraySectors * bps));
            img.EntryArray = array;
            img.Header.ArrayCrcComputed = Crc32.Compute(array, 0, array.Length);
            img.Header.ArrayCrcOk = img.Header.ArrayCrcComputed == img.Header.ArrayCrcStored;

            for (int i = 0; i < img.Header.EntryCount; i++)
            {
                int off = i * (int)img.Header.EntrySize;
                if (off + (int)img.Header.EntrySize > array.Length) break;
                img.Entries.Add(GptEntry.Parse(array, off, (int)img.Header.EntrySize, i));
            }
            return img;
        }

        public static GptImage ReadPrimary(RawDisk d)
        {
            return ReadImage(d, 1, true);
        }

        /// <summary>Reads the trailing backup GPT, located at the last LBA by UEFI convention.</summary>
        public static GptImage ReadBackup(RawDisk d)
        {
            long last = d.SectorCount - 1;
            if (last < 1) return null;
            return ReadImage(d, last, false);
        }

        public static string Describe(GptImage img, RawDisk d, string label)
        {
            if (img == null) { Out.Indent(label + ": not present"); return string.Empty; }
            var sb = new StringBuilder();
            GptHeader h = img.Header;
            if (!h.SignatureOk)
            {
                Out.Indent(label + ": NO 'EFI PART' signature at LBA " + h.SourceLba + "  (blank or destroyed)");
                return sb.ToString();
            }
            Out.Indent(label + ": LBA " + h.MyLba + "  alt LBA " + h.AlternateLba);
            Out.Indent(label + ": header CRC " + (h.HeaderCrcOk ? "VALID" : "INVALID (stored 0x" + h.HeaderCrcStored.ToString("x8") + ", computed 0x" + h.HeaderCrcComputed.ToString("x8") + ")"));
            Out.Indent(label + ": array CRC   " + (h.ArrayCrcOk ? "VALID" : "INVALID (stored 0x" + h.ArrayCrcStored.ToString("x8") + ", computed 0x" + h.ArrayCrcComputed.ToString("x8") + ")"));
            Out.Indent(label + ": disk GUID " + h.DiskGuid);
            Out.Indent(label + ": " + h.EntryCount + " entries x " + h.EntrySize + " bytes at LBA " + h.EntryLba);
            Out.Indent(label + ": usable LBA " + h.FirstUsableLba + ".." + h.LastUsableLba);

            int used = 0, suspicious = 0;
            foreach (GptEntry e in img.Entries)
            {
                if (!e.InUse) continue;
                used++;
                bool bad = e.LastLba < e.FirstLba || e.FirstLba < h.FirstUsableLba || e.LastLba > h.LastUsableLba;
                if (bad) suspicious++;
            }
            Out.Indent(label + ": " + used + " entries in use" + (suspicious > 0 ? ", " + suspicious + " of them out of bounds" : ""));
            return sb.ToString();
        }

        public static void PrintEntries(GptImage img, RawDisk d, string indent)
        {
            if (img == null || !img.Usable) return;
            GptHeader h = img.Header;
            foreach (GptEntry e in img.Entries)
            {
                if (!e.InUse) continue;
                bool oob = e.LastLba < e.FirstLba || e.FirstLba < h.FirstUsableLba || e.LastLba > h.LastUsableLba;
                Console.WriteLine("{0}slot {1,-3} LBA {2,10}..{3,-10} {4,12}  {5}  {6}{7}",
                    indent, e.SlotIndex, e.FirstLba, e.LastLba,
                    Fmt.HumanSize((long)e.SectorCount * d.BytesPerSector),
                    e.Name.Length > 0 ? "\"" + e.Name + "\"" : "(unnamed)",
                    GptTypes.Name(e.TypeGuid),
                    oob ? "   <-- OUT OF BOUNDS" : "");
            }
        }

        /// <summary>Compares the two GPT copies and reports where they disagree.</summary>
        public static List<string> Compare(GptImage primary, GptImage backup, RawDisk d)
        {
            var diffs = new List<string>();
            if (primary == null || backup == null || !primary.Usable || !backup.Usable) return diffs;
            int n = (int)Math.Max(primary.Header.EntryCount, backup.Header.EntryCount);
            for (int i = 0; i < n; i++)
            {
                GptEntry a = i < primary.Entries.Count ? primary.Entries[i] : null;
                GptEntry b = i < backup.Entries.Count ? backup.Entries[i] : null;
                string sa = a == null || !a.InUse ? "-" : (a.FirstLba + ".." + a.LastLba + " " + a.TypeGuid);
                string sb = b == null || !b.InUse ? "-" : (b.FirstLba + ".." + b.LastLba + " " + b.TypeGuid);
                if (sa != sb) diffs.Add("slot " + i + ": primary [" + sa + "]  backup [" + sb + "]");
            }
            if (primary.Header.DiskGuid != backup.Header.DiskGuid)
                diffs.Add("disk GUID differs: primary " + primary.Header.DiskGuid + " backup " + backup.Header.DiskGuid);
            return diffs;
        }

        // ---------------------------------------------------------------- writing

        public sealed class Layout
        {
            public Guid DiskGuid;
            public uint EntryCount = 128;
            public uint EntrySize = 128;
            public ulong FirstUsable;
            public ulong LastUsable;
            public readonly List<GptEntry> Entries = new List<GptEntry>();
        }

        public static byte[] BuildProtectiveMbr(int bps, long sectorCount)
        {
            var s = new byte[bps];
            // UEFI 2.x: the single 0xEE entry belongs in the SECOND slot (offset 446+16),
            // with slot 0 left empty. Writing it to slot 0 produces a table Windows rejects.
            const int slotOffset = 446 + 16;
            s[slotOffset + 0] = 0x00;                                   // boot flag: not bootable
            s[slotOffset + 1] = 0x00;
            s[slotOffset + 2] = 0x02;
            s[slotOffset + 3] = 0x00;
            s[slotOffset + 4] = 0xEE;                                   // type: GPT protective
            ulong size = (ulong)(sectorCount - 1);
            if (size > 0xFFFFFFFFUL) size = 0xFFFFFFFFUL;
            Bin.PutU32(s, slotOffset + 8, 1);
            Bin.PutU32(s, slotOffset + 12, (uint)size);
            s[bps - 2] = 0x55;
            s[bps - 1] = 0xAA;
            return s;
        }

        private static byte[] BuildEntryArray(Layout lay, out uint arrayCrc)
        {
            long total = (long)lay.EntryCount * lay.EntrySize;
            if (total > 64L * 1024 * 1024) throw new InvalidOperationException("GPT entry array too large: " + total);
            var a = new byte[total];
            foreach (GptEntry e in lay.Entries)
            {
                if (e.SlotIndex < 0 || e.SlotIndex >= lay.EntryCount)
                    throw new InvalidOperationException("GPT slot index out of range: " + e.SlotIndex);
                byte[] rec = e.Build((int)lay.EntrySize);
                Buffer.BlockCopy(rec, 0, a, e.SlotIndex * (int)lay.EntrySize, (int)lay.EntrySize);
            }
            arrayCrc = Crc32.Compute(a, 0, a.Length);
            return a;
        }

        private static byte[] BuildHeader(Layout lay, ulong myLba, ulong altLba, ulong entryLba,
                                         uint arrayCrc, int bps)
        {
            var h = new byte[bps];
            Buffer.BlockCopy(Sig, 0, h, 0, 8);
            Bin.PutU32(h, 8, 0x00010000);
            Bin.PutU32(h, 12, 92);
            Bin.PutU32(h, 16, 0);
            Bin.PutU32(h, 20, 0);
            Bin.PutU64(h, 24, myLba);
            Bin.PutU64(h, 32, altLba);
            Bin.PutU64(h, 40, lay.FirstUsable);
            Bin.PutU64(h, 48, lay.LastUsable);
            Bin.PutGuid16(h, 56, lay.DiskGuid);
            Bin.PutU64(h, 72, entryLba);
            Bin.PutU32(h, 80, lay.EntryCount);
            Bin.PutU32(h, 84, lay.EntrySize);
            Bin.PutU32(h, 88, arrayCrc);
            uint crc = Crc32.Compute(h, 0, 92);
            Bin.PutU32(h, 16, crc);
            return h;
        }

        /// <summary>
        /// Writes a fully consistent GPT: protective MBR, primary header+array, and a matching
        /// backup array+header at the end of the device.
        /// </summary>
        public static void Write(RawDisk d, Layout lay)
        {
            int bps = d.BytesPerSector;
            long lastLba = d.SectorCount - 1;
            int arraySectors = (int)(((long)lay.EntryCount * lay.EntrySize + bps - 1) / bps);

            if (lay.FirstUsable == 0 && lay.LastUsable == 0)
            {
                lay.FirstUsable = (ulong)(2 + arraySectors);
                lay.LastUsable = (ulong)(lastLba - 1 - arraySectors);
            }
            if ((long)lay.FirstUsable < 2 + arraySectors)
                throw new InvalidOperationException("FirstUsable LBA " + lay.FirstUsable + " overlaps the primary GPT.");
            if ((long)lay.LastUsable > lastLba - 1 - arraySectors)
                throw new InvalidOperationException("LastUsable LBA " + lay.LastUsable + " overlaps the backup GPT.");
            if (lay.DiskGuid == Guid.Empty) lay.DiskGuid = Guid.NewGuid();

            // Refuse to emit a table that Windows would reject: every entry must sit inside
            // the usable area, must not overlap another entry, and must not be inverted.
            var sorted = new List<GptEntry>();
            foreach (GptEntry e in lay.Entries) if (e.InUse) sorted.Add(e);
            sorted.Sort((a, b) => a.FirstLba.CompareTo(b.FirstLba));
            ulong prevLast = 0;
            for (int i = 0; i < sorted.Count; i++)
            {
                GptEntry e = sorted[i];
                if (e.LastLba < e.FirstLba)
                    throw new InvalidOperationException("GPT slot " + e.SlotIndex + " is inverted (" +
                                                         e.FirstLba + ".." + e.LastLba + ").");
                if (e.FirstLba < lay.FirstUsable || e.LastLba > lay.LastUsable)
                    throw new InvalidOperationException("GPT slot " + e.SlotIndex + " spans LBA " +
                                                         e.FirstLba + ".." + e.LastLba +
                                                         ", outside the usable area " + lay.FirstUsable +
                                                         ".." + lay.LastUsable + " (it would collide with the GPT).");
                if (i > 0 && e.FirstLba <= prevLast)
                    throw new InvalidOperationException("GPT slot " + e.SlotIndex + " (LBA " + e.FirstLba +
                                                         ") overlaps the previous entry which ends at " + prevLast + ".");
                prevLast = e.LastLba;
            }

            uint arrayCrc;
            byte[] array = BuildEntryArray(lay, out arrayCrc);

            ulong primaryEntryLba = 2;
            ulong backupEntryLba = lay.LastUsable + 1;

            byte[] primaryHeader = BuildHeader(lay, 1, (ulong)lastLba, primaryEntryLba, arrayCrc, bps);
            byte[] backupHeader = BuildHeader(lay, (ulong)lastLba, 1, backupEntryLba, arrayCrc, bps);

            // Write order is deliberate. The entry arrays go down first and both headers last,
            // because a header is the commit point for its own array: if we are interrupted part
            // way through, each header still describes the array that was already there rather
            // than an array that never arrived. LBA 0 goes first because a GPT disk's protective
            // MBR carries no data of its own.
            d.WriteAt(0, BuildProtectiveMbr(bps, d.SectorCount), bps);
            d.WriteAt(d.LbaToOffset((long)primaryEntryLba), array, array.Length);
            d.WriteAt(d.LbaToOffset((long)backupEntryLba), array, array.Length);
            d.WriteAt(d.LbaToOffset(1), primaryHeader, bps);
            d.WriteAt(d.LbaToOffset(lastLba), backupHeader, bps);
            d.Flush();
        }
    }
}
