using System;
using System.Collections.Generic;
using System.Text;

namespace BlRecover
{
    internal sealed class MbrEntry
    {
        public byte BootFlag;
        public byte Type;
        public uint StartLba;
        public uint SectorCount;
        public byte[] Raw = new byte[16];

        public bool InUse { get { return Type != 0x00; } }

        public static MbrEntry Parse(byte[] sector, int tableOffset, int index)
        {
            var e = new MbrEntry();
            int off = tableOffset + index * 16;
            Buffer.BlockCopy(sector, off, e.Raw, 0, 16);
            e.BootFlag = sector[off];
            e.Type = sector[off + 4];
            e.StartLba = Bin.U32(sector, off + 8);
            e.SectorCount = Bin.U32(sector, off + 12);
            return e;
        }

        public byte[] Build()
        {
            var b = new byte[16];
            b[0] = BootFlag;
            b[4] = Type;
            Bin.PutU32(b, 8, StartLba);
            Bin.PutU32(b, 12, SectorCount);
            return b;
        }

        public string TypeName()
        {
            switch (Type)
            {
                case 0x00: return "empty";
                case 0x01: return "FAT12";
                case 0x04: return "FAT16 <32M";
                case 0x05: return "extended";
                case 0x06: return "FAT16";
                case 0x07: return "NTFS/exFAT (also used by BitLocker)";
                case 0x0B: return "FAT32";
                case 0x0C: return "FAT32 LBA";
                case 0x0E: return "FAT16 LBA";
                case 0x0F: return "extended LBA";
                case 0x27: return "Windows system/recovery";
                case 0x42: return "LDM";
                case 0x82: return "Linux swap";
                case 0x83: return "Linux";
                case 0x8E: return "Linux LVM";
                case 0xA5: return "FreeBSD";
                case 0xEE: return "GPT protective";
                case 0xEF: return "EFI system";
                case 0xFB: return "VMware VMFS";
                default: return "type 0x" + Type.ToString("X2", System.Globalization.CultureInfo.InvariantCulture);
            }
        }
    }

    internal sealed class MbrDisk
    {
        public byte[] Sector0;
        public bool HasBootSignature;
        public bool HasCode;
        public bool IsProtectiveForGpt;
        public readonly List<MbrEntry> Entries = new List<MbrEntry>();

        public static MbrDisk Read(RawDisk d)
        {
            var m = new MbrDisk();
            m.Sector0 = d.ReadAt(0, d.BytesPerSector);
            m.HasBootSignature = m.Sector0[m.Sector0.Length - 2] == 0x55 && m.Sector0[m.Sector0.Length - 1] == 0xAA;
            bool nonzero = false;
            for (int i = 0; i < 446; i++) if (m.Sector0[i] != 0) { nonzero = true; break; }
            m.HasCode = nonzero;
            for (int i = 0; i < 4; i++) m.Entries.Add(MbrEntry.Parse(m.Sector0, 446, i));

            MbrEntry first = m.Entries[0];
            bool protective = m.HasBootSignature && !m.HasCode
                              && first.Type == 0x00 && first.BootFlag == 0x00
                              && m.Entries[1].Type == 0xEE
                              && m.Entries[1].BootFlag == 0x00
                              && m.Entries[1].StartLba == 1
                              && m.Entries[1].SectorCount != 0;
            m.IsProtectiveForGpt = protective;
            return m;
        }

        public void WriteEntry(RawDisk d, int index, MbrEntry entry)
        {
            if (index < 0 || index > 3) throw new ArgumentOutOfRangeException("index", "MBR has 4 primary entries (0-3)");
            byte[] b = entry.Build();
            Buffer.BlockCopy(b, 0, Sector0, 446 + index * 16, 16);
            if (Sector0[Sector0.Length - 2] != 0x55 || Sector0[Sector0.Length - 1] != 0xAA)
            {
                Sector0[Sector0.Length - 2] = 0x55;
                Sector0[Sector0.Length - 1] = 0xAA;
            }
            d.WriteAt(0, Sector0, Sector0.Length);
            d.Flush();
            Entries[index] = entry;
        }

        public static string Describe(MbrDisk m, RawDisk d)
        {
            var sb = new StringBuilder();
            sb.AppendLine("  boot signature 0x55AA : " + (m.HasBootSignature ? "present" : "ABSENT (sector 0 looks blank)"));
            sb.AppendLine("  boot code         : " + (m.HasCode ? "present" : "zeroed"));
            if (m.IsProtectiveForGpt)
                sb.AppendLine("  GPT protective    : yes - this is a GPT disk");
            else if (!m.HasBootSignature && !m.HasCode)
                sb.AppendLine("  GPT protective    : n/a - LBA 0 is blank, there is no partition table here");
            else
                sb.AppendLine("  GPT protective    : no - MBR partitioned");
            for (int i = 0; i < 4; i++)
            {
                MbrEntry e = m.Entries[i];
                if (!e.InUse) { sb.AppendLine("  slot " + i + ": empty"); continue; }
                long endBytes = ((long)e.StartLba + e.SectorCount) * d.BytesPerSector;
                sb.AppendLine("  slot " + i + ": LBA " + e.StartLba + ".." +
                              (e.StartLba + e.SectorCount - 1) +
                              "  " + Fmt.HumanSize((long)e.SectorCount * d.BytesPerSector) +
                              "  boot=" + (e.BootFlag == 0x80 ? "yes" : "no") +
                              "  " + e.TypeName());
            }
            return sb.ToString();
        }
    }
}
