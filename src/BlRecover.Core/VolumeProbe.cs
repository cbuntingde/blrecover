using System;
using System.Text;

namespace BlRecover
{
    internal enum VolumeKind
    {
        Unknown,
        Fve,        // BitLocker (possibly BitLocker To Go)
        Ntfs,
        ExFat,
        Fat32,
        Fat16,
        Fat12
    }

    /// <summary>
    /// Recognises the volume header at the start of a partition for every filesystem a
    /// Windows backup drive is likely to use, not just BitLocker. Deleting a partition
    /// leaves the filesystem's own boot sector fully intact, so it is the single most
    /// reliable witness that a volume used to live at a given sector.
    /// </summary>
    internal static class VolumeProbe
    {
        public static readonly byte[] Ntfs = Encoding.ASCII.GetBytes("NTFS    ");
        public static readonly byte[] ExFat = Encoding.ASCII.GetBytes("EXFAT   ");
        public static readonly byte[] Fve = Encoding.ASCII.GetBytes("-FVE-FS-");
        public static readonly byte[] ToGo = Encoding.ASCII.GetBytes("MSWIN4.1");
        public static readonly byte[] Fat32 = Encoding.ASCII.GetBytes("FAT32   ");
        public static readonly byte[] Fat16 = Encoding.ASCII.GetBytes("FAT16   ");
        public static readonly byte[] Fat12 = Encoding.ASCII.GetBytes("FAT12   ");
        public static readonly byte[] FatOld = Encoding.ASCII.GetBytes("FAT     ");

        public static VolumeKind Classify(byte[] b, int off)
        {
            if (Bin.BytesEqual(b, off + 3, Fve) || Bin.BytesEqual(b, off + 3, ToGo)) return VolumeKind.Fve;
            if (Bin.BytesEqual(b, off + 3, Ntfs)) return VolumeKind.Ntfs;
            if (Bin.BytesEqual(b, off + 3, ExFat)) return VolumeKind.ExFat;
            if (Bin.BytesEqual(b, off + 82, Fat32)) return VolumeKind.Fat32;
            if (Bin.BytesEqual(b, off + 54, Fat16) || Bin.BytesEqual(b, off + 54, FatOld)) return VolumeKind.Fat16;
            if (Bin.BytesEqual(b, off + 54, Fat12)) return VolumeKind.Fat12;
            return VolumeKind.Unknown;
        }

        public static string Describe(VolumeKind k)
        {
            switch (k)
            {
                case VolumeKind.Fve: return "BitLocker";
                case VolumeKind.Ntfs: return "NTFS";
                case VolumeKind.ExFat: return "exFAT";
                case VolumeKind.Fat32: return "FAT32";
                case VolumeKind.Fat16: return "FAT16";
                case VolumeKind.Fat12: return "FAT12";
                default: return "unknown";
            }
        }

        public static bool NeedsKey(VolumeKind k) { return k == VolumeKind.Fve; }

        /// <summary>
        /// Partition size in bytes, read from the BIOS parameter block. For an unencrypted
        /// volume this is BETTER evidence than anything else on the disk: it is the volume's
        /// own record of its length, and it is what Windows itself used.
        /// Returns null when the BPB does not make sense.
        /// </summary>
        public static ulong? SizeFromBpb(byte[] b, int off, int len)
        {
            try
            {
                // BPB gotcha: bytes-per-sector at 0x0B is a 16-bit field (512 is stored as 00 02),
                // while sectors-per-cluster at 0x0D is a single byte. Reading 0x0B as a byte gives
                // 0 for a 512-byte volume and silently invalidates the whole BPB.
                int bps = Bin.U16(b, off + 0x0B);
                int spc = b[off + 0x0D];
                if (bps < 128 || bps > 65536 || (bps & (bps - 1)) != 0) return null;   // power of two
                if (spc == 0 || (spc & (spc - 1)) != 0) return null;                   // power of two

                if (Bin.BytesEqual(b, off + 3, Ntfs))
                {
                    ulong total = Bin.U64(b, off + 0x28);
                    if (total == 0) return null;   // an NTFS volume bigger than 2^64 sectors is not a thing
                    return total * (ulong)bps;
                }
                if (Bin.BytesEqual(b, off + 3, ExFat))
                {
                    ulong total = Bin.U64(b, off + 0x40);
                    if (total == 0) return null;
                    return total * (ulong)bps;
                }
                if (Bin.BytesEqual(b, off + 82, Fat32))
                {
                    uint t32 = Bin.U32(b, off + 0x20);
                    if (t32 == 0) t32 = Bin.U32(b, off + 0x2C);      // 0 means "use the 64-bit field"
                    if (t32 == 0) return null;
                    return t32 * (ulong)bps;
                }
                if (Bin.BytesEqual(b, off + 54, Fat16) || Bin.BytesEqual(b, off + 54, FatOld) ||
                    Bin.BytesEqual(b, off + 54, Fat12))
                {
                    ushort t16 = Bin.U16(b, off + 0x13);
                    uint t32 = Bin.U32(b, off + 0x20);
                    ulong total = t16 != 0 ? t16 : t32;
                    if (total == 0) return null;
                    return total * (ulong)bps;
                }
            }
            catch { }
            return null;
        }

        /// <summary>Volume serial / label, purely for reporting.</summary>
        public static string SerialNumber(byte[] b, int off)
        {
            if (Bin.BytesEqual(b, off + 3, Ntfs))
                return Bin.U64(b, off + 0x48).ToString("X16");
            return null;
        }
    }
}
