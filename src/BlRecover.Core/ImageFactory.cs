using System;
using System.IO;
using System.Runtime.InteropServices;

namespace BlRecover
{
    /// <summary>
    /// Builds synthetic disk images that look like a BitLocker-encrypted GPT or MBR disk.
    /// Used by the self-test suite and by the CLI's "mkimage" command so the whole recovery
    /// path can be rehearsed on a file before anyone touches a real drive.
    /// </summary>
    internal static class ImageFactory
    {
        private const uint FSCTL_SET_SPARSE = 0x000900C4;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DeviceIoControl(
            Microsoft.Win32.SafeHandles.SafeFileHandle hDevice,
            uint dwIoControlCode,
            IntPtr lpInBuffer, uint nInBufferSize,
            IntPtr lpOutBuffer, uint nOutBufferSize,
            out uint lpBytesReturned, IntPtr lpOverlapped);

        /// <summary>
        /// Creates an image file that is a true sparse file of the requested length.
        /// This matters: a plain SetLength on a 500 GB image allocates 500 GB for real.
        /// FILE_ATTRIBUTE_SPARSE is silently ignored by SetFileAttributes, so the only
        /// supported route is the FSCTL_SET_SPARSE control code.
        /// </summary>
        public static void CreateSparse(string path, long sizeBytes)
        {
            if (sizeBytes <= 0) throw new ArgumentOutOfRangeException("sizeBytes");

            if (!File.Exists(path))
            {
                using (new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None)) { }
            }

            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.None))
            {
                if (!SetSparse(fs))
                {
                    int err = Marshal.GetLastWin32Error();
                    // Never grow a file we could not make sparse - that would allocate for real.
                    throw new IOException("The file system refused to make " + path + " sparse " +
                                          "(Win32 error " + err + "), so it cannot safely host a " +
                                          (sizeBytes / (1024 * 1024 * 1024)) +
                                          " GB image. Pick another file system or a smaller --size-mb.");
                }
                // Safe now: a sparse file records the new EOF without allocating clusters.
                fs.SetLength(sizeBytes);
                fs.Flush(true);
            }
        }

        private static bool SetSparse(FileStream fs)
        {
            uint returned;
            return DeviceIoControl(fs.SafeFileHandle, FSCTL_SET_SPARSE,
                                   IntPtr.Zero, 0, IntPtr.Zero, 0, out returned, IntPtr.Zero);
        }

        /// <summary>Writes a Windows 7/10 style BitLocker volume header at a byte offset.</summary>
        public static byte[] BuildVolumeHeader(int bps, int spc, Guid volumeGuid,
                                               ulong block1, ulong block2, ulong block3)
        {
            var v = new byte[bps];
            v[0] = 0xEB; v[1] = 0x58; v[2] = 0x90;
            Buffer.BlockCopy(System.Text.Encoding.ASCII.GetBytes("-FVE-FS-"), 0, v, 3, 8);
            Bin.PutU16(v, 0x0B, (ushort)bps);   // bytes per sector is a 16-bit BPB field
            v[0x0D] = (byte)spc;               // sectors per cluster is a single byte
            v[0x1FE] = 0x55; v[0x1FF] = 0xAA;
            Bin.PutGuid16(v, 160, volumeGuid);
            Bin.PutU64(v, 176, block1);
            Bin.PutU64(v, 184, block2);
            Bin.PutU64(v, 192, block3);
            return v;
        }

        /// <summary>Writes one of the three redundant FVE metadata blocks.</summary>
        public static byte[] BuildMetadataBlock(ushort method, ushort protectorType, Guid volumeGuid,
                                                ulong encryptedVolumeSize,
                                                ulong block1, ulong block2, ulong block3,
                                                ulong volumeHeaderOffset, ulong creationFileTime)
        {
            var b = new byte[Fve.MaxBlockBytes];
            Buffer.BlockCopy(System.Text.Encoding.ASCII.GetBytes("-FVE-FS-"), 0, b, 0, 8);
            Bin.PutU16(b, 8, 0x2000);
            Bin.PutU16(b, 10, 2);                                  // block header version
            Bin.PutU64(b, 16, encryptedVolumeSize);                // encrypted volume size
            Bin.PutU32(b, 28, 1);                                  // number of volume header sectors
            Bin.PutU64(b, 32, block1);
            Bin.PutU64(b, 40, block2);
            Bin.PutU64(b, 48, block3);
            Bin.PutU64(b, 56, volumeHeaderOffset);

            int md = 64;
            Bin.PutU32(b, md, 0);                                  // patched once entries are laid out
            Bin.PutGuid16(b, md + 16, volumeGuid);
            Bin.PutU16(b, md + 36, method);
            Bin.PutU64(b, md + 40, creationFileTime);

            int pos = md + 48;

            int e1 = 56;                                          // VMK with a stretch-key value
            Bin.PutU16(b, pos + 0, (ushort)e1);
            Bin.PutU16(b, pos + 2, 0x0002);
            Bin.PutU16(b, pos + 4, 0x0003);
            Bin.PutU16(b, pos + 6, 1);
            Bin.PutU16(b, pos + 26, protectorType);
            pos += e1;

            int e2 = 96;                                          // FVEK, AES-CCM wrapped
            Bin.PutU16(b, pos + 0, (ushort)e2);
            Bin.PutU16(b, pos + 2, 0x0003);
            Bin.PutU16(b, pos + 4, 0x0005);
            Bin.PutU16(b, pos + 6, 1);
            pos += e2;

            int e3 = 24;                                          // relocated volume header block
            Bin.PutU16(b, pos + 0, (ushort)e3);
            Bin.PutU16(b, pos + 2, 0x000f);
            Bin.PutU16(b, pos + 4, 0x000f);
            Bin.PutU16(b, pos + 6, 1);
            Bin.PutU64(b, pos + 8, volumeHeaderOffset);
            Bin.PutU64(b, pos + 16, 512);
            pos += e3;

            Bin.PutU32(b, md, (uint)(pos - md));
            return b;
        }

        public static void WriteVolume(RawDisk d, long baseOffset, int bps, int spc,
                                       ushort method, ushort protector, Guid volumeGuid,
                                       ulong encryptedVolumeSize, ulong creationFileTime)
        {
            ulong b1 = 0x100000, b2 = 0x200000, b3 = 0x300000, vhOff = 0x80000;
            d.WriteAt(baseOffset, BuildVolumeHeader(bps, spc, volumeGuid, b1, b2, b3), bps);
            byte[] blk = BuildMetadataBlock(method, protector, volumeGuid, encryptedVolumeSize,
                                            b1, b2, b3, vhOff, creationFileTime);
            d.WriteAt(baseOffset + (long)b1, blk, blk.Length);
            d.WriteAt(baseOffset + (long)b2, blk, blk.Length);
            d.WriteAt(baseOffset + (long)b3, blk, blk.Length);
        }

        /// <summary>Boot sector for a plain, unencrypted NTFS or exFAT volume.</summary>
        public static byte[] BuildPlainBootSector(VolumeKind kind, int bps, ulong volumeBytes)
        {
            var s = new byte[bps];
            s[0] = 0xEB; s[1] = 0x52; s[2] = 0x90;
            ulong totalSectors = volumeBytes / (ulong)bps;

            if (kind == VolumeKind.ExFat)
            {
                Buffer.BlockCopy(VolumeProbe.ExFat, 0, s, 3, 8);
                Bin.PutU16(s, 0x0B, (ushort)bps);
                s[0x0D] = 8;                                   // sectors per cluster
                Bin.PutU64(s, 0x40, totalSectors);             // volume length
                Bin.PutU32(s, 0x64, 0x1000);                  // FAT offset
            }
            else
            {
                Buffer.BlockCopy(VolumeProbe.Ntfs, 0, s, 3, 8);
                Bin.PutU16(s, 0x0B, (ushort)bps);
                s[0x0D] = 8;
                s[0x15] = 0xF8;                               // media descriptor
                s[0x24] = 0x80; s[0x26] = 0x80;               // extended boot signature
                Bin.PutU64(s, 0x28, totalSectors);
                Bin.PutU64(s, 0x30, 4);                       // MFT LCN
                s[0x40] = unchecked((byte)-10);                // clusters per MFT record (2^10 = 1024)
                Bin.PutU64(s, 0x48, 0x0011223344556677UL);    // volume serial
            }
            s[bps - 2] = 0x55;
            s[bps - 1] = 0xAA;
            return s;
        }

        public sealed class Spec
        {
            public string Path;
            public int BytesPerSector = 512;
            public int SectorsPerCluster = 8;
            public long SizeBytes;
            public bool Mbr;
            public bool DestroyPrimaryGpt;      // simulate `diskpart clean`
            public ulong VolumeStartLba = 2048;
            public ulong VolumeSectors;
            public ushort Method = 0x8000;
            public ushort Protector = 0x0800;
            /// <summary>If set, write a plain filesystem boot sector instead of a BitLocker one.</summary>
            public VolumeKind Filesystem = VolumeKind.Fve;
            public Guid VolumeGuid = new Guid("1D9A0C55-8E7B-4A31-9F02-6C5D4E3B2A10");
            public ulong CreationFileTime = 130000000000000000UL;
        }

        public static Spec BuildFile(Spec spec)
        {
            int bps = spec.BytesPerSector;
            ulong volBytes = spec.VolumeSectors * (ulong)bps;

            CreateSparse(spec.Path, spec.SizeBytes);

            using (RawDisk d = RawDisk.OpenDevice(0, spec.Path, "synthetic", "", "file", false, 0, bps, true))
            {
                if (spec.Mbr)
                {
                    var mbr = new byte[bps];
                    int baseOff = 446;
                    mbr[baseOff + 4] = 0x07;                        // a healthy NTFS partition first
                    Bin.PutU32(mbr, baseOff + 8, 2048);
                    Bin.PutU32(mbr, baseOff + 12, 2048);
                    d.WriteAt(0, mbr, bps);
                }
                else
                {
                    var lay = new Gpt.Layout { DiskGuid = Guid.NewGuid() };
                    if (!spec.DestroyPrimaryGpt)
                    {
                        // A partition entry that is then zeroed, mimicking a deletion.
                        lay.Entries.Add(new GptEntry
                        {
                            SlotIndex = 0,
                            TypeGuid = GptTypes.BasicData,
                            UniqueGuid = Guid.NewGuid(),
                            FirstLba = 34,
                            LastLba = 2047,
                            Name = "System"
                        });
                    }
                    Gpt.Write(d, lay);
                }

                if (spec.Filesystem == VolumeKind.Fve)
                {
                    WriteVolume(d, d.LbaToOffset((long)spec.VolumeStartLba), bps, spec.SectorsPerCluster,
                                spec.Method, spec.Protector, spec.VolumeGuid, volBytes, spec.CreationFileTime);
                }
                else
                {
                    d.WriteAt(d.LbaToOffset((long)spec.VolumeStartLba),
                              BuildPlainBootSector(spec.Filesystem, bps, volBytes), bps);
                }

                if (!spec.Mbr && spec.DestroyPrimaryGpt)
                {
                    // Wipe LBA 0 and the primary header + entry array, exactly like `diskpart clean`.
                    d.WriteAt(0, new byte[bps * 40], bps * 40);
                    d.Flush();
                }
            }
            return spec;
        }
    }
}
