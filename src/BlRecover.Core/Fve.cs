using System;
using System.Collections.Generic;
using System.Text;

namespace BlRecover
{
    internal enum FveVariant
    {
        Unknown,
        Vista,          // -FVE-FS- with boot entry EB 52 90, first block derived from cluster geometry
        Win7Plus,       // -FVE-FS- with boot entry EB 58 90, three u64 block offsets
        ToGo            // BitLocker To Go on FAT: MSWIN4.1 at offset 3
    }

    internal static class FveMethods
    {
        public static string Name(ushort m)
        {
            switch (m)
            {
                case 0x8000: return "AES-128-CBC + Elephant diffuser";
                case 0x8001: return "AES-256-CBC + Elephant diffuser";
                case 0x8002: return "AES-128-CBC";
                case 0x8003: return "AES-256-CBC";
                case 0x8004: return "AES-XTS-128 (AES-128)";
                case 0x8005: return "AES-XTS-256 (AES-256)";
                default: return "0x" + m.ToString("X4", System.Globalization.CultureInfo.InvariantCulture) + " (unknown)";
            }
        }
    }

    internal static class FveProtectors
    {
        public static string Name(ushort t)
        {
            switch (t)
            {
                case 0x0000: return "clear key (protection suspended - no credential needed)";
                case 0x0100: return "TPM";
                case 0x0200: return "startup key (USB)";
                case 0x0500: return "TPM + PIN";
                case 0x0800: return "recovery password (48-digit key)";
                case 0x2000: return "password";
                default: return null;
            }
        }

        /// <summary>Credential a user is most likely to have, used only for guidance text.</summary>
        public static string LikelyCredential(ushort t)
        {
            switch (t)
            {
                case 0x0800: return "48-digit recovery key";
                case 0x2000: return "unlock password";
                case 0x0000: return "none (protection is suspended)";
                case 0x0100: return "TPM - auto-unlocks on THIS PC, no key needed";
                case 0x0200: return "the USB startup key";
                case 0x0500: return "TPM + your PIN";
                default: return "TPM / automatic";
            }
        }
    }

    internal sealed class FveEntryInfo
    {
        public int Offset;
        public ushort Size;
        public ushort EntryType;    // 0x0000 property, 0x0002 VMK, 0x0003 FVEK, 0x000f volume header block
        public ushort ValueType;    // 0x0001 key, 0x0002 utf16, 0x0003 stretch key, 0x0005 AES-CCM, 0x000f offset+size
        public ushort? ProtectorType;
        public ulong? BlockOffset;
        public ulong? BlockSize;

        public string TypeName()
        {
            switch (EntryType)
            {
                case 0x0000: return "property";
                case 0x0001: return "property (retired)";
                case 0x0002: return "VMK (volume master key)";
                case 0x0003: return "FVEK (full volume key)";
                case 0x000f: return "volume header block";
                default: return "type 0x" + EntryType.ToString("X4", System.Globalization.CultureInfo.InvariantCulture);
            }
        }
    }

    internal sealed class FveMetadata
    {
        public bool BlockSignatureOk;
        public ushort BlockSizeField;
        public ushort BlockVersion;
        public ulong EncryptedVolumeSize;      // bytes of the volume that are encrypted; 0 == whole volume
        public uint NumberOfVolumeHeaderSectors;
        public ulong VolumeHeaderOffset;       // where the original unencrypted volume header is stored
        public ulong[] BlockOffsets = new ulong[3];
        public uint MetadataSize;
        public Guid VolumeGuid;
        public ushort EncryptionMethod;
        public ulong CreationFileTime;
        public readonly List<FveEntryInfo> Entries = new List<FveEntryInfo>();
        public string ParseNote = "";
        public bool LooksSane;

        public ulong VolumeHeaderSize
        {
            get { return (ulong)NumberOfVolumeHeaderSectors * 512UL; }
        }

        public int BlocksWithSignature;
    }

    /// <summary>Result of classifying one sector-aligned offset.</summary>
    internal sealed class FveHit
    {
        public ulong Lba;
        public long Offset;
        public bool IsVolumeHeader;     // -FVE-FS-/MSWIN4.1 at offset 3 -> start of the BitLocker volume
        public bool IsMetadataBlock;     // -FVE-FS- at offset 0 -> one of the 3 redundant FVE metadata blocks
        public FveVariant Variant;
        public FveMetadata Meta;         // only for volume headers
        public ulong[] BlockOffsets;
        public bool BlocksResolve;       // all/most of the referenced metadata blocks verified
        public bool OnCleanBoundary = true;   // start offset is a multiple of the scan alignment

        /// <summary>What the volume actually is. Only VolumeKind.Fve needs a key.</summary>
        public VolumeKind Kind = VolumeKind.Unknown;

        /// <summary>Partition size in bytes read from the filesystem's own BPB (unencrypted volumes).</summary>
        public ulong? BpbSize;
    }

    /// <summary>
    /// Parses BitLocker (FVE) on-disk structures. Read-only: this never decrypts and never
    /// touches key material - it only reads the cleartext volume header and the cleartext
    /// headers of the three FVE metadata blocks.
    /// </summary>
    internal static class Fve
    {
        public static readonly byte[] VolumeSig = Encoding.ASCII.GetBytes("-FVE-FS-");
        public static readonly byte[] ToGoSig = Encoding.ASCII.GetBytes("MSWIN4.1");
        public const int BlockHeaderSize = 64;
        public const int MetadataHeaderSize = 48;
        public const int MaxBlockBytes = 65536;

        /// <summary>
        /// Classifies the sector that starts at <paramref name="sectorOff"/> inside
        /// <paramref name="buf"/>. Returns null if the sector is not a BitLocker structure.
        /// </summary>
        public static FveHit Classify(byte[] buf, int sectorOff, int sectorLength, ulong lba, long offset)
        {
            bool volSig = Bin.BytesEqual(buf, sectorOff + 3, VolumeSig);
            bool togoSig = Bin.BytesEqual(buf, sectorOff + 3, ToGoSig);
            bool blockSig = Bin.BytesEqual(buf, sectorOff, VolumeSig);

            if (!volSig && !togoSig && !blockSig) return null;

            var hit = new FveHit();
            hit.Lba = lba;
            hit.Offset = offset;

            if (blockSig && !volSig)
            {
                // "-FVE-FS-" at offset 0 -> one of the three redundant metadata blocks that sit
                // near the front of the volume, not the volume header itself.
                hit.IsMetadataBlock = true;
                return hit;
            }

            hit.IsVolumeHeader = true;
            hit.Kind = VolumeProbe.Classify(buf, sectorOff);
            hit.BpbSize = VolumeProbe.SizeFromBpb(buf, sectorOff, buf.Length - sectorOff);

            // Pick the layout from the signature and the boot entry point.
            byte b0 = buf[sectorOff], b1 = buf[sectorOff + 1];
            if (togoSig)
            {
                hit.Variant = FveVariant.ToGo;
                hit.BlockOffsets = new ulong[]
                {
                    Bin.U64(buf, sectorOff + 440),
                    Bin.U64(buf, sectorOff + 448),
                    Bin.U64(buf, sectorOff + 456)
                };
                hit.Meta = new FveMetadata { VolumeGuid = Bin.Guid16(buf, sectorOff + 424), BlocksWithSignature = 0 };
            }
            else if (b0 == 0xEB && b1 == 0x52)
            {
                hit.Variant = FveVariant.Vista;
                // Vista: the first metadata block is located through the BPB cluster geometry.
                // Bytes-per-sector at 0x0B is a 16-bit field, sectors-per-cluster at 0x0D a byte.
                int bps = Bin.U16(buf, sectorOff + 0x0B);
                int spc = buf[sectorOff + 0x0D];
                ulong clusterSize = (bps == 0 || spc == 0) ? 0UL : (ulong)bps * (ulong)spc;
                ulong lcn = Bin.U64(buf, sectorOff + 0x38);
                ulong first = clusterSize == 0 ? 0UL : lcn * clusterSize;
                // Blocks 2 and 3 come from the block header at +32/+40/+48 once block 1 is read.
                hit.BlockOffsets = new ulong[] { first, 0, 0 };
            }
            else
            {
                hit.Variant = FveVariant.Win7Plus;
                hit.BlockOffsets = new ulong[]
                {
                    Bin.U64(buf, sectorOff + 176),
                    Bin.U64(buf, sectorOff + 184),
                    Bin.U64(buf, sectorOff + 192)
                };
                hit.Meta = new FveMetadata { VolumeGuid = Bin.Guid16(buf, sectorOff + 160), BlocksWithSignature = 0 };
            }

            return hit;
        }

        /// <summary>Reads and parses the FVE metadata block at a byte offset relative to the volume start.</summary>
        public static FveMetadata ReadMetadataBlock(byte[] buf, int len)
        {
            var m = new FveMetadata();
            m.BlockSignatureOk = Bin.BytesEqual(buf, 0, VolumeSig);
            if (!m.BlockSignatureOk) { m.ParseNote = "no -FVE-FS- signature at block start"; return m; }
            if (len < BlockHeaderSize + MetadataHeaderSize)
            {
                m.ParseNote = "block truncated (" + len + " bytes)";
                return m;
            }

            m.BlockSizeField = Bin.U16(buf, 8);
            m.BlockVersion = Bin.U16(buf, 10);
            m.EncryptedVolumeSize = Bin.U64(buf, 16);
            m.NumberOfVolumeHeaderSectors = Bin.U32(buf, 28);
            m.BlockOffsets[0] = Bin.U64(buf, 32);
            m.BlockOffsets[1] = Bin.U64(buf, 40);
            m.BlockOffsets[2] = Bin.U64(buf, 48);
            m.VolumeHeaderOffset = Bin.U64(buf, 56);

            int md = BlockHeaderSize;
            m.MetadataSize = Bin.U32(buf, md);
            m.VolumeGuid = Bin.Guid16(buf, md + 16);
            m.EncryptionMethod = Bin.U16(buf, md + 36);
            m.CreationFileTime = Bin.U64(buf, md + 40);

            // Sanity: the volume GUID must be non-zero and the method must be one we recognise.
            m.LooksSane = m.VolumeGuid != Guid.Empty && m.EncryptionMethod != 0
                          && m.EncryptionMethod >= 0x8000 && m.EncryptionMethod <= 0x8005
                          && m.MetadataSize >= MetadataHeaderSize && m.MetadataSize <= MaxBlockBytes;

            // Walk the entry array.
            int end = BlockHeaderSize + (int)m.MetadataSize;
            if (end > len) { end = len; m.ParseNote = "metadata_size runs past block; entries truncated"; }
            int pos = BlockHeaderSize + MetadataHeaderSize;
            int guard = 0;
            while (pos + 8 <= end && guard++ < 4096)
            {
                ushort size = Bin.U16(buf, pos);
                if (size < 8 || pos + size > end) { m.ParseNote = "entry at +" + pos + " has implausible size " + size; break; }
                var e = new FveEntryInfo();
                e.Offset = pos;
                e.Size = size;
                e.EntryType = Bin.U16(buf, pos + 2);
                e.ValueType = Bin.U16(buf, pos + 4);

                if (e.EntryType == 0x0002 && size >= 28)
                {
                    ushort pt = Bin.U16(buf, pos + 26);
                    if (FveProtectors.Name(pt) != null) e.ProtectorType = pt;
                }
                if (e.EntryType == 0x000f && e.ValueType == 0x000f && size >= 24)
                {
                    e.BlockOffset = Bin.U64(buf, pos + 8);
                    e.BlockSize = Bin.U64(buf, pos + 16);
                }
                m.Entries.Add(e);
                pos += size;
            }
            return m;
        }

        /// <summary>Reads the full chain starting from a sector aligned with a volume header.</summary>
        public static FveHit Resolve(RawDisk d, FveHit hit, out string note)
        {
            note = "";
            try
            {
                byte[] vh = d.ReadAt(hit.Offset, d.BytesPerSector);

                if (hit.Variant == FveVariant.ToGo && hit.Meta != null)
                {
                    // GUID already captured from offset 424; read block 1 for the rest.
                }

                FveMetadata meta = null;
                var seenOffsets = new List<ulong>();

                if (hit.Variant == FveVariant.Win7Plus || hit.Variant == FveVariant.ToGo)
                {
                    // Re-read the three block offsets straight from the volume header.
                    int baseOff = hit.Variant == FveVariant.ToGo ? 440 : 176;
                    for (int i = 0; i < 3; i++)
                    {
                        ulong bo = Bin.U64(vh, baseOff + i * 8);
                        seenOffsets.Add(bo);
                    }
                }
                else
                {
                    // Vista: only block 1 is known up front; 2 and 3 come from the block header.
                    seenOffsets.Add(hit.BlockOffsets[0]);
                }

                // Vista re-seed bookkeeping. Block 1's header carries the authoritative offsets for
                // blocks 2 and 3, but it normally reports its OWN offset in BlockOffsets[0]. So the
                // restart below re-reads the very same block unless it is done at most once - which
                // used to spin forever on any healthy Vista volume. This loop walks untrusted
                // on-disk data, so it also carries a hard read cap.
                bool reseeded = false;
                int guard = 0;
                for (int i = 0; i < seenOffsets.Count; i++)
                {
                    if (++guard > 64) { note = "metadata block walk hit its read limit"; break; }
                    ulong rel = seenOffsets[i];
                    if (rel == 0) { note = "metadata block offset #" + (i + 1) + " is zero"; continue; }
                    long abs = hit.Offset + (long)rel;
                    if (abs < 0 || abs + MaxBlockBytes > d.SizeBytes)
                    {
                        note = "metadata block #" + (i + 1) + " offset " + rel + " is outside the device";
                        continue;
                    }
                    byte[] block = d.ReadAt(abs, MaxBlockBytes);
                    FveMetadata bm = ReadMetadataBlock(block, MaxBlockBytes);
                    if (!bm.BlockSignatureOk) continue;
                    if (meta == null) meta = bm;

                    if (hit.Variant == FveVariant.Vista && i == 0 && !reseeded)
                    {
                        reseeded = true;
                        seenOffsets.Clear();
                        seenOffsets.Add(bm.BlockOffsets[0]);
                        seenOffsets.Add(bm.BlockOffsets[1]);
                        seenOffsets.Add(bm.BlockOffsets[2]);
                        if (seenOffsets[0] == 0 && seenOffsets[1] == 0 && seenOffsets[2] == 0) break;
                        i = -1; // restart once, now with the authoritative offsets
                    }
                }

                if (meta == null)
                {
                    note = "no FVE metadata block could be read (header present but blocks missing)";
                    if (hit.Meta != null) { hit.Meta.LooksSane = false; hit.Meta.ParseNote = note; }
                    hit.Meta = hit.Meta ?? new FveMetadata { LooksSane = false };
                    hit.BlocksResolve = false;
                    return hit;
                }

                // Count how many of the three referenced blocks actually carry a signature.
                int found = 0;
                for (int i = 0; i < 3; i++)
                {
                    ulong rel = meta.BlockOffsets[i];
                    if (rel == 0) continue;
                    long abs = hit.Offset + (long)rel;
                    if (abs < 0 || abs + 8 > d.SizeBytes) continue;
                    byte[] sig = d.ReadAt(abs, 8);
                    if (Bin.BytesEqual(sig, 0, VolumeSig)) found++;
                }
                meta.BlocksWithSignature = found;
                hit.BlockOffsets = meta.BlockOffsets;
                hit.Meta = meta;
                hit.BlocksResolve = found > 0;
                if (found == 1) meta.ParseNote = "only 1 of 3 metadata blocks is readable";
                else if (found == 2) meta.ParseNote = "2 of 3 metadata blocks readable";
                else if (found == 3) meta.ParseNote = "all 3 metadata blocks readable";
                return hit;
            }
            catch (Exception ex)
            {
                note = ex.Message;
                hit.Meta = hit.Meta ?? new FveMetadata { LooksSane = false };
                return hit;
            }
        }

        /// <summary>Best-guess partition size in bytes from the FVE metadata.</summary>
        public static ulong? SuggestPartitionSize(FveMetadata m, int bytesPerSector, long deviceBytes, long volumeStartOffset)
        {
            if (m == null) return null;
            ulong evs = m.EncryptedVolumeSize;
            if (evs == 0)
            {
                // 0 means "the whole volume"; fall back to the space left on the device.
                ulong remaining = (ulong)Math.Max(0, deviceBytes - volumeStartOffset);
                return remaining;
            }
            // Round up to a whole sector.
            ulong bps = (ulong)bytesPerSector;
            ulong rounded = ((evs + bps - 1) / bps) * bps;
            if ((long)rounded > deviceBytes - volumeStartOffset)
                rounded = (ulong)Math.Max(0, deviceBytes - volumeStartOffset);
            return rounded;
        }
    }
}
