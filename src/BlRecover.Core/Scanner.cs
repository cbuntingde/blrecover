using System;
using System.Collections.Generic;

namespace BlRecover
{
    internal sealed class LbaRange
    {
        public ulong First;
        public ulong Last;
        public string Source;
        /// <summary>True for GPT/MBR structures themselves - never safe to write over.</summary>
        public bool Structural;

        public bool Overlaps(ulong f, ulong l)
        {
            return f <= Last && l >= First;
        }

        public static LbaRange Of(GptEntry e, string source)
        {
            return new LbaRange { First = e.FirstLba, Last = e.LastLba, Source = source };
        }
    }

    internal sealed class ScanOptions
    {
        public int Alignment = 1024 * 1024;   // 1 MiB: where virtually every BitLocker volume starts
        public bool ScanWholeDevice;           // ignore "in use" ranges
        public ulong MaxOffset;                // 0 = whole device
        public bool Progress = true;
    }

    internal sealed class ScanResult
    {
        public readonly List<FveHit> VolumeHeaders = new List<FveHit>();
        public readonly List<FveHit> OrphanMetadataBlocks = new List<FveHit>();
        public readonly List<FveHit> InUse = new List<FveHit>();
        public ulong BytesScanned;
        public ulong BytesSkipped;
        public int ReadErrors;
    }

    /// <summary>
    /// Streams the device looking for the BitLocker volume header signature at the start of a
    /// sector. A deleted partition leaves its volume header fully intact, so finding one in
    /// currently-unallocated space is the signal that a recoverable volume exists.
    /// </summary>
    internal static class Scanner
    {
        private const int ChunkBytes = 4 * 1024 * 1024;

        /// <summary>
        /// Complement of <paramref name="inUse"/> over [0, sectorLimit). Scanning is done per
        /// free range so that a small in-use region never causes a whole chunk - and a volume
        /// sitting right next to it - to be skipped.
        /// </summary>
        private static List<LbaRange> BuildFreeRanges(long sectorLimit, IList<LbaRange> inUse, bool whole)
        {
            var free = new List<LbaRange>();
            if (whole || inUse == null || inUse.Count == 0)
            {
                free.Add(new LbaRange { First = 0, Last = (ulong)Math.Max(0, sectorLimit - 1), Source = "whole device" });
                return free;
            }

            var used = new List<LbaRange>();
            foreach (LbaRange r in inUse)
            {
                if (r.Last >= r.First && r.First < (ulong)sectorLimit)
                    used.Add(new LbaRange { First = r.First, Last = Math.Min(r.Last, (ulong)(sectorLimit - 1)), Source = r.Source });
            }
            used.Sort((a, b) => a.First.CompareTo(b.First));

            ulong cursor = 0;
            foreach (LbaRange u in used)
            {
                if (u.First > cursor)
                    free.Add(new LbaRange { First = cursor, Last = u.First - 1, Source = "free" });
                if (u.Last + 1 > cursor) cursor = u.Last + 1;
            }
            if (cursor < (ulong)sectorLimit)
                free.Add(new LbaRange { First = cursor, Last = (ulong)(sectorLimit - 1), Source = "free" });

            free.RemoveAll(r => r.Last < r.First);
            return free;
        }

        public static ScanResult Scan(RawDisk d, IList<LbaRange> inUse, ScanOptions opt,
                                      Action<string> report)
        {
            var result = new ScanResult();
            int bps = d.BytesPerSector;
            int align = opt.Alignment < bps ? bps : opt.Alignment;
            if (align % bps != 0) align = ((align / bps) + 1) * bps;

            ulong limit = opt.MaxOffset > 0 && opt.MaxOffset < (ulong)d.SizeBytes
                ? opt.MaxOffset
                : (ulong)d.SizeBytes;
            limit = (limit / (ulong)bps) * (ulong)bps;
            long sectorLimit = (long)(limit / (ulong)bps);

            List<LbaRange> ranges = BuildFreeRanges(sectorLimit, inUse, opt.ScanWholeDevice);
            ulong totalBytes = 0;
            foreach (LbaRange r in ranges) totalBytes += (r.Last - r.First + 1) * (ulong)bps;
            ulong nextReport = totalBytes / 16;

            var buffer = new byte[ChunkBytes];
            ulong doneBytes = 0;

            foreach (LbaRange range in ranges)
            {
                long rangeStart = (long)range.First * bps;
                long rangeEnd = ((long)range.Last + 1) * bps;
                long pos = rangeStart;

                while (pos < rangeEnd)
                {
                    int want = ChunkBytes;
                    if (pos + want > rangeEnd) want = (int)(rangeEnd - pos);
                    want = (want / bps) * bps;
                    if (want <= 0) break;

                    int got;
                    try
                    {
                        got = ReadFully(d, pos, buffer, want);
                    }
                    catch (Exception)
                    {
                        result.ReadErrors++;
                        pos += want;
                        doneBytes += (ulong)want;
                        continue;
                    }

                    result.BytesScanned += (ulong)got;
                    doneBytes += (ulong)got;

                    int sectors = got / bps;
                    for (int s = 0; s < sectors; s++)
                    {
                        int off = s * bps;
                        // Fast reject. Every filesystem we care about has a signature at offset 3
                        // (NTFS/exFAT/BitLocker) or at 0x36/0x56/0x1B (FAT32/16/12), so this is
                        // four byte comparisons before we give up on a sector.
                        byte c0 = buffer[off], c3 = buffer[off + 3];
                        if (!(c3 == 0x2D || c3 == 0x4D || c3 == 0x4E || c3 == 0x45
                              || c0 == 0xEB || c0 == 0xE9 || c0 == 0x52)) continue;

                        long absOffset = pos + off;
                        ulong lba = (ulong)(absOffset / bps);

                        VolumeKind kind = VolumeProbe.Classify(buffer, off);
                        if (kind == VolumeKind.Unknown) continue;

                        FveHit hit = Fve.Classify(buffer, off, bps, lba, absOffset);
                        if (hit == null)
                        {
                            // Not a BitLocker structure, but a real filesystem volume header.
                            hit = new FveHit
                            {
                                Lba = lba,
                                Offset = absOffset,
                                IsVolumeHeader = true,
                                Kind = kind,
                                BpbSize = VolumeProbe.SizeFromBpb(buffer, off, bps)
                            };
                        }
                        hit.OnCleanBoundary = align <= bps || (absOffset % align) == 0;

                        if (hit.IsMetadataBlock) result.OrphanMetadataBlocks.Add(hit);
                        else if (IsCovered(inUse, lba)) result.InUse.Add(hit);
                        else result.VolumeHeaders.Add(hit);
                    }

                    if (opt.Progress && nextReport > 0 && doneBytes >= nextReport)
                    {
                        nextReport += totalBytes / 16;
                        if (report != null)
                            report("  scanned " + Fmt.HumanSize(doneBytes) + " / " + Fmt.HumanSize(totalBytes));
                    }
                    pos += want;
                }
            }
            result.BytesSkipped = (ulong)d.SizeBytes - result.BytesScanned;
            return result;
        }

        /// <summary>
        /// Classification only: whether a hit sits inside a partition that is currently in use.
        /// This is independent of whether the scan covered the whole device.
        /// </summary>
        private static bool IsCovered(IList<LbaRange> inUse, ulong lba)
        {
            if (inUse == null) return false;
            foreach (LbaRange r in inUse) if (r.Overlaps(lba, lba)) return true;
            return false;
        }

        private static int ReadFully(RawDisk d, long offset, byte[] buffer, int want)
        {
            d.ReadAt(offset, buffer, want);
            return want;
        }

        /// <summary>Collects LBAs claimed by live partitions from whatever table structures are usable.</summary>
        public static List<LbaRange> CollectInUse(RawDisk d, GptImage primary, GptImage backup, MbrDisk mbr)
        {
            var list = new List<LbaRange>();
            // GPT structures (header + entry array) are never a user partition.
            if (primary != null && primary.Usable)
            {
                int arr = primary.Header.ArraySectors(d.BytesPerSector);
                list.Add(new LbaRange { First = 0, Last = 1 + (ulong)arr, Source = "primary GPT", Structural = true });
                ulong backupArrayLba = primary.Header.LastUsableLba + 1;
                list.Add(new LbaRange { First = backupArrayLba, Last = (ulong)d.SectorCount - 1, Source = "backup GPT", Structural = true });
                foreach (GptEntry e in primary.Entries)
                    if (e.InUse && e.LastLba >= e.FirstLba)
                        list.Add(LbaRange.Of(e, "GPT slot " + e.SlotIndex));
            }
            else if (backup != null && backup.Usable)
            {
                int arr = backup.Header.ArraySectors(d.BytesPerSector);
                list.Add(new LbaRange { First = 0, Last = 1 + (ulong)arr, Source = "primary GPT (assumed)", Structural = true });
                list.Add(new LbaRange
                {
                    First = (ulong)((long)backup.Header.EntryLba - arr),
                    Last = (ulong)d.SectorCount - 1,
                    Source = "backup GPT",
                    Structural = true
                });
                foreach (GptEntry e in backup.Entries)
                    if (e.InUse && e.LastLba >= e.FirstLba)
                        list.Add(LbaRange.Of(e, "backup GPT slot " + e.SlotIndex));
            }
            else if (mbr != null && !mbr.IsProtectiveForGpt)
            {
                for (int i = 0; i < mbr.Entries.Count; i++)
                {
                    MbrEntry e = mbr.Entries[i];
                    if (e.InUse && e.SectorCount > 0)
                        list.Add(new LbaRange
                        {
                            First = e.StartLba,
                            Last = e.StartLba + e.SectorCount - 1,
                            Source = "MBR slot " + i
                        });
                }
            }
            return list;
        }
    }
}
