using System;
using System.Collections.Generic;
using System.IO;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace BlRecover
{
    /// <summary>
    /// Block-addressed access to a physical disk (\\.\PhysicalDriveN) or to a raw image file.
    /// All offsets in this program are BYTE offsets unless the name says Lba.
    /// </summary>
    internal sealed class RawDisk : IDisposable
    {
        private Microsoft.Win32.SafeHandles.SafeFileHandle _handle;

        public int Index { get; private set; }
        public string DevicePath { get; private set; }
        public string Model { get; set; }
        public string Serial { get; set; }
        public string BusType { get; set; }
        public bool IsImage { get; private set; }
        public int BytesPerSector { get; set; }
        public long SizeBytes { get; private set; }
        public bool CanWrite { get; private set; }
        public string ReadOnlyReason { get; private set; }
        public bool IsBoot { get; set; }

        /// <summary>Exact Win32 error from the last failed open, for diagnostics.</summary>
        public int LastWin32 { get; private set; }
        public string LastErrorText { get; private set; }

        public RawDisk(int bytesPerSector)
        {
            BytesPerSector = bytesPerSector;
        }

        public long SectorCount { get { return SizeBytes / BytesPerSector; } }

        public long LbaToOffset(long lba) { return lba * (long)BytesPerSector; }

        public ulong LbaToOffsetU(ulong lba) { return lba * (ulong)BytesPerSector; }

        private static RawDisk OpenHandle(RawDisk d, string devicePath, bool allowWrite)
        {
            int win32;
            uint share = Native.FILE_SHARE_READ | Native.FILE_SHARE_WRITE;
            uint flags = Native.FILE_ATTRIBUTE_NORMAL;

            // Devices and image files both need read+write share so another tool can hold the
            // volume open. Write access is requested only when the caller actually wants it.
            if (allowWrite)
            {
                SafeFileHandle hw = Native.TryOpen(devicePath, Native.GENERIC_READ | Native.GENERIC_WRITE,
                                                   share, flags, out win32);
                if (!hw.IsInvalid)
                {
                    d._handle = hw;
                    d.CanWrite = true;
                    return d;
                }
                d.LastWin32 = win32;
                d.LastErrorText = Native.DescribeError(win32);
            }

            SafeFileHandle hr = Native.TryOpen(devicePath, Native.GENERIC_READ, share, flags, out win32);
            if (!hr.IsInvalid)
            {
                d._handle = hr;
                if (allowWrite) d.ReadOnlyReason = "opened read-only: write access was refused";
                return d;
            }

            d.LastWin32 = win32;
            d.LastErrorText = Native.DescribeError(win32);
            if (win32 == 5) throw new UnauthorizedAccessException(BuildAccessDeniedMessage(devicePath, win32));
            throw new IOException("Cannot open " + devicePath + ": " + Native.DescribeError(win32) +
                                  " (Win32 " + win32 + ").");
        }

        private static string BuildAccessDeniedMessage(string devicePath, int win32)
        {
            var sb = new StringBuilder();
            sb.Append("Windows refused to open ").Append(devicePath).Append(" (Win32 ").Append(win32)
              .Append(": ").Append(Native.DescribeError(win32)).AppendLine(").");
            sb.AppendLine();
            sb.AppendLine("Run \"blrecover diagnose\" for a full breakdown - it tests every access route and");
            sb.AppendLine("prints the exact error for each one.");
            sb.AppendLine();
            sb.Append(Privileges.StatusHelp());
            return sb.ToString();
        }

        public static RawDisk OpenDevice(int index, string devicePath, string model, string serial,
                                         string busType, bool isBoot, long declaredSize, int declaredBps,
                                         bool allowWrite)
        {
            var d = new RawDisk(declaredBps > 0 ? declaredBps : 512);
            d.Index = index;
            d.DevicePath = devicePath;
            d.Model = model;
            d.Serial = serial;
            d.BusType = busType;
            d.IsBoot = isBoot;
            d.IsImage = !devicePath.StartsWith(@"\\.\", StringComparison.OrdinalIgnoreCase);

            if (d.IsImage)
            {
                try { d.FileLength = new FileInfo(devicePath).Length; } catch { }
            }

            // One code path for everything: CreateFile + ReadFile/WriteFile. No FileStream,
            // because GetFileSizeEx and file-style seek semantics do not apply to block devices.
            OpenHandle(d, devicePath, allowWrite);
            if (!allowWrite && d.ReadOnlyReason == null) d.ReadOnlyReason = "opened read-only for analysis";

            d.SizeBytes = d.QueryRealSize()                          // authoritative: from the disk driver
                           ?? d.FileLength                         // regular file
                           ?? (declaredSize > 0 ? (long?)declaredSize : null)  // what Windows reports
                           ?? 0;
            if (d.SizeBytes <= 0)
            {
                var sb = new StringBuilder("Could not determine the size of ").Append(devicePath).Append('.');
                sb.Append(" GetFileSizeEx and IOCTL_DISK_GET_LENGTH_INFO both failed");
                if (d.LastWin32 != 0)
                    sb.Append(" (Win32 ").Append(d.LastWin32).Append(": ")
                      .Append(Native.DescribeError(d.LastWin32)).Append(')');
                sb.Append(". Run \"blrecover diagnose\" for the full picture.");
                throw new IOException(sb.ToString());
            }
            if (d.SizeBytes < d.BytesPerSector * 4)
                throw new IOException("Device " + devicePath + " is too small to hold a partition table.");
            return d;
        }

        /// <summary>Known length for regular files, used only as a fallback for images.</summary>
        private long? FileLength { get; set; }

        /// <summary>
        /// Ask the driver for the real device length. GetFileSizeEx fails with
        /// ERROR_INVALID_FUNCTION on a disk, so IOCTL_DISK_GET_LENGTH_INFO is the only way.
        /// The backup GPT lives in the very last sectors, so this number must be exact.
        /// </summary>
        private long? QueryRealSize()
        {
            if (_handle == null || _handle.IsInvalid) return null;
            try
            {
                var outBuf = new byte[32];
                uint returned;
                if (Native.DeviceIoControl(_handle, Native.IOCTL_DISK_GET_LENGTH_INFO, null, 0,
                                           outBuf, (uint)outBuf.Length, out returned, IntPtr.Zero))
                {
                    long len = BitConverter.ToInt64(outBuf, 0);
                    if (len > 0) return len;
                }
                else
                {
                    LastWin32 = Marshal.GetLastWin32Error();
                    LastErrorText = Native.DescribeError(LastWin32);
                }
            }
            catch { }

            if (IsImage)
            {
                long sz;
                if (Native.GetFileSizeEx(_handle, out sz) && sz > 0) return sz;
            }
            return null;
        }

        public byte[] ReadAt(long offset, int count)
        {
            var b = new byte[count];
            ReadAt(offset, b, count);
            return b;
        }

        /// <summary>
        /// Positioned read, implemented with SetFilePointerEx + ReadFile.
        ///
        /// FileStream is deliberately NOT used for devices: it calls GetFileSizeEx, which fails
        /// with ERROR_INVALID_FUNCTION on a block device, and it assumes seekable-file semantics
        /// that disk handles do not have. Every native tool reads disks this way.
        /// </summary>
        public void ReadAt(long offset, byte[] buffer, int count)
        {
            if (count == 0) return;
            if (offset < 0 || offset + (long)count > SizeBytes)
                throw new ArgumentOutOfRangeException("offset",
                    "read of " + count + " bytes at " + offset + " runs past end of device (" + SizeBytes + ")");

            long remaining = count;
            long pos = offset;
            int done = 0;
            // A single ReadFile can come up short on some drivers, so loop until satisfied.
            while (remaining > 0)
            {
                long newPos;
                if (!Native.SetFilePointerEx(_handle, pos, out newPos, Native.FILE_BEGIN))
                    throw new IOException("Seek to " + pos + " failed: " +
                        Native.DescribeError(Marshal.GetLastWin32Error()));
                uint got;
                if (!Native.ReadFile(_handle, buffer, (uint)(done + (int)remaining), out got, IntPtr.Zero))
                    throw new IOException("Read of " + count + " bytes at " + offset + " failed: " +
                        Native.DescribeError(Marshal.GetLastWin32Error()));
                if (got == 0) throw new EndOfStreamException("Unexpected end of device at offset " + pos);
                done += (int)got;
                pos += got;
                remaining -= got;
            }
        }

        public void WriteAt(long offset, byte[] buffer, int count)
        {
            if (!CanWrite) throw new InvalidOperationException("Device is not open for writing: " + ReadOnlyReason);
            if (offset < 0 || offset + (long)count > SizeBytes)
                throw new ArgumentOutOfRangeException("offset",
                    "write of " + count + " bytes at " + offset + " runs past end of device (" + SizeBytes + ")");

            long remaining = count;
            long pos = offset;
            int done = 0;
            while (remaining > 0)
            {
                long newPos;
                if (!Native.SetFilePointerEx(_handle, pos, out newPos, Native.FILE_BEGIN))
                    throw new IOException("Seek to " + pos + " failed: " +
                        Native.DescribeError(Marshal.GetLastWin32Error()));
                uint put;
                if (!Native.WriteFile(_handle, buffer, (uint)(done + (int)remaining), out put, IntPtr.Zero))
                    throw new IOException("Write of " + count + " bytes at " + offset + " failed: " +
                        Native.DescribeError(Marshal.GetLastWin32Error()));
                if (put == 0) throw new IOException("Device accepted 0 bytes at offset " + pos);
                done += (int)put;
                pos += put;
                remaining -= put;
            }
        }

        public void Flush()
        {
            if (!CanWrite || _handle == null) return;
            if (!Native.FlushFileBuffers(_handle))
                throw new IOException("Flush failed: " + Native.DescribeError(Marshal.GetLastWin32Error()));
        }

        public void Dispose()
        {
            if (_handle != null) { try { _handle.Dispose(); } catch { } _handle = null; }
        }
    }

    internal sealed class DiskInfoLite
    {
        public int Index;
        public string DevicePath;
        public string Model;
        public string Serial;
        public string BusType;
        public long Size;
        public int BytesPerSector = 512;
        public bool IsBoot;
        public string SectorsNote = "";
    }

    internal sealed class StorageDiskRow
    {
        public int Number = -1;
        public string Model = "";
        public string Serial = "";
        public int LogicalSectorSize;
        public bool IsBoot;
        public bool IsSystem;
    }

    internal static class DiskList
    {
        public static List<DiskInfoLite> Enumerate()
        {
            var list = new List<DiskInfoLite>();
            List<DiskInfoLite> raw;
            try { raw = EnumerateRaw(); }
            catch (Exception ex)
            {
                throw new IOException("Cannot enumerate disks via WMI: " + ex.Message, ex);
            }

            // Sector sizes and boot flags from the storage stack (best effort).
            // NOTE: the Storage WMI provider rejects any explicit projection on some systems
            // ("Invalid query"), and DeviceID comes back null with SELECT *, so rows are matched
            // on the documented Number property, falling back to model/serial, then position.
            var sectorSize = new Dictionary<int, int>();
            var bootDisks = new HashSet<int>();
            var msftOrder = new List<StorageDiskRow>();
            try
            {
                var searcher = new ManagementObjectSearcher(
                    @"root\Microsoft\Windows\Storage",
                    "SELECT * FROM MSFT_Disk");
                foreach (ManagementObject o in searcher.Get())
                {
                    msftOrder.Add(new StorageDiskRow
                    {
                        Number = ReadInt(o, "Number"),
                        Model = ReadString(o, "FriendlyName").Trim(),
                        Serial = ReadString(o, "SerialNumber").Trim(),
                        LogicalSectorSize = ReadInt(o, "LogicalSectorSize"),
                        IsBoot = ReadBool(o, "IsBoot"),
                        IsSystem = ReadBool(o, "IsSystem")
                    });
                }
            }
            catch (Exception) { /* namespace unavailable - fall back to Win32_DiskDrive only */ }

            foreach (StorageDiskRow r in msftOrder)
            {
                int idx = r.Number;
                if (idx < 0 && r.Model.Length > 0)
                {
                    // fall back to matching the model/serial reported by Win32_DiskDrive
                    foreach (DiskInfoLite probe in raw)
                    {
                        if ((r.Model.Length > 0 && probe.Model.IndexOf(r.Model, StringComparison.OrdinalIgnoreCase) >= 0) ||
                            (r.Serial.Length > 0 && probe.Serial.Equals(r.Serial, StringComparison.OrdinalIgnoreCase)))
                        {
                            idx = probe.Index;
                            break;
                        }
                    }
                }
                if (idx < 0) continue;

                int lss = r.LogicalSectorSize;
                if (lss == 512 || lss == 1024 || lss == 2048 || lss == 4096) sectorSize[idx] = lss;
                if (r.IsBoot || r.IsSystem) bootDisks.Add(idx);
            }

            foreach (DiskInfoLite d in raw)
            {
                int bps;
                if (sectorSize.TryGetValue(d.Index, out bps))
                    d.BytesPerSector = bps;
                else
                    d.SectorsNote = "sector size not reported by the storage stack, assuming 512";
                d.IsBoot = bootDisks.Contains(d.Index);
                d.DevicePath = @"\\.\PhysicalDrive" + d.Index.ToString(System.Globalization.CultureInfo.InvariantCulture);
                list.Add(d);
            }

            list.Sort((a, b) => a.Index.CompareTo(b.Index));
            return list;
        }

        /// <summary>Win32_DiskDrive only - no storage-stack enrichment, no recursion.</summary>
        private static List<DiskInfoLite> EnumerateRaw()
        {
            var raw = new List<DiskInfoLite>();
            var searcher = new ManagementObjectSearcher(
                "SELECT Index, Model, SerialNumber, Size, InterfaceType, PNPDeviceID FROM Win32_DiskDrive");
            foreach (ManagementObject o in searcher.Get())
            {
                var d = new DiskInfoLite();
                if (!int.TryParse(Convert.ToString(o["Index"]), out d.Index)) continue;
                d.Model = (o["Model"] as string ?? "").Trim();
                d.Serial = (o["SerialNumber"] as string ?? "").Trim();
                d.BusType = (o["InterfaceType"] as string ?? "").Trim();
                string pnp = o["PNPDeviceID"] as string ?? "";
                if (pnp.IndexOf("USB", StringComparison.OrdinalIgnoreCase) >= 0) d.BusType = "USB";
                else if (pnp.IndexOf("NVME", StringComparison.OrdinalIgnoreCase) >= 0) d.BusType = "NVMe";
                else if (pnp.IndexOf("SCSI", StringComparison.OrdinalIgnoreCase) >= 0 ||
                         pnp.IndexOf("ATA", StringComparison.OrdinalIgnoreCase) >= 0) d.BusType = "SATA/ATA";
                try { d.Size = Convert.ToInt64(o["Size"]); } catch { d.Size = 0; }
                raw.Add(d);
            }
            raw.Sort((a, b) => a.Index.CompareTo(b.Index));
            return raw;
        }

        private static string ReadString(ManagementObject o, string prop)
        {
            try { return o[prop] as string ?? ""; } catch { return ""; }
        }

        private static int ReadInt(ManagementObject o, string prop)
        {
            try { return Convert.ToInt32(o[prop]); } catch { return 0; }
        }

        private static bool ReadBool(ManagementObject o, string prop)
        {
            try { return Convert.ToBoolean(o[prop]); } catch { return false; }
        }
    }
}
