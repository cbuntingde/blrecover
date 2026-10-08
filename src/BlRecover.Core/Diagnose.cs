using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace BlRecover
{
    /// <summary>
    /// Works out exactly why raw disk access is refused, instead of guessing. Read-only: it only
    /// opens handles and throws them away, and never writes a single byte.
    /// </summary>
    internal static class Diagnose
    {
        public static int Run()
        {
            Out.Title("blrecover diagnose");
            Out.Dim("  This is read-only. It opens handles, reads the token, and closes everything.");

            // ---------- 1. token ----------
            Out.Title("1. Process token");
            Out.Indent("elevated (Administrators)   : " + (Privileges.Elevated ? "yes" : "NO"));
            // Report each privilege from its own recorded outcome. Inferring them all from a single
            // LastProblem flag used to print "enabled OK" for SeBackup/SeRestore even when they were
            // never granted, which is exactly the false reassurance a diagnostic must not give.
            foreach (string p in Privileges.Required)
            {
                string s;
                bool known = Privileges.PrivilegeStatus.TryGetValue(p, out s);
                if (!known) s = "not checked";
                string line = p.PadRight(29) + ": " + s;
                if (known && s == "enabled") Out.Indent(line);
                else Out.Warn(line);
            }
            if (!string.IsNullOrEmpty(Privileges.LastProblem))
                Out.Indent("  problem: " + Privileges.LastProblem);
            Out.Dim("  " + Privileges.StatusHelp());

            // ---------- 2. physical drives ----------
            Out.Title("2. Physical drive access");
            List<DiskInfoLite> disks;
            try { disks = DiskList.Enumerate(); }
            catch (Exception ex) { Out.Bad("  could not enumerate disks: " + ex.Message); return 1; }

            foreach (DiskInfoLite info in disks)
            {
                string path = @"\\.\PhysicalDrive" + info.Index.ToString(System.Globalization.CultureInfo.InvariantCulture);
                Out.H("  " + path + "  " + info.Model + (info.IsBoot ? "   [BOOT DISK]" : ""));

                Test(path, "GENERIC_READ", Native.GENERIC_READ, Native.FILE_SHARE_READ | Native.FILE_SHARE_WRITE,
                     Native.FILE_ATTRIBUTE_NORMAL);
                Test(path, "GENERIC_READ|GENERIC_WRITE", Native.GENERIC_READ | Native.GENERIC_WRITE,
                     Native.FILE_SHARE_READ | Native.FILE_SHARE_WRITE, Native.FILE_ATTRIBUTE_NORMAL);
                Test(path, "GENERIC_READ, share=all", Native.GENERIC_READ, Native.FILE_SHARE_ALL,
                     Native.FILE_ATTRIBUTE_NORMAL);
                Test(path, "GENERIC_READ, NO_BUFFERING", Native.GENERIC_READ,
                     Native.FILE_SHARE_READ | Native.FILE_SHARE_WRITE,
                     Native.FILE_ATTRIBUTE_NORMAL | Native.FILE_FLAG_NO_BUFFERING);
                Test(path, "GENERIC_READ, BACKUP_SEMANTICS", Native.GENERIC_READ,
                     Native.FILE_SHARE_READ | Native.FILE_SHARE_WRITE,
                     Native.FILE_ATTRIBUTE_NORMAL | Native.FILE_FLAG_BACKUP_SEMANTICS);
                Test(path, "FILE_READ_DATA only", 0x00000001,
                     Native.FILE_SHARE_READ | Native.FILE_SHARE_WRITE, Native.FILE_ATTRIBUTE_NORMAL);
            }

            // ---------- 3. volume handles ----------
            Out.Title("3. Volume handles (a fallback route some blockers do not cover)");
            foreach (char c in "CDEFGHIJKLMNOPQRSTUVWXYZ")
            {
                string vp = @"\\.\" + c + ":";
                int err;
                SafeFileHandle h = Native.TryOpen(vp, Native.GENERIC_READ, Native.FILE_SHARE_READ | Native.FILE_SHARE_WRITE,
                                                  Native.FILE_ATTRIBUTE_NORMAL, out err);
                if (!h.IsInvalid)
                {
                    Out.Ok("  " + vp + "  open OK");
                    h.Dispose();
                }
                else if (err != 2 && err != 3)   // skip FILE_NOT_FOUND / PATH_NOT_FOUND
                {
                    Out.Indent("  " + vp + "  Win32 " + err + " - " + Native.DescribeError(err));
                }
            }
            for (int i = 1; i <= 12; i++)
            {
                string vp = @"\\.\HarddiskVolume" + i.ToString(System.Globalization.CultureInfo.InvariantCulture);
                int err;
                SafeFileHandle h = Native.TryOpen(vp, Native.GENERIC_READ, Native.FILE_SHARE_READ | Native.FILE_SHARE_WRITE,
                                                  Native.FILE_ATTRIBUTE_NORMAL, out err);
                if (!h.IsInvalid)
                {
                    Out.Ok("  " + vp + "  open OK");
                    h.Dispose();
                }
                else if (err != 2 && err != 3)
                {
                    Out.Indent("  " + vp + "  Win32 " + err + " - " + Native.DescribeError(err));
                }
            }

            // ---------- 4. verdict ----------
            Out.Title("4. Verdict");
            Out.Info(Verdict());
            Out.Dim("  Copy this whole output into the conversation if anything is still blocked.");
            return 0;
        }

        private static void Test(string path, string label, uint access, uint share, uint flags)
        {
            int err;
            SafeFileHandle h = Native.TryOpen(path, access, share, flags, out err);
            if (!h.IsInvalid)
            {
                string size = "?";
                var buf = new byte[32];
                uint ret;
                if (Native.DeviceIoControl(h, Native.IOCTL_DISK_GET_LENGTH_INFO, null, 0,
                                           buf, (uint)buf.Length, out ret, IntPtr.Zero))
                    size = Fmt.HumanSize(BitConverter.ToInt64(buf, 0));
                else
                    size = "size FAILED (Win32 " + Marshal.GetLastWin32Error() + ")";
                Out.Ok("      OK      " + label.PadRight(30) + size);
                h.Dispose();
            }
            else
            {
                Out.Bad("      FAILED  " + label.PadRight(30) + "Win32 " + err + " - " + Native.DescribeError(err));
            }
        }

        private static string Verdict()
        {
            int err;
            SafeFileHandle h = Native.TryOpen(@"\\.\PhysicalDrive0", Native.GENERIC_READ,
                Native.FILE_SHARE_READ | Native.FILE_SHARE_WRITE, Native.FILE_ATTRIBUTE_NORMAL, out err);
            if (!h.IsInvalid)
            {
                h.Dispose();
                return "Raw physical-disk reads work. blrecover can read Disk 0 - run \"blrecover analyze --disk 0\".";
            }
            if (err == 5)
            {
                var sb = new StringBuilder();
                sb.AppendLine("Raw physical-disk reads are blocked with Win32 5 (Access denied) even though");
                sb.Append("SeManageVolumePrivilege reports as enabled. That points at a filter driver ");
                sb.Append("(anti-virus, anti-ransomware, a disk-encryption product, or a hardening agent) rather");
                sb.AppendLine("than at this tool.");
                sb.AppendLine();
                sb.AppendLine("Things that cause exactly this:");
                sb.AppendLine("  - a security product that blocks \\Device\\HarddiskVolume* raw opens");
                sb.AppendLine("  - a corporate/EDR policy removing SeManageVolumePrivilege after elevation");
                sb.AppendLine("  - Storage Spaces / a third-party disk manager owning the device");
                sb.AppendLine();
                sb.Append("Practical next steps: try the same command from a Windows Recovery Environment or a ");
                sb.Append("bootable Linux/PE USB, which bypasses the endpoint protection entirely, or ask IT what ");
                sb.AppendLine("policy is in force.");
                return sb.ToString();
            }
            return "Unexpected Win32 " + err + " - " + Native.DescribeError(err);
        }
    }
}
