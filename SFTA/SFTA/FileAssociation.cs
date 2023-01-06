using System;
using System.IO;
using System.Text;
using System.Security.Principal;
using System.Security.Cryptography;
using Microsoft.Win32;

namespace Applets.Common
{
    class FileAssociation
    {
        private const string WzFileExtUserChoice = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\{0}\\UserChoice";

        private struct HashMap
        {
            public int cache;
            public int counter;
            public int index;
            public int md5Bytes1;
            public int md5Bytes2;
            public int outHash1;
            public int outHash2;
            public int reckon0;
            public int[] reckon1;
            public int[] reckon2;
            public int reckon3;
            public int[] reckon4;
            public int[] reckon5;
            public int[] reckon6;
            public int[] reckon7;
            public int reckon8;
            public int[] reckon9;

            public void Init()
            {
                cache = 0;
                outHash1 = 0;
                reckon1 = new int[2];
                reckon2 = new int[2];
                reckon4 = new int[2];
                reckon5 = new int[2];
                reckon6 = new int[2];
                reckon7 = new int[3];
                reckon9 = new int[3];
            }
        };

        static void Main(string[] args)
        {
            SetFileTypeAssociation(".pdf", "WinZip.PdfExpress");
        }

        public static bool SetFileTypeAssociation(string extension, string progId)
        {
            if (!IsWindows8OrNewer())
            {
                return false;
            }

            string progIdHash = CreateProgIdHash(extension, progId);
            if (progIdHash != null && progIdHash.Length > 0)
            {
                DeleteUserChoiceRegistryKey(extension);
                CreateUserChoiceRegistryKey(extension, progId, progIdHash);
                return true;
            }

            return false;
        }

        public static bool IsWindows8OrNewer()
        {
            var os = Environment.OSVersion;
            return (os.Platform == PlatformID.Win32NT) && (os.Version.Major > 6 || (os.Version.Major == 6 && os.Version.Minor >= 2));
        }

        private static string CreateProgIdHash(string extension, string progId)
        {
            string sid = WindowsIdentity.GetCurrent().User.ToString();
            string regDate = GenerateDate();
            string experience = GetExperienceString();
            string data = (extension + sid + progId + regDate + experience).ToLower();
            byte[] dataBytes = StringToBytes(data);

            byte[] md5Bytes;
            using (MD5 md5 = MD5.Create())
            {
                md5Bytes = md5.ComputeHash(dataBytes);
            }

            byte[] outBytes = new byte[8];
            GenerateHash(dataBytes, md5Bytes, outBytes);
            return Convert.ToBase64String(outBytes);
        }

        private static string GenerateDate()
        {
            DateTime dt = DateTime.UtcNow;
            dt = new DateTime(dt.Ticks - (dt.Ticks % TimeSpan.TicksPerMinute), dt.Kind);
            long ft = dt.ToFileTime();
            return string.Format("{0:x16}", ft);
        }

        private static string GetExperienceString()
        {
            string shell32Path = Environment.GetFolderPath(Environment.SpecialFolder.System) + @"\Shell32.dll";
            if (File.Exists(shell32Path))
            {
                using (FileStream fs = File.Open(shell32Path, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    int memSize = 1024 * 1024 * 8; // Read 8 MB This should be enough to search the Experience String
                    byte[] srcBytes = new byte[memSize];
                    int readSize = fs.Read(srcBytes, 0, srcBytes.Length);
                    if (readSize > 0)
                    {
                        string searchStr = "User Choice set via Windows User Experience";
                        int start = FindStringInBytes(searchStr, srcBytes, readSize);
                        if (start > -1)
                        {
                            int end = -1;
                            for (int i = start; i < readSize; i+=2)
                            {
                                if (srcBytes[i] == 0 && srcBytes[i + 1] == 0)
                                {
                                    end = i;
                                    break;
                                }
                            }
                            if (end > start)
                            {
                                return Encoding.Unicode.GetString(srcBytes, start, end - start);
                            }
                        }
                    }
                }
            }
            return "";
        }

        private static int FindStringInBytes(string searchStr, byte[] srcBytes, int srcSize)
        {
            byte[] searchBytes = Encoding.Unicode.GetBytes(searchStr);
            for (int i = 0; i < srcSize - searchBytes.Length; i++)
            {
                if (srcBytes[i] == searchBytes[0])
                {
                    bool flag = true;
                    for (int j = 1; j < searchBytes.Length; j++)
                    {
                        if (srcBytes[i + j] != searchBytes[j])
                        {
                            flag = false;
                            break;
                        }
                    }
                    if (flag)
                    {
                        return i;
                    }
                }
            }
            return -1;
        }

        private static byte[] StringToBytes(string str)
        {
            int size = str.Length * 2 + 2;
            byte[] bytes = new byte[size];
            byte[] tmpBytes = Encoding.Unicode.GetBytes(str);
            Array.Copy(tmpBytes, bytes, tmpBytes.Length);
            bytes[size - 1] = 0;
            bytes[size - 2] = 0;
            return bytes;
        }

        private static bool GenerateHash(byte[] data, byte[] md5, byte[] outBytes)
        {
            byte[] hash = new byte[16];
            int len = data.Length;
            int hLen = (len & 4) < 1 ? 1 : 0;
            hLen += (len >> 2) - 1;
            if (hLen < 1 || Convert.ToBoolean(hLen & 1))
            {
                return false;
            }
            if (!Hash1(data, hLen, md5, hash, 0) || !Hash2(data, hLen, md5, hash, 8))
            {
                return false;
            }

            int n1 = BitConverter.ToInt32(hash, 8) ^ BitConverter.ToInt32(hash, 0);
            byte[] tmpBytes = BitConverter.GetBytes(n1);
            Array.Copy(tmpBytes, outBytes, tmpBytes.Length);
            int n2 = BitConverter.ToInt32(hash, 12) ^ BitConverter.ToInt32(hash, 4);
            tmpBytes = BitConverter.GetBytes(n2);
            Array.Copy(tmpBytes, 0, outBytes, 4, tmpBytes.Length);
            return true;
        }

        private static int Shr32(int value, int count)
        {
            return (int)((uint)value >> count);
        }

        private static bool Hash1(byte[] data, int hLen, byte[] md5, byte[] hash, int hashIndex)
        {
            HashMap hm = new HashMap();
            hm.Init();
            hm.md5Bytes1 = (BitConverter.ToInt32(md5, 0) | 1) + 0x69FB0000;
            hm.md5Bytes2 = (BitConverter.ToInt32(md5, 4) | 1) + 0x13DB0000;
            hm.index = (hLen - 2) >> 1;
            hm.counter = hm.index + 1;
            int dataIndex = 0;
            while (hm.counter > 0)
            {
                hm.reckon0 = BitConverter.ToInt32(data, dataIndex) + hm.outHash1;
                hm.reckon1[0] = BitConverter.ToInt32(data, dataIndex + 4);
                dataIndex += 8;
                hm.reckon2[0] = hm.reckon0 * hm.md5Bytes1 - 0x10FA9605 * Shr32(hm.reckon0, 16);
                hm.reckon2[1] = 0x79F8A395 * hm.reckon2[0] + 0x689B6B9F * Shr32(hm.reckon2[0], 16);
                hm.reckon3 = (int)(0xEA970001 * hm.reckon2[1] - 0x3C101569 * Shr32(hm.reckon2[1], 16));
                hm.reckon4[0] = hm.reckon3 + hm.reckon1[0];
                hm.reckon5[0] = hm.cache + hm.reckon3;
                hm.reckon6[0] = hm.reckon4[0] * hm.md5Bytes2 - 0x3CE8EC25 * Shr32(hm.reckon4[0], 16);
                hm.reckon6[1] = 0x59C3AF2D * hm.reckon6[0] - 0x2232E0F1 * Shr32(hm.reckon6[0], 16);
                hm.outHash1 = 0x1EC90001 * hm.reckon6[1] + 0x35BD1EC9 * Shr32(hm.reckon6[1], 16);
                hm.outHash2 = hm.reckon5[0] + hm.outHash1;
                hm.cache = hm.outHash2;
                hm.counter--;
            }
            if (hLen - 2 - hm.index * 2 == 1)
            {

                hm.reckon7[0] = BitConverter.ToInt32(data, 8 * hm.index + 8) + hm.outHash1;
                hm.reckon7[1] = hm.reckon7[0] * hm.md5Bytes1 - 0x10FA9605 * Shr32(hm.reckon7[0], 16);
                hm.reckon7[2] = 0x79F8A395 * hm.reckon7[1] + 0x689B6B9F * Shr32(hm.reckon7[1], 16);
                hm.reckon8 = (int)(0xEA970001 * hm.reckon7[2] - 0x3C101569 * Shr32(hm.reckon7[2], 16));
                hm.reckon9[0] = hm.reckon8 * hm.md5Bytes2 - 0x3CE8EC25 * Shr32(hm.reckon8, 16);
                hm.reckon9[1] = 0x59C3AF2D * hm.reckon9[0] - 0x2232E0F1 * Shr32(hm.reckon9[0], 16);
                hm.outHash1 = 0x1EC90001 * hm.reckon9[1] + 0x35BD1EC9 * Shr32(hm.reckon9[1], 16);
                hm.outHash2 = hm.outHash1 + hm.cache + hm.reckon8;
            }
            byte[] tmpBytes = BitConverter.GetBytes(hm.outHash1);
            Array.Copy(tmpBytes, 0, hash, hashIndex, tmpBytes.Length);
            tmpBytes = BitConverter.GetBytes(hm.outHash2);
            Array.Copy(tmpBytes, 0, hash, hashIndex + 4, tmpBytes.Length);
            return true;
        }

        private static bool Hash2(byte[] data, int hLen, byte[] md5, byte[] hash, int hashIndex)
        {
            HashMap hm = new HashMap();
            hm.Init();
            hm.md5Bytes1 = BitConverter.ToInt32(md5, 0) | 1;
            hm.md5Bytes2 = BitConverter.ToInt32(md5, 4) | 1;
            hm.index = (hLen - 2) >> 1;
            hm.counter = hm.index + 1;
            int dataIndex = 0;
            while (hm.counter > 0)
            {
                hm.reckon0 = BitConverter.ToInt32(data, dataIndex) + hm.outHash1;
                dataIndex += 8;
                hm.reckon1[0] = hm.reckon0 * hm.md5Bytes1;
                hm.reckon1[1] = (int)(0xB1110000 * hm.reckon1[0] - 0x30674EEF * Shr32(hm.reckon1[0], 16));
                hm.reckon2[0] = 0x5B9F0000 * hm.reckon1[1] - 0x78F7A461 * Shr32(hm.reckon1[1], 16);
                hm.reckon2[1] = 0x12CEB96D * Shr32(hm.reckon2[0], 16) - 0x46930000 * hm.reckon2[0];
                hm.reckon3 = 0x1D830000 * hm.reckon2[1] + 0x257E1D83 * Shr32(hm.reckon2[1], 16);
                hm.reckon4[0] = hm.md5Bytes2 * (hm.reckon3 + BitConverter.ToInt32(data, dataIndex - 4));
                hm.reckon4[1] = 0x16F50000 * hm.reckon4[0] - 0x5D8BE90B * Shr32(hm.reckon4[0], 16);
                hm.reckon5[0] = (int)(0x96FF0000 * hm.reckon4[1] - 0x2C7C6901 * Shr32(hm.reckon4[1], 16));
                hm.reckon5[1] = 0x2B890000 * hm.reckon5[0] + 0x7C932B89 * Shr32(hm.reckon5[0], 16);
                hm.outHash1 = (int)(0x9F690000 * hm.reckon5[1] - 0x405B6097 * Shr32(hm.reckon5[1], 16));
                hm.outHash2 = hm.outHash1 + hm.cache + hm.reckon3;
                hm.cache = hm.outHash2;
                hm.counter--;
            }
            if (hLen - 2 - hm.index * 2 == 1)
            {
                hm.reckon6[0] = (BitConverter.ToInt32(data, 8 * hm.index + 8) + hm.outHash1) * hm.md5Bytes1;
                hm.reckon6[1] = (int)(0xB1110000 * hm.reckon6[0] - 0x30674EEF * Shr32(hm.reckon6[0], 16));
                hm.reckon7[0] = (int)(0x5B9F0000 * hm.reckon6[1] - 0x78F7A461 * Shr32(hm.reckon6[1], 16));
                hm.reckon7[1] = 0x12CEB96D * Shr32(hm.reckon7[0], 16) - 0x46930000 * hm.reckon7[0];
                hm.reckon8 = 0x1D830000 * hm.reckon7[1] + 0x257E1D83 * Shr32(hm.reckon7[1], 16);
                hm.reckon9[0] = 0x16F50000 * hm.reckon8 * hm.md5Bytes2 - 0x5D8BE90B * Shr32(hm.reckon8 * hm.md5Bytes2, 16);
                hm.reckon9[1] = (int)(0x96FF0000 * hm.reckon9[0] - 0x2C7C6901 * Shr32(hm.reckon9[0], 16));
                hm.reckon9[2] = 0x2B890000 * hm.reckon9[1] + 0x7C932B89 * Shr32(hm.reckon9[1], 16);
                hm.outHash1 = (int)(0x9F690000 * hm.reckon9[2] - 0x405B6097 * Shr32(hm.reckon9[2], 16));
                hm.outHash2 = hm.outHash1 + hm.cache + hm.reckon8;
            }
            byte[] tmpBytes = BitConverter.GetBytes(hm.outHash1);
            Array.Copy(tmpBytes, 0, hash, hashIndex, tmpBytes.Length);
            tmpBytes = BitConverter.GetBytes(hm.outHash2);
            Array.Copy(tmpBytes, 0, hash, hashIndex + 4, tmpBytes.Length);
            return true;
        }

        private static void DeleteUserChoiceRegistryKey(string extension)
        {
            var userChoiceSubKey = string.Format(WzFileExtUserChoice, extension);
            using (var regKey = Registry.CurrentUser.OpenSubKey(userChoiceSubKey, false))
            {
                if (regKey != null)
                {
                    Registry.CurrentUser.DeleteSubKey(userChoiceSubKey, false);
                }
            }
        }

        private static void CreateUserChoiceRegistryKey(string extension, string progId, string hash)
        {
            var userChoiceSubKey = string.Format(WzFileExtUserChoice, extension);
            using (var regKey = Registry.CurrentUser.CreateSubKey(userChoiceSubKey))
            {
                if (regKey != null)
                {
                    regKey.SetValue("Progid", progId);
                    regKey.SetValue("Hash", hash);
                }
            }
        }
    }

}
