using AESylum.MFortress;
using System.Security.Cryptography;
using System.Text;

namespace AESylum
{
    public class Patch(uint rva, byte[] bytes)
    {
        public uint Rva = rva;
        public byte[] Bytes = bytes;
    }

    public class BuildInfo
    {
        public uint TimeDateStamp;
        public uint OepRva;
        public uint ImportRVA;
        public uint ImportSize;
        public uint IatRVA;
        public uint IatSize;
        public uint DelayImportRVA;
        public uint DelayImportSize;
        public required Patch[] Patches;
    }

    public static class Program
    {
        private static readonly byte[] AesKey =
        [
            0xCF, 0x88, 0xA9, 0x25, 0xF7, 0x25, 0x54, 0xB4,
            0xB8, 0xA5, 0xB8, 0xA0, 0x89, 0xC7, 0x90, 0x66
        ];

        private static readonly byte[] AesIv = new byte[16];

        // Signature at the start of .text in an already-decrypted build.
        private static readonly byte[] DecryptedTextSignature =
        [
            0x55, 0x8B, 0xEC, 0xD9, 0x45, 0x08, 0xD9, 0xE1,
            0x5D, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC
        ];

        private static readonly uint UnsupportedBuildTimeDateStamp = 0x4DAC7482;

        private static readonly BuildInfo[] Builds =
        [
            new()
            {
                TimeDateStamp = 0x4DC8887C,
                OepRva = 0x00C21EFF,
                ImportRVA = 0x0101794C,
                ImportSize = 0x00000230,
                IatRVA = 0x00DAA000,
                IatSize = 0x00000920,
                DelayImportRVA = 0x010177A4,
                DelayImportSize = 0x00000080,
                Patches = Patches_Steam.Entries,
            },
            new()
            {
                TimeDateStamp = 0x4DC89913,
                OepRva = 0x00C2255F,
                ImportRVA = 0x010179A0,
                ImportSize = 0x00000230,
                IatRVA = 0x00DAA000,
                IatSize = 0x00000920,
                DelayImportRVA = 0x010177F8,
                DelayImportSize = 0x00000080,
                Patches = Patches_EA.Entries,
            },
        ];

        public static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Usage: AESylum <input-file>");
                return;
            }

            string input = args[0];
            string backup = input + ".bak";
            string output = input;

            if (!File.Exists(input))
            {
                Console.WriteLine($"Not found: {input}");
                return;
            }

            if (File.Exists(backup))
            {
                Console.WriteLine($"Backup already exists: {backup}");
                Console.ReadLine();
                return;
            }

            byte[] raw = File.ReadAllBytes(input);

            if (!IsValidPE(raw))
            {
                Console.WriteLine($"{input} doesn't look like a valid PE file.");
                Console.ReadLine();
                return;
            }

            uint timeDateStamp = ReadTimeDateStamp(raw);

            if (timeDateStamp == UnsupportedBuildTimeDateStamp)
            {
                Console.WriteLine($"This build (0x{timeDateStamp:X8}) isn't supported.");
                Console.ReadLine();
                return;
            }

            if (FindBuild(timeDateStamp) == null)
            {
                Console.WriteLine($"Unknown build 0x{timeDateStamp:X8}, nothing to do.");
                Console.ReadLine();
                return;
            }

            File.Move(input, backup);

            if (SectionOffset(raw, ".bind") >= 0)
            {
                Console.WriteLine("Removing .bind section...");
                RemoveBind(ref raw);
            }
            else
            {
                Console.WriteLine("No .bind section found, skipping.");
            }

            if (IsTextSectionDecrypted(raw))
            {
                Console.WriteLine("Sections already decrypted, skipping.");
            }
            else
            {
                Console.WriteLine("Decrypting sections...");
                DecryptSections(raw);
            }

            Console.WriteLine("Rebuilding the PE header...");
            RestoreHeader(ref raw);

            Console.WriteLine("Patching out the DRM checks...");
            ApplyPatches(raw);

            File.WriteAllBytes(output, raw);
            Console.WriteLine();
            Console.WriteLine($"Wrote output to {output}");
            Console.WriteLine($"Original file backed up as {backup}");
            Console.ReadLine();
        }


        #region Phase 1 – Strip the SteamStub .bind wrapper

        private static void RemoveBind(ref byte[] raw)
        {
            StripSection(ref raw, ".bind");
            UpdateSizeOfImage(raw);

            int ntHeadersOffset = ToInt32(raw, 0x3C);
            Write32(raw, ntHeadersOffset + 4 + 20 + 64, 0);
        }

        #endregion

        #region Phase 2 – AES section decrypt

        private static bool IsTextSectionDecrypted(byte[] raw)
        {
            int sectionHeaderOffset = SectionOffset(raw, ".text");
            if (sectionHeaderOffset < 0) return false;

            int pointerToRawData = ToInt32(raw, sectionHeaderOffset + 20);
            if (pointerToRawData < 0) return false;
            if (pointerToRawData + DecryptedTextSignature.Length > raw.Length) return false;

            for (int i = 0; i < DecryptedTextSignature.Length; i++)
            {
                if (raw[pointerToRawData + i] != DecryptedTextSignature[i]) return false;
            }

            return true;
        }

        private static void DecryptSections(byte[] raw)
        {
            string[] targets = { ".text", ".textidx", "CONST" };

            int ntHeadersOffset = ToInt32(raw, 0x3C);
            int sectionCount = ToInt16(raw, ntHeadersOffset + 4 + 2);
            int optionalHeaderSize = ToInt16(raw, ntHeadersOffset + 4 + 16);
            int sectionTableOffset = ntHeadersOffset + 4 + 20 + optionalHeaderSize;

            for (int i = 0; i < sectionCount; i++)
            {
                int sectionHeaderOffset = sectionTableOffset + i * 40;
                string name = Encoding.UTF8.GetString(raw, sectionHeaderOffset, 8).TrimEnd('\0');
                if (!targets.Contains(name)) continue;

                int sectionSize = ToInt32(raw, sectionHeaderOffset + 16);
                int pointerToRawData = ToInt32(raw, sectionHeaderOffset + 20);

                // Skip first byte, align down to AES block size
                int start = pointerToRawData + 1;
                int length = ((sectionSize - 1) / 16) * 16;
                if (length <= 0) continue;

                byte[] chunk = new byte[length];
                Buffer.BlockCopy(raw, start, chunk, 0, length);
                byte[] decrypted = AESDecrypt(chunk, AesKey, AesIv);
                Buffer.BlockCopy(decrypted, 0, raw, start, length);

                Console.WriteLine($"    {name}: decrypted 0x{length:X} bytes at 0x{start:X}");
            }
        }

        public static byte[] AESDecrypt(byte[] data, byte[] key, byte[] iv)
        {
            byte[] ret = new byte[data.Length];

            using Aes aesAlg = Aes.Create();
            aesAlg.Mode = CipherMode.CBC;
            aesAlg.Padding = PaddingMode.None;

            ICryptoTransform decryptor = aesAlg.CreateDecryptor(key, iv);
            decryptor.TransformBlock(data, 0, data.Length, ret, 0);
            return ret;
        }

        #endregion

        #region Phase 3 – Strip DRM sections and restore header fields

        private static void RestoreHeader(ref byte[] raw)
        {
            int ntHeadersOffset = ToInt32(raw, 0x3C);
            uint timeDateStamp = (uint)ToInt32(raw, ntHeadersOffset + 4 + 4);

            BuildInfo? build = null;
            foreach (BuildInfo candidate in Builds)
            {
                if (candidate.TimeDateStamp == timeDateStamp)
                {
                    build = candidate;
                    break;
                }
            }

            if (build == null)
            {
                Console.WriteLine($"    Unknown build 0x{timeDateStamp:X8}, skipping.");
                return;
            }

            foreach (string name in new[] { ".extra", "" })
            {
                while (StripSection(ref raw, name))
                {
                    Console.WriteLine($"    Stripped section: {(name.Length == 0 ? "(unnamed)" : name)}");
                }
            }

            UpdateSizeOfImage(raw);

            ntHeadersOffset = ToInt32(raw, 0x3C);
            int optionalHeaderOffset = ntHeadersOffset + 4 + 20;

            Write32(raw, optionalHeaderOffset + 4, SumAlignedVirtualSize(raw, [".text", ".textidx", "CONST"]));       // SizeOfCode          
            Write32(raw, optionalHeaderOffset + 8, SumAlignedVirtualSize(raw, [".rdata", ".data", ".shr", ".rsrc"])); // SizeOfInitializedData
            Write32(raw, optionalHeaderOffset + 16, (int)build.OepRva);                 // AddressOfEntryPoint
            Write32(raw, optionalHeaderOffset + 20, SectionRva(raw, ".text"));          // BaseOfCode
            Write32(raw, optionalHeaderOffset + 24, SectionRva(raw, ".rdata"));         // BaseOfData
            Write32(raw, optionalHeaderOffset + 64, 0);                                 // CheckSum

            int dataDirectoryOffset = optionalHeaderOffset + 96;
            Write32(raw, dataDirectoryOffset + 1 * 8 + 0, (int)build.ImportRVA);        // Import RVA
            Write32(raw, dataDirectoryOffset + 1 * 8 + 4, (int)build.ImportSize);       // Import size
            Write32(raw, dataDirectoryOffset + 4 * 8 + 0, 0);                           // Security RVA (cleared)
            Write32(raw, dataDirectoryOffset + 4 * 8 + 4, 0);                           // Security size
            Write32(raw, dataDirectoryOffset + 12 * 8 + 0, (int)build.IatRVA);          // IAT RVA
            Write32(raw, dataDirectoryOffset + 12 * 8 + 4, (int)build.IatSize);         // IAT size
            Write32(raw, dataDirectoryOffset + 13 * 8 + 0, (int)build.DelayImportRVA);  // Delay import RVA
            Write32(raw, dataDirectoryOffset + 13 * 8 + 4, (int)build.DelayImportSize); // Delay import size
        }

        #endregion

        #region Phase 4 – Apply per-build patches

        private static void ApplyPatches(byte[] raw)
        {
            int ntHeadersOffset = ToInt32(raw, 0x3C);
            uint timeDateStamp = (uint)ToInt32(raw, ntHeadersOffset + 4 + 4);

            BuildInfo? build = null;
            foreach (BuildInfo candidate in Builds)
            {
                if (candidate.TimeDateStamp == timeDateStamp)
                {
                    build = candidate;
                    break;
                }
            }

            if (build?.Patches == null || build.Patches.Length == 0)
            {
                Console.WriteLine($"    No patches defined for build 0x{timeDateStamp:X8}.");
                return;
            }

            int applied = 0;
            foreach (Patch patch in build.Patches)
            {
                int fileOffset = RvaToFileOffset(raw, patch.Rva);
                if (fileOffset < 0)
                {
                    continue;
                }

                Buffer.BlockCopy(patch.Bytes, 0, raw, fileOffset, patch.Bytes.Length);
                applied++;
            }

            Console.WriteLine($"    Applied {applied} patches.");
        }

        private static int RvaToFileOffset(byte[] raw, uint rva)
        {
            int ntHeadersOffset = ToInt32(raw, 0x3C);
            int sectionCount = ToInt16(raw, ntHeadersOffset + 4 + 2);
            int optionalHeaderSize = ToInt16(raw, ntHeadersOffset + 4 + 16);
            int sectionTableOffset = ntHeadersOffset + 4 + 20 + optionalHeaderSize;

            for (int i = 0; i < sectionCount; i++)
            {
                int sectionHeaderOffset = sectionTableOffset + i * 40;
                uint virtualAddress = (uint)ToInt32(raw, sectionHeaderOffset + 12);
                uint virtualSize = (uint)ToInt32(raw, sectionHeaderOffset + 8);
                uint pointerToRawData = (uint)ToInt32(raw, sectionHeaderOffset + 20);
                if (rva >= virtualAddress && rva < virtualAddress + virtualSize)
                {
                    return (int)(pointerToRawData + (rva - virtualAddress));
                }
            }

            return -1;
        }

        #endregion

        #region Section table helpers

        private static bool StripSection(ref byte[] raw, string name)
        {
            int sectionHeaderOffset = SectionOffset(raw, name);
            if (sectionHeaderOffset < 0) return false;

            int ntHeadersOffset = ToInt32(raw, 0x3C);
            int sectionCount = ToInt16(raw, ntHeadersOffset + 4 + 2);
            int optionalHeaderSize = ToInt16(raw, ntHeadersOffset + 4 + 16);
            int sectionTableOffset = ntHeadersOffset + 4 + 20 + optionalHeaderSize;
            int sectionIndex = (sectionHeaderOffset - sectionTableOffset) / 40;

            uint pointerToRawData = (uint)ToInt32(raw, sectionHeaderOffset + 20);

            bool isLastInFile = true;
            for (int i = 0; i < sectionCount; i++)
            {
                if (i == sectionIndex) continue;

                uint otherPointerToRawData = (uint)ToInt32(raw, sectionTableOffset + i * 40 + 20);
                if (otherPointerToRawData > pointerToRawData)
                {
                    isLastInFile = false;
                    break;
                }
            }

            if (sectionIndex < sectionCount - 1)
            {
                int length = (sectionCount - 1 - sectionIndex) * 40;
                Buffer.BlockCopy(raw, sectionHeaderOffset + 40, raw, sectionHeaderOffset, length);
            }

            Array.Clear(raw, sectionTableOffset + (sectionCount - 1) * 40, 40);

            int numberOfSectionsOffset = ntHeadersOffset + 4 + 2;
            short newSectionCount = (short)(ToInt16(raw, numberOfSectionsOffset) - 1);
            raw[numberOfSectionsOffset] = (byte)(newSectionCount & 0xFF);
            raw[numberOfSectionsOffset + 1] = (byte)(newSectionCount >> 8);

            if (isLastInFile && pointerToRawData < (uint)raw.Length)
            {
                Array.Resize(ref raw, (int)pointerToRawData);
            }

            return true;
        }

        private static void UpdateSizeOfImage(byte[] raw)
        {
            int ntHeadersOffset = ToInt32(raw, 0x3C);
            int optionalHeaderOffset = ntHeadersOffset + 4 + 20;
            uint sectionAlignment = (uint)ToInt32(raw, optionalHeaderOffset + 32);
            int sectionCount = ToInt16(raw, ntHeadersOffset + 4 + 2);
            int optionalHeaderSize = ToInt16(raw, ntHeadersOffset + 4 + 16);
            int sectionTableOffset = ntHeadersOffset + 4 + 20 + optionalHeaderSize;

            uint maxEnd = 0;
            for (int i = 0; i < sectionCount; i++)
            {
                int sectionHeaderOffset = sectionTableOffset + i * 40;
                uint virtualAddress = (uint)ToInt32(raw, sectionHeaderOffset + 12);
                uint virtualSize = (uint)ToInt32(raw, sectionHeaderOffset + 8);
                uint end = (virtualAddress + virtualSize + sectionAlignment - 1) & ~(sectionAlignment - 1);
                if (end > maxEnd) maxEnd = end;
            }

            Write32(raw, optionalHeaderOffset + 56, (int)maxEnd);
        }

        #endregion

        #region PE / byte helpers

        public static bool IsValidPE(byte[] raw)
        {
            if (raw[0] != 'M' || raw[1] != 'Z') return false;

            int ntHeadersOffset = ToInt32(raw, 0x3C);
            if (ntHeadersOffset < 0 || ntHeadersOffset + 4 + 20 + 2 > raw.Length) return false;
            if (raw[ntHeadersOffset] != 'P' || raw[ntHeadersOffset + 1] != 'E') return false;
            if (raw[ntHeadersOffset + 2] != 0 || raw[ntHeadersOffset + 3] != 0) return false;

            // 32-bit check
            int optionalHeaderOffset = ntHeadersOffset + 4 + 20;
            if (ToInt16(raw, optionalHeaderOffset) != 0x10B) return false;

            return true;
        }

        public static uint ReadTimeDateStamp(byte[] raw)
        {
            int ntHeadersOffset = ToInt32(raw, 0x3C);
            return (uint)ToInt32(raw, ntHeadersOffset + 4 + 4);
        }

        public static int SumAlignedVirtualSize(byte[] raw, string[] names)
        {
            int ntHeadersOffset = ToInt32(raw, 0x3C);
            int optionalHeaderOffset = ntHeadersOffset + 4 + 20;
            uint fileAlignment = (uint)ToInt32(raw, optionalHeaderOffset + 36);

            uint total = 0;
            foreach (string name in names)
            {
                int sectionHeaderOffset = SectionOffset(raw, name);
                if (sectionHeaderOffset < 0) continue;

                uint virtualSize = (uint)ToInt32(raw, sectionHeaderOffset + 8);
                uint aligned = (virtualSize + fileAlignment - 1) & ~(fileAlignment - 1);
                total += aligned;
            }
            return (int)total;
        }

        private static BuildInfo? FindBuild(uint timeDateStamp)
        {
            foreach (BuildInfo candidate in Builds)
            {
                if (candidate.TimeDateStamp == timeDateStamp) return candidate;
            }

            return null;
        }

        public static int SectionOffset(byte[] raw, string name)
        {
            int ntHeadersOffset = ToInt32(raw, 0x3C);
            int sectionCount = ToInt16(raw, ntHeadersOffset + 4 + 2);
            int optionalHeaderSize = ToInt16(raw, ntHeadersOffset + 4 + 16);
            int sectionTableOffset = ntHeadersOffset + 4 + 20 + optionalHeaderSize;

            for (int i = 0; i < sectionCount; i++)
            {
                int sectionHeaderOffset = sectionTableOffset + i * 40;
                if (Encoding.UTF8.GetString(raw, sectionHeaderOffset, 8).TrimEnd('\0') == name) return sectionHeaderOffset;
            }

            return -1;
        }

        public static int SectionRva(byte[] raw, string name)
        {
            int sectionHeaderOffset = SectionOffset(raw, name);
            return sectionHeaderOffset < 0 ? -1 : ToInt32(raw, sectionHeaderOffset + 12);
        }

        public static void Write32(byte[] buf, int i, int val)
        {
            buf[i] = (byte)val;
            buf[i + 1] = (byte)(val >> 0x08);
            buf[i + 2] = (byte)(val >> 0x10);
            buf[i + 3] = (byte)(val >> 0x18);
        }

        public static int ToInt32(byte[] buf, int i)
        {
            return buf[i] | (buf[i + 1] << 8) | (buf[i + 2] << 16) | (buf[i + 3] << 24);
        }

        public static short ToInt16(byte[] buf, int i)
        {
            return (short)(buf[i] | (buf[i + 1] << 8));
        }

        #endregion
    }
}