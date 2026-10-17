namespace AESylum.MFortress
{
    internal static class Signatures
    {
        // memory reads that anchor the integrity hash loops
        private static readonly string[] HashMemoryReads =
        [
            "8B ?? 2B ?? 0F B7 ?? FF", "0F B7 ?? ?? 01 83 ?? 02 33", "0F B7 ?? 33 ?? 69",
            "0F B7 ?? 03 ?? 69", "0F B7 ?? ?? FF 03 ?? 69", "0F B7 ?? ?? FF 33 ?? 69",
            "0F B7 ?? ?? FF 8B", "0F B7 ?? 6B ?? ?? 83", "0F B7 ?? ?? 83 ?? ?? 33 ?? 69",
            "0F B7 ?? ?? 69 ?? ?? ?? ?? ?? 83", "0F B7 ?? ?? FF 6B ?? ?? 83", "0F B7 ?? 33 ?? 89 ?? ?? 3B",
            "2B ?? 0F B7 ?? ?? 03 ?? 83", "0F B7 ?? 69 ?? ?? ?? ?? ?? 83", "0F B7 ?? ?? ?? 83 ?? ?? 03",
            "0F B7 ?? 33 ?? ?? ?? ?? ?? 83 ?? ?? 69", "0F B7 ?? 83 ?? ?? 33 ?? 3B", "0F B7 ?? 33 ?? 3B",
            "0F B7 ?? ?? ?? 69 ?? ?? ?? ?? ?? 83", "0F B7 ?? 69 ?? ?? ?? ?? ?? 03 ?? 83",
            "0F B7 ?? ?? 03 ?? 89 ?? ?? 3B", "0F B7 ?? 8B ?? C1 ?? ?? C1", "3B ?? 74 ?? 0F B7 ?? ?? ?? 83",
            "0F B7 ?? ?? ?? 33 ?? ?? ?? ?? ?? 83", "0F B7 ?? ?? ?? 6B ?? ?? 83", "0F B7 ?? ?? 03 ?? 69",
            "0F B7 ?? ?? 83 ?? ?? 03", "0F B7 ?? ?? 33 ?? 69", "0F B7 ?? ?? 8B ?? C1 ?? ?? 33",
            "0F B7 ?? ?? 69 ?? ?? ?? ?? ?? 03 ?? 8B", "0F B7 ?? ?? ?? 6B ?? ?? 03", "0F B7 ?? ?? ?? 33 ?? ?? 83",
            "0F B7 ?? ?? 6B ?? ?? 83", "0F B7 ?? ?? 33 ?? ?? 83", "0F B7 ?? ?? 33 ?? ?? 69",
            "0F B7 ?? ?? ?? 83 ?? ?? 8B ?? C1 ?? ?? 33", "0F B7 ?? 33 ?? ?? 83", "0F B7 ?? ?? ?? 69 ?? ?? ?? ?? ?? 03",
            "0F B7 ?? 33 ?? 83 ?? ?? 89 ?? ?? 3B", "33 ?? 0F B7 ?? 33 ?? 83", "2B ?? 0F B7 ?? ?? 8B",
            "0F B7 ?? 03 ?? ?? 83", "0F B7 ?? ?? ?? 03 ?? ?? 83", "0F B7 ?? 6B ?? ?? 03 ?? 83",
            "0F B7 ?? ?? ?? 33 ?? ?? 8B ?? ?? 69", "8B ?? ?? 0F B7 ?? 03 ?? ?? 89", "8B ?? ?? 0F B7 ?? 33 ?? 89",
            "8B ?? ?? 0F B7 ?? 33 ?? ?? 89", "2B ?? ?? 0F B7 ?? ?? 03", "03 ?? ?? 0F B7 ?? ?? 03",
            "2B ?? ?? 0F B7 ?? ?? 33", "8B ?? ?? 0F B7 ?? ?? ?? 8B ?? ?? 83", "74 ?? 0F B7 ?? ?? 8B ?? 83",
            "2B ?? 0F B7 ?? ?? 03 ?? ?? 83", "0F B7 ?? ?? ?? 83 ?? ?? C1",
            "8B ?? ?? 0F B7 ?? 69 ?? ?? ?? ?? ?? 03 ?? 8B", "0F B7 ?? ?? 8B ?? 83 ?? ?? C1",
            "0F B7 ?? ?? 03 ?? ?? 83 ?? ?? 69",
        ];

        private static readonly HashSet<string> BadFirstMnemonics =
        [
            "ret", "retn", "retf", "iretd", "int3", "int", "hlt", "ud0", "ud1", "ud2", "nop", "pop", "leave", "jmp", "ljmp", "call",
        ];

        private static readonly List<HashPattern> CompiledHashPatterns = HashMemoryReads.Select(CompilePattern).ToList();

        #region Hash reads

        public static List<long> FindHashReads(BinaryImage image)
        {
            List<long> reads = [];
            byte[] bytes = image.Bytes;
            foreach (CodeSection section in image.Code)
            {
                long low = section.VirtualAddress;
                long high = low + Math.Max(section.VirtualSize, section.RawSize);
                long limit = Math.Min(high, bytes.Length);

                for (long offset = low; offset + 1 < limit; offset++)
                {
                    if (bytes[offset] != 0x0F || bytes[offset + 1] != 0xB7) continue;

                    foreach (HashPattern pattern in CompiledHashPatterns)
                    {
                        long start = offset - pattern.Anchor;
                        if (start < low || start + pattern.Bytes.Length > limit || !Matches(bytes, start, pattern.Bytes)) continue;

                        reads.Add(image.Base + offset);
                        break;
                    }
                }
            }
            reads.Sort();
            return reads;
        }

        private static HashPattern CompilePattern(string text)
        {
            string[] tokens = text.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            int anchor = -1;
            for (int i = 0; i + 1 < tokens.Length && anchor < 0; i++)
            {
                if (tokens[i] == "0F" && tokens[i + 1] == "B7") anchor = i;
            }

            int[] bytes = tokens.Select(token => token == "??" ? -1 : Convert.ToInt32(token, 16)).ToArray();
            return new HashPattern(anchor, bytes);
        }

        private static bool Matches(byte[] image, long at, int[] pattern)
        {
            if (at < 0 || at + pattern.Length > image.Length) return false;

            for (int i = 0; i < pattern.Length; i++)
            {
                if (pattern[i] >= 0 && image[at + i] != pattern[i]) return false;
            }
            return true;
        }

        #endregion

        #region Functions

        public static List<long> FindFunctionEntries(BinaryImage image, Decoder decoder)
        {
            HashSet<long> entries = [];
            foreach (CodeSection section in image.Code)
            {
                long low = section.VirtualAddress;
                long high = low + Math.Max(section.VirtualSize, section.RawSize);
                int length = (int)(high - low);
                byte[] data = new byte[length];
                Array.Copy(image.Bytes, (int)low, data, 0, Math.Min(length, image.Bytes.Length - (int)low));
                long sectionBase = image.Base + low;
                entries.Add(sectionBase);

                // standard prologues
                for (int i = 0; i + 2 < length;)
                {
                    if (!IsPrologue(data, i))
                    {
                        i++;
                        continue;
                    }

                    if (BoundaryBefore(data, i)) entries.Add(sectionBase + i);
                    i += 3;
                }

                // the first byte after a run of int3 padding
                for (int i = 0; i < length;)
                {
                    if (data[i] != 0xCC)
                    {
                        i++;
                        continue;
                    }

                    int run = i;
                    while (run < length && data[run] == 0xCC)
                    {
                        run++;
                    }

                    if (run - i >= 2 && run < length && BoundaryBefore(data, i)) entries.Add(sectionBase + run);
                    i = run;
                }
            }

            List<long> kept = [];
            foreach (long entry in entries.Order())
            {
                byte[] head = image.BytesAt(entry, 3);
                if (head.Length == 3 && IsPrologue(head, 0))
                {
                    kept.Add(entry);
                    continue;
                }

                Instruction? instruction = decoder.Decode(entry);
                if (instruction == null || BadFirstMnemonics.Contains(instruction.Mnemonic) || Condition.IsConditionalJump(instruction.Mnemonic)) continue;
                kept.Add(entry);
            }
            return kept;
        }

        public static Dictionary<long, long> FunctionBounds(List<long> entries, BinaryImage image)
        {
            Dictionary<long, long> bounds = [];
            for (int i = 0; i < entries.Count; i++)
            {
                long entry = entries[i];
                long next = Math.Min(i + 1 < entries.Count ? entries[i + 1] : long.MaxValue, image.SectionEnd(entry));
                long offset = Math.Min(next - image.Base, image.Bytes.Length);

                // trailing int3 padding is not part of the function
                while (offset > entry - image.Base && image.Bytes[offset - 1] == 0xCC)
                {
                    offset--;
                }
                bounds[entry] = image.Base + offset;
            }
            return bounds;
        }

        // push ebp / mov ebp, esp or push ebx / mov ebx, esp
        private static bool IsPrologue(byte[] data, int at) => data[at + 1] == 0x8B && (data[at] == 0x55 && data[at + 2] == 0xEC || data[at] == 0x53 && data[at + 2] == 0xDC);

        private static bool BoundaryBefore(byte[] data, long position)
        {
            if (position == 0) return true;

            byte previous = data[position - 1];
            if (previous is 0xCC or 0xC3 or 0x00 or 0xFF) return true;
            if (position >= 3 && data[position - 3] == 0xC2) return true;
            if (position >= 5 && data[position - 5] == 0xE9) return true;
            return position >= 2 && (data[position - 2] == 0xFF && previous is >= 0xE0 and <= 0xE7 || data[position - 2] == 0xEB);
        }

        #endregion

        private record HashPattern(int Anchor, int[] Bytes);
    }
}
