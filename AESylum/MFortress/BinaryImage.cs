namespace AESylum.MFortress
{
    internal class CodeSection
    {
        public long VirtualAddress;
        public long VirtualSize;
        public long RawSize;
        public long Length => Math.Max(VirtualSize, RawSize);
    }

    internal class BinaryImage
    {
        public byte[] Bytes = [];
        public long Base;
        public CodeSection[] Code = [];

        public byte[] BytesAt(long virtualAddress, int count)
        {
            long offset = virtualAddress - Base;
            if (offset < 0) return [];

            int take = (int)Math.Max(0, Math.Min(count, Bytes.Length - offset));
            byte[] result = new byte[take];
            Array.Copy(Bytes, (int)offset, result, 0, take);
            return result;
        }

        public long SectionEnd(long virtualAddress)
        {
            foreach (CodeSection section in Code)
            {
                long start = Base + section.VirtualAddress;
                long end = start + section.Length;
                if (start <= virtualAddress && virtualAddress < end) return end;
            }
            return Base + Bytes.Length;
        }

        public (long Low, long High) CodeExtent()
        {
            long low = long.MaxValue;
            long high = 0;
            foreach (CodeSection section in Code)
            {
                low = Math.Min(low, Base + section.VirtualAddress);
                high = Math.Max(high, Base + section.VirtualAddress + section.Length);
            }
            return (low, high);
        }
    }
}
