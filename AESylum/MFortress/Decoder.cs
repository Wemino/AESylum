using Iced.Intel;

namespace AESylum.MFortress
{
    internal enum OperandKind
    {
        Register = 1,
        Immediate = 2,
        Memory = 3,
    }

    internal class Operand
    {
        public OperandKind Kind;
        public string? Register;
        public long Immediate;
        public bool HasSegment;
        public string? Base;
        public string? Index;
        public int Scale;
        public long Displacement;
        public int Size;
    }

    internal class Instruction
    {
        public long Address;
        public int Size;
        public byte[] Bytes = [];
        public string Mnemonic = string.Empty;
        public Operand[] Operands = [];
    }

    internal class Decoder
    {
        public readonly byte[] Image;
        public readonly long Base;
        public readonly long CodeLow;
        public readonly long CodeHigh;

        private readonly Dictionary<long, Instruction?> cache = new();
        private readonly ByteArrayCodeReader reader;
        private readonly Iced.Intel.Decoder decoder;

        public Decoder(byte[] image, long imageBase, long codeLow, long codeHigh)
        {
            Image = image;
            Base = imageBase;
            CodeLow = codeLow;
            CodeHigh = codeHigh;

            reader = new ByteArrayCodeReader(image);
            decoder = Iced.Intel.Decoder.Create(32, reader);
        }

        public Instruction? Decode(long virtualAddress)
        {
            if (cache.TryGetValue(virtualAddress, out Instruction? cached)) return cached;

            long offset = virtualAddress - Base;
            Instruction? result = offset >= 0 && offset < Image.Length ? DecodeAt((int)offset, virtualAddress) : null;
            cache[virtualAddress] = result;
            return result;
        }

        private Instruction? DecodeAt(int offset, long virtualAddress)
        {
            reader.Position = offset;
            decoder.IP = (ulong)virtualAddress;
            decoder.Decode(out Iced.Intel.Instruction raw);
            return raw.IsInvalid ? null : ToInstruction(in raw, Image, offset);
        }

        private static Instruction ToInstruction(in Iced.Intel.Instruction raw, byte[] source, int offset)
        {
            byte[] bytes = new byte[raw.Length];
            Array.Copy(source, offset, bytes, 0, raw.Length);

            string mnemonic = MnemonicNames[(int)raw.Mnemonic];
            List<Operand> operands = new(4);

            if (raw.OpCount == 1 && raw.Op0Kind is OpKind.FarBranch16 or OpKind.FarBranch32)
            {
                mnemonic = raw.Mnemonic == Mnemonic.Jmp ? "ljmp" : "lcall";
                operands.Add(new Operand { Kind = OperandKind.Immediate, Immediate = raw.FarBranchSelector });
                operands.Add(new Operand { Kind = OperandKind.Immediate, Immediate = raw.Op0Kind == OpKind.FarBranch16 ? raw.FarBranch16 : raw.FarBranch32 });
            }
            else
            {
                for (int i = 0; i < raw.OpCount; i++)
                {
                    if (IsImplicitOperand(in raw, i)) continue;
                    operands.Add(ConvertOperand(in raw, i));
                }
            }

            if (mnemonic == "lea" && operands.Count == 2 && operands[0].Kind == OperandKind.Register && operands[1].Kind == OperandKind.Memory)
            {
                operands[1].Size = RegisterWidth(operands[0].Register!);
            }

            DropImplicitSt0(mnemonic, operands);

            return new Instruction
            {
                Address = (long)raw.IP,
                Size = raw.Length,
                Bytes = bytes,
                Mnemonic = WithPrefix(in raw, mnemonic),
                Operands = operands.ToArray(),
            };
        }

        private static Operand ConvertOperand(in Iced.Intel.Instruction instruction, int index)
        {
            OpKind kind = instruction.GetOpKind(index);
            int memorySize = instruction.MemorySize.GetSize();
            bool segmentOverride = instruction.SegmentPrefix != Register.None;

            switch (kind)
            {
                case OpKind.Register:
                    return new Operand { Kind = OperandKind.Register, Register = RegisterNames[(int)instruction.GetOpRegister(index)] };

                case OpKind.NearBranch16:
                    ulong next = instruction.NextIP;
                    short relative = (short)(ushort)(instruction.NearBranch16 - next);
                    return new Operand { Kind = OperandKind.Immediate, Immediate = (long)((next + (ulong)(long)relative) & 0xFFFFFFFF) };

                case OpKind.NearBranch32:
                case OpKind.NearBranch64:
                    return new Operand { Kind = OperandKind.Immediate, Immediate = (long)(instruction.NearBranchTarget & 0xFFFFFFFF) };

                case OpKind.Memory:
                    return MemoryOperand(in instruction, memorySize, segmentOverride);

                case OpKind.MemorySegSI:
                    return StringOperand(memorySize, "si", segmentOverride);

                case OpKind.MemorySegESI:
                case OpKind.MemorySegRSI:
                    return StringOperand(memorySize, "esi", segmentOverride);

                case OpKind.MemoryESDI:
                    return StringOperand(memorySize, "di", true);

                case OpKind.MemoryESEDI:
                case OpKind.MemoryESRDI:
                    return StringOperand(memorySize, "edi", true);

                default:
                    return new Operand { Kind = OperandKind.Immediate, Immediate = ImmediateValue(in instruction, kind) };
            }
        }

        private static long ImmediateValue(in Iced.Intel.Instruction instruction, OpKind kind)
        {
            return kind switch
            {
                OpKind.Immediate8 => instruction.Immediate8,
                OpKind.Immediate8_2nd => instruction.Immediate8_2nd,
                OpKind.Immediate16 => instruction.Immediate16,
                OpKind.Immediate32 => instruction.Immediate32,
                OpKind.Immediate64 => (long)instruction.Immediate64,
                OpKind.Immediate8to16 => instruction.Immediate8to16,
                OpKind.Immediate8to32 => instruction.Immediate8to32,
                OpKind.Immediate8to64 => instruction.Immediate8to64,
                OpKind.Immediate32to64 => instruction.Immediate32to64,
                _ => throw new InvalidOperationException($"Unexpected operand kind {kind} at 0x{instruction.IP:X}"),
            };
        }

        private static Operand MemoryOperand(in Iced.Intel.Instruction instruction, int size, bool segmentOverride)
        {
            Operand result = new()
            {
                Kind = OperandKind.Memory,
                Base = instruction.MemoryBase == Register.None ? null : RegisterNames[(int)instruction.MemoryBase],
                Index = instruction.MemoryIndex == Register.None ? null : RegisterNames[(int)instruction.MemoryIndex],
                Scale = instruction.MemoryIndexScale,
                HasSegment = segmentOverride,
                Size = size,
            };

            uint displacement = instruction.MemoryDisplacement32;
            if (result.Base == null && result.Index == null) result.Displacement = displacement;
            else if (instruction.MemoryDisplSize == 2) result.Displacement = (short)(ushort)displacement;
            else result.Displacement = (int)displacement;

            return result;
        }

        private static Operand StringOperand(int size, string baseRegister, bool segment)
        {
            return new Operand { Kind = OperandKind.Memory, Base = baseRegister, Scale = 1, Size = size, HasSegment = segment };
        }

        private static bool IsImplicitOperand(in Iced.Intel.Instruction instruction, int index)
        {
            OpKind kind = instruction.GetOpKind(index);
            if (kind is OpKind.MemorySegDI or OpKind.MemorySegEDI or OpKind.MemorySegRDI) return true;
            return instruction.Mnemonic == Mnemonic.Xlatb;
        }

        private static string WithPrefix(in Iced.Intel.Instruction instruction, string mnemonic)
        {
            string prefix = instruction.HasLockPrefix ? "lock " : string.Empty;
            if (instruction.IsStringInstruction)
            {
                bool compares = instruction.Mnemonic is Mnemonic.Cmpsb or Mnemonic.Cmpsw or Mnemonic.Cmpsd or Mnemonic.Scasb or Mnemonic.Scasw or Mnemonic.Scasd;
                if (instruction.HasRepePrefix) prefix += compares ? "repe " : "rep ";
                else if (instruction.HasRepnePrefix) prefix += "repne ";
            }
            return prefix + mnemonic;
        }

        private static int RegisterWidth(string register)
        {
            if (register.Length == 3 && register[0] == 'e') return 4;
            if (register.Length == 2 && register[1] is 'l' or 'h') return 1;
            return 2;
        }

        private static void DropImplicitSt0(string mnemonic, List<Operand> operands)
        {
            if (!mnemonic.StartsWith('f') || operands.Count != 2) return;
            if (operands[0].Kind != OperandKind.Register || operands[1].Kind != OperandKind.Register) return;

            if (operands[1].Register == "st0") operands.RemoveAt(1);
            else if (operands[0].Register == "st0") operands.RemoveAt(0);
        }

        #region Names

        private static readonly Dictionary<string, string> MnemonicAliases = new()
        {
            { "fcomip", "fcompi" },
            { "fucomip", "fucompi" },
            { "reservednop", "nop" },
        };

        private static readonly string[] RegisterNames = BuildNames<Register>(name => name.ToLowerInvariant());

        private static readonly string[] MnemonicNames = BuildNames<Mnemonic>(name => MnemonicAliases.TryGetValue(name.ToLowerInvariant(), out string? alias) ? alias : name.ToLowerInvariant());

        private static string[] BuildNames<T>(Func<string, string> convert) where T : struct, Enum
        {
            T[] values = Enum.GetValues<T>();
            string[] names = new string[values.Max(value => Convert.ToInt32(value)) + 1];
            foreach (T value in values)
            {
                names[Convert.ToInt32(value)] = convert(value.ToString());
            }
            return names;
        }

        #endregion
    }

    internal static class Registers
    {
        private static readonly Dictionary<string, string> Full = new()
        {
            { "eax", "eax" }, { "ecx", "ecx" }, { "edx", "edx" }, { "ebx", "ebx" },
            { "esp", "esp" }, { "ebp", "ebp" }, { "esi", "esi" }, { "edi", "edi" },
            { "ax", "eax" }, { "cx", "ecx" }, { "dx", "edx" }, { "bx", "ebx" },
            { "sp", "esp" }, { "bp", "ebp" }, { "si", "esi" }, { "di", "edi" },
            { "al", "eax" }, { "cl", "ecx" }, { "dl", "edx" }, { "bl", "ebx" },
            { "ah", "eax" }, { "ch", "ecx" }, { "dh", "edx" }, { "bh", "ebx" },
        };

        private static readonly Dictionary<string, int> Numbers = new()
        {
            { "eax", 0 }, { "ecx", 1 }, { "edx", 2 }, { "ebx", 3 }, { "esp", 4 }, { "ebp", 5 }, { "esi", 6 }, { "edi", 7 },
        };

        // name back if it's a full 32 bits register, null otherwise
        public static string? Full32(string? name)
        {
            if (name == null) return null;
            return Full.TryGetValue(name, out string? full) && full == name ? name : null;
        }

        // the 32 bits register that contains it (al -> eax), null otherwise
        public static string? Containing(string? name)
        {
            if (name == null) return null;
            return Full.TryGetValue(name, out string? full) ? full : null;
        }

        public static bool TryNumber(string register, out int number) => Numbers.TryGetValue(register, out number);
    }

    // Flags known after a self-zeroing xor/sub, only the zero state is tracked
    internal enum KnownFlags
    {
        Unknown = 0,
        Zero = 1,
    }

    internal static class Condition
    {
        private static readonly HashSet<string> LoopMnemonics = ["loop", "loope", "loopne", "loopz", "loopnz", "jecxz", "jcxz"];

        // execution never reaches the next address after these
        private static readonly HashSet<string> PathEnders = ["ret", "retn", "retf", "iretd", "int3", "int", "hlt", "ud0", "ud1", "ud2", "ljmp"];

        // Outcome of a jcc with ZF=1, CF=0, SF=0, OF=0 (null if not modelled)
        public static bool? OutcomeWhenZero(string mnemonic)
        {
            return mnemonic switch
            {
                "je" or "jz" => true,
                "jne" or "jnz" => false,
                "jb" or "jc" or "jnae" => false,
                "jae" or "jnb" or "jnc" => true,
                "jbe" or "jna" => true,
                "ja" or "jnbe" => false,
                "js" => false,
                "jns" => true,
                "jl" or "jnge" => false,
                "jge" or "jnl" => true,
                "jle" or "jng" => true,
                "jg" or "jnle" => false,
                "jo" => false,
                "jno" => true,
                _ => null,
            };
        }

        public static bool IsConditionalJump(string mnemonic) => (mnemonic.StartsWith('j') && mnemonic != "jmp") || LoopMnemonics.Contains(mnemonic);

        public static bool IsLoop(string mnemonic) => LoopMnemonics.Contains(mnemonic);

        public static bool EndsPath(string mnemonic) => PathEnders.Contains(mnemonic);
    }
}
