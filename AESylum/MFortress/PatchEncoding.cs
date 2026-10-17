namespace AESylum.MFortress
{
    internal static class PatchEncoding
    {
        private const int GameScanDepth = 6;
        private const int KillScanDepth = 4;

        #region Encoders

        // sub/xor reg, x becomes xor reg, reg padded with nops
        public static byte[]? EncodeZero(Decoder decoder, long compareAddress)
        {
            Instruction instruction = decoder.Decode(compareAddress)!;
            string? full = Registers.Containing(instruction.Operands[0].Register);
            if (full == null || !Registers.TryNumber(full, out int number)) return null;

            byte[] patched = new byte[instruction.Size];
            Array.Fill(patched, (byte)0x90);
            patched[0] = 0x33;
            patched[1] = (byte)(0xC0 | number << 3 | number);
            return patched;
        }

        // jcc becomes jmp, the near form loses its second opcode byte and gets one more displacement byte
        public static byte[]? EncodeForce(Decoder decoder, long branchAddress)
        {
            byte[] bytes = decoder.Decode(branchAddress)!.Bytes;
            if (bytes[0] is >= 0x70 and < 0x80) return [0xEB, bytes[1]];
            if (bytes[0] != 0x0F || bytes[1] is < 0x80 or > 0x8F) return null;

            byte[] patched = new byte[6];
            patched[0] = 0xE9;
            BitConverter.GetBytes(BitConverter.ToInt32(bytes, 2) + 1).CopyTo(patched, 1);
            patched[5] = 0x90;
            return patched;
        }

        public static byte[] EncodeNop(Decoder decoder, long branchAddress)
        {
            byte[] patched = new byte[decoder.Decode(branchAddress)!.Size];
            Array.Fill(patched, (byte)0x90);
            return patched;
        }

        #endregion

        #region Direction

        public static (string Good, bool ZeroSide) ValidDirection(FunctionGraph graph, Decoder decoder, long branchAddress, HashSet<long> must)
        {
            (long taken, long next) = graph.Branches[branchAddress];
            bool zeroTaken = Condition.OutcomeWhenZero(graph.Nodes[branchAddress].Mnemonic) == true;
            string matchDirection = zeroTaken ? "taken" : "fall";
            string opposite = zeroTaken ? "fall" : "taken";
            long matchDestination = zeroTaken ? taken : next;
            long missDestination = zeroTaken ? next : taken;

            string good;
            if (must.Contains(matchDestination)) good = opposite;
            else if (must.Contains(missDestination)) good = matchDirection;
            else if (BeginsKillGadget(graph, decoder, matchDestination)) good = opposite;
            else if (zeroTaken && ReachesGameLogic(graph, decoder, next)) good = "fall";
            else good = matchDirection;

            return (good, IsZeroSide(good, zeroTaken));
        }

        private static bool IsZeroSide(string good, bool zeroTaken) => good == "taken" && zeroTaken || good == "fall" && !zeroTaken;

        private static bool ReachesGameLogic(FunctionGraph graph, Decoder decoder, long start)
        {
            long current = start;
            bool pushedConstant = false;
            for (int i = 0; i < GameScanDepth; i++)
            {
                Instruction? instruction = NodeOrDecode(graph, decoder, current);
                if (instruction == null) return false;

                string mnemonic = instruction.Mnemonic;
                if (mnemonic == "mov" && IsFramePivot(instruction)) return false;
                if (mnemonic is "cmp" or "test") return true;
                if (mnemonic == "call") return !pushedConstant && !IsCallPlusFive(instruction);
                if (mnemonic == "push" && instruction.Operands[0].Kind == OperandKind.Immediate) pushedConstant = true;
                if (Condition.EndsPath(mnemonic) || mnemonic == "jmp") return false;

                current += instruction.Size;
            }
            return false;
        }

        private static bool BeginsKillGadget(FunctionGraph graph, Decoder decoder, long start)
        {
            long current = start;
            for (int i = 0; i < KillScanDepth; i++)
            {
                Instruction? instruction = NodeOrDecode(graph, decoder, current);
                if (instruction == null) return false;

                string mnemonic = instruction.Mnemonic;
                if (mnemonic == "mov" && IsFramePivot(instruction)) return true;
                if (Condition.EndsPath(mnemonic) || mnemonic is "call" or "jmp" || Condition.IsConditionalJump(mnemonic)) return false;

                current += instruction.Size;
            }
            return false;
        }

        private static Instruction? NodeOrDecode(FunctionGraph graph, Decoder decoder, long address) => graph.Nodes.TryGetValue(address, out Instruction? instruction) ? instruction : decoder.Decode(address);

        private static bool IsCallPlusFive(Instruction instruction) =>
            instruction.Bytes.Length > 0 && instruction.Bytes[0] == 0xE8 && instruction.Operands.Length > 0
            && instruction.Operands[0].Kind == OperandKind.Immediate && instruction.Operands[0].Immediate == instruction.Address + instruction.Size;

        private static bool IsFramePivot(Instruction instruction) =>
            instruction.Mnemonic == "mov" && instruction.Operands.Length == 2
            && instruction.Operands[0] is { Kind: OperandKind.Register, Register: "ebp" }
            && instruction.Operands[1] is { Kind: OperandKind.Register, Register: "esp" };

        #endregion

        #region Emit

        public static (long Address, byte[] Patched) EmitForBranch(FunctionGraph graph, Decoder decoder, long branchAddress, HashSet<long> must, long? compareHint, string? good)
        {
            bool zeroSide;
            if (good == null)
            {
                (good, zeroSide) = ValidDirection(graph, decoder, branchAddress, must);
            }
            else
            {
                bool zeroTaken = Condition.OutcomeWhenZero(graph.Nodes[branchAddress].Mnemonic) == true;
                zeroSide = IsZeroSide(good, zeroTaken);
            }

            if (zeroSide && ZeroableFlagSetter(graph, branchAddress, compareHint) is long compare && EncodeZero(decoder, compare) is byte[] zeroed) return (compare, zeroed);
            if (good == "taken" && EncodeForce(decoder, branchAddress) is byte[] forced) return (branchAddress, forced);

            return (branchAddress, EncodeNop(decoder, branchAddress));
        }

        public static (long Address, byte[] Patched)? EncodeSkip(Decoder decoder, long branchAddress, string force)
        {
            if (force != "taken") return (branchAddress, EncodeNop(decoder, branchAddress));

            byte[]? forced = EncodeForce(decoder, branchAddress);
            return forced != null ? (branchAddress, forced) : null;
        }

        private static long? ZeroableFlagSetter(FunctionGraph graph, long branchAddress, long? compareHint)
        {
            if (!compareHint.HasValue)
            {
                Instruction? setter = Detectors.NearestFlagSetter(graph, branchAddress);
                return IsZeroablePrimary(setter) ? setter!.Address : null;
            }

            graph.Nodes.TryGetValue(compareHint.Value, out Instruction? hinted);
            if (IsZeroablePrimary(hinted)) return hinted!.Address;

            Instruction? fallback = Detectors.NearestFlagSetter(graph, branchAddress);
            return IsZeroableFallback(fallback) ? fallback!.Address : null;
        }

        // sub/xor reg, mem or reg, reg that can safely become xor reg, reg
        private static bool IsZeroablePrimary(Instruction? instruction)
        {
            if (instruction is not { Mnemonic: "sub" or "xor", Operands: [{ Kind: OperandKind.Register } destination, Operand source] }) return false;

            return source.Kind == OperandKind.Memory
                || source.Kind == OperandKind.Register && Registers.Full32(source.Register) != null && Registers.Full32(destination.Register) != null && destination.Register != source.Register;
        }

        private static bool IsZeroableFallback(Instruction? instruction)
        {
            if (instruction is not { Mnemonic: "sub" or "xor", Operands: [{ Kind: OperandKind.Register } destination, Operand source] }) return false;

            return source.Kind == OperandKind.Memory || source.Kind == OperandKind.Register && destination.Register != source.Register;
        }

        #endregion
    }
}
