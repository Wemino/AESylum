namespace AESylum.MFortress
{
    internal static class Bits
    {
        public const long Mask32 = 0xFFFFFFFF;
    }

    // Registers, [ebp+disp] slots and push/pop values. Only there to resolve computed jumps/calls and to know when a branch runs right after a self-zeroing xor/sub (ZF=1)
    internal class PropagationState
    {
        public Dictionary<string, long?> Registers = new();
        public Dictionary<long, long?> Slots = new();
        public List<long?> Stack = new();
        public KnownFlags Flags = KnownFlags.Unknown;

        public PropagationState Clone()
        {
            return new PropagationState
            {
                Registers = new Dictionary<string, long?>(Registers),
                Slots = new Dictionary<long, long?>(Slots),
                Stack = new List<long?>(Stack),
                Flags = Flags,
            };
        }
    }

    internal static class Propagation
    {
        // instructions that leave the flags alone
        private static readonly HashSet<string> Preserves =
        [
            "mov", "movzx", "movsx", "lea", "push", "pop", "nop", "xchg", "cdq", "cwde", "cbw", "jmp", "rdtsc",
            "movss", "movsd", "movaps", "movups", "movd", "movq", "xorps", "pxor", "movdqa", "movdqu", "addss",
            "subss", "mulss", "divss", "sqrtss", "cvtsi2ss", "cvttss2si", "cvtss2sd", "cvtsd2ss", "andps", "orps",
            "unpcklps", "shufps", "movlps", "movhps", "movlhps", "movhlps", "cvtdq2ps", "cvttps2dq", "maxss", "minss",
            "addps", "subps", "mulps", "divps", "xorpd", "andpd", "movapd", "setne", "sete", "setl", "setg", "setle",
            "setge", "seta", "setb", "setae", "setbe", "sets", "setns", "setnp", "setp", "wait", "leave",
        ];

        private static readonly string[] X87FlagSetters = ["fcomi", "fucomi", "fcompi", "fucompi"];

        private static readonly HashSet<string> Arithmetic2 = ["add", "sub", "xor", "and", "or", "shl", "shr", "sar", "sal", "imul", "adc", "sbb", "rol", "ror"];

        private static readonly HashSet<string> Arithmetic1 = ["inc", "dec", "neg", "not"];

        public static long? SlotKey(Operand operand)
        {
            if (operand.Kind != OperandKind.Memory) return null;
            if (!operand.HasSegment && operand.Base == "ebp" && operand.Index == null) return operand.Displacement;
            return null;
        }

        public static long? Value(PropagationState state, Operand operand)
        {
            switch (operand.Kind)
            {
                case OperandKind.Immediate:
                    return operand.Immediate & Bits.Mask32;

                case OperandKind.Register:
                    string? register = Registers.Full32(operand.Register);
                    return register != null ? GetRegister(state, register) : null;

                case OperandKind.Memory when operand.Size == 4:
                    long? key = SlotKey(operand);
                    return key.HasValue ? GetSlot(state, key.Value) : null;

                default:
                    return null;
            }
        }

        private static long? GetRegister(PropagationState state, string register) => state.Registers.TryGetValue(register, out long? value) ? value : null;

        private static long? GetSlot(PropagationState state, long key) => state.Slots.TryGetValue(key, out long? value) ? value : null;

        private static void SetRegister(PropagationState state, Operand operand, long? value)
        {
            string? name = operand.Register;
            string? full = Registers.Containing(name);
            if (full == null) return;

            // writing a sub-register loses the full value
            if (name != full || value == null) state.Registers.Remove(full);
            else state.Registers[full] = value.Value & Bits.Mask32;

            if (full == "ebp") state.Slots.Clear();
        }

        private static void SetSlot(PropagationState state, Operand operand, long? value)
        {
            long? key = SlotKey(operand);
            if (!key.HasValue) return;

            if (value == null || operand.Size != 4)
            {
                // partial or unknown write, forget every slot overlapping it
                for (long slot = key.Value - 3; slot <= key.Value + 3; slot++)
                {
                    state.Slots.Remove(slot);
                }
            }
            else
            {
                state.Slots[key.Value] = value.Value & Bits.Mask32;
            }
        }

        private static void SetDestination(PropagationState state, Operand operand, long? value)
        {
            if (operand.Kind == OperandKind.Register) SetRegister(state, operand, value);
            else if (operand.Kind == OperandKind.Memory) SetSlot(state, operand, value);
        }

        private static bool StartsWithX87Setter(string mnemonic) => X87FlagSetters.Any(mnemonic.StartsWith);

        public static void Run(Instruction instruction, PropagationState state)
        {
            string mnemonic = instruction.Mnemonic;
            Operand[] operands = instruction.Operands;

            // xor reg, reg / sub reg, reg
            if (mnemonic is "xor" or "sub" && operands.Length == 2
                && operands[0].Kind == OperandKind.Register && operands[1].Kind == OperandKind.Register
                && operands[0].Register == operands[1].Register)
            {
                SetRegister(state, operands[0], 0);
                state.Flags = KnownFlags.Zero;
                return;
            }

            bool x87KeepsFlags = mnemonic.StartsWith('f') && !StartsWithX87Setter(mnemonic);
            if (!Preserves.Contains(mnemonic) && !x87KeepsFlags && !Condition.IsConditionalJump(mnemonic))
            {
                state.Flags = KnownFlags.Unknown;
            }

            if (mnemonic == "push")
            {
                state.Stack.Add(Value(state, operands[0]));
                return;
            }

            if (mnemonic == "pop")
            {
                long? value = null;
                if (state.Stack.Count > 0)
                {
                    value = state.Stack[^1];
                    state.Stack.RemoveAt(state.Stack.Count - 1);
                }
                SetDestination(state, operands[0], value);
                return;
            }

            if (mnemonic == "call")
            {
                // call $+5, pushes its own return address
                if (instruction.Bytes.Length > 0 && instruction.Bytes[0] == 0xE8
                    && operands[0].Kind == OperandKind.Immediate && operands[0].Immediate == instruction.Address + 5)
                {
                    state.Stack.Add((instruction.Address + 5) & Bits.Mask32);
                    return;
                }

                state.Flags = KnownFlags.Unknown;
                state.Registers.Remove("eax");
                state.Registers.Remove("ecx");
                state.Registers.Remove("edx");
                state.Stack.Clear();
                return;
            }

            if (mnemonic == "mov" && operands.Length == 2)
            {
                SetDestination(state, operands[0], Value(state, operands[1]));
                return;
            }

            if (mnemonic == "lea" && operands.Length == 2 && operands[0].Kind == OperandKind.Register)
            {
                Operand memory = operands[1];
                long? value = null;
                if (!memory.HasSegment && memory.Index == null)
                {
                    if (memory.Base == null)
                    {
                        value = memory.Displacement & Bits.Mask32;
                    }
                    else
                    {
                        long? baseValue = GetRegister(state, memory.Base);
                        value = baseValue == null ? null : (baseValue.Value + memory.Displacement) & Bits.Mask32;
                    }
                }
                SetRegister(state, operands[0], value);
                return;
            }

            if (Arithmetic2.Contains(mnemonic) && operands.Length >= 2 && operands[0].Kind == OperandKind.Register)
            {
                string? destination = Registers.Full32(operands[0].Register);
                if (destination == null)
                {
                    SetRegister(state, operands[0], null);
                    return;
                }

                long? result;
                if (mnemonic == "imul" && operands.Length == 3)
                {
                    long? left = Value(state, operands[1]);
                    long? right = Value(state, operands[2]);
                    result = left == null || right == null ? null : (left.Value * right.Value) & Bits.Mask32;
                }
                else
                {
                    long? left = GetRegister(state, destination);
                    long? right = Value(state, operands[1]);
                    if (left == null || right == null || mnemonic is "adc" or "sbb" or "rol" or "ror" or "sar" or "sal")
                    {
                        result = null;
                    }
                    else
                    {
                        long a = left.Value;
                        long b = right.Value;
                        long computed = mnemonic switch
                        {
                            "add" => a + b,
                            "sub" => a - b,
                            "xor" => a ^ b,
                            "and" => a & b,
                            "or" => a | b,
                            "shl" => a << (int)(b & 31),
                            "shr" => a >> (int)(b & 31),
                            "imul" => a * b,
                            _ => 0,
                        };
                        result = computed & Bits.Mask32;
                    }
                }
                SetRegister(state, operands[0], result);
                return;
            }

            if (Arithmetic2.Contains(mnemonic) && operands.Length >= 2 && operands[0].Kind == OperandKind.Memory)
            {
                SetSlot(state, operands[0], null);
                return;
            }

            if (Arithmetic1.Contains(mnemonic) && operands.Length > 0 && operands[0].Kind == OperandKind.Register)
            {
                string? destination = Registers.Full32(operands[0].Register);
                long? current = destination != null ? GetRegister(state, destination) : null;
                long? result = null;
                if (current != null)
                {
                    long value = current.Value;
                    long computed = mnemonic switch
                    {
                        "inc" => value + 1,
                        "dec" => value - 1,
                        "neg" => -value,
                        _ => ~value,
                    };
                    result = computed & Bits.Mask32;
                }
                SetRegister(state, operands[0], result);
                return;
            }

            if (Arithmetic1.Contains(mnemonic) && operands.Length > 0 && operands[0].Kind == OperandKind.Memory)
            {
                SetSlot(state, operands[0], null);
                return;
            }

            if (mnemonic == "xchg" && operands.Length == 2 && operands[0].Kind == OperandKind.Register && operands[1].Kind == OperandKind.Register)
            {
                long? left = Value(state, operands[0]);
                long? right = Value(state, operands[1]);
                SetRegister(state, operands[0], right);
                SetRegister(state, operands[1], left);
                return;
            }

            if (mnemonic is "mul" or "div" or "idiv" or "cdq" or "rdtsc" or "cpuid" or "cwde" or "cbw" || (mnemonic == "imul" && operands.Length == 1))
            {
                state.Registers.Remove("eax");
                state.Registers.Remove("edx");
                if (mnemonic == "cpuid")
                {
                    state.Registers.Remove("ebx");
                    state.Registers.Remove("ecx");
                }
                return;
            }

            if (Condition.IsLoop(mnemonic))
            {
                state.Registers.Remove("ecx");
                return;
            }

            // compares only touch the flags
            if (mnemonic is "cmp" or "test" or "bt" or "comiss" or "ucomiss") return;
            if (mnemonic.StartsWith("fcom") || mnemonic.StartsWith("fucom") || mnemonic.StartsWith("ficom")) return;

            if (operands.Length > 0) SetDestination(state, operands[0], null);
        }
    }
}
