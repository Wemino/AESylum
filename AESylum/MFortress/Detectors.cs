namespace AESylum.MFortress
{
    internal class HashLoop
    {
        public long Header;
        public long Latch;
        public HashSet<long> Body = new();
        public long? Exit;
        public long SkipBranch;
        public string SkipForce = "";
    }

    internal static class Detectors
    {
        private const int DiscardLookahead = 6;
        private const int BooleanLookahead = 10;

        public static readonly HashSet<string> FlagSetters =
        [
            "cmp", "test", "sub", "add", "xor", "or", "and", "dec", "inc", "neg", "sbb", "adc", "shl", "shr", "sar", "bt", "imul",
        ];

        private static readonly HashSet<string> SetInstructionsWriteOnly =
        [
            "setne", "sete", "seta", "setb", "setae", "setbe", "setl", "setg", "setle", "setge", "sets", "setns",
        ];

        public static bool InCodeRange(FunctionGraph graph, long value) => graph.CodeLow <= value && value < graph.CodeHigh;

        public static Instruction? NearestFlagSetter(FunctionGraph graph, long branchAddress)
        {
            long[] addresses = graph.SortedAddresses().Where(address => address < branchAddress).ToArray();
            for (int i = addresses.Length - 1; i >= 0; i--)
            {
                if (FlagSetters.Contains(graph.Nodes[addresses[i]].Mnemonic)) return graph.Nodes[addresses[i]];
            }
            return null;
        }

        #region Slots

        // every write to an [ebp+disp] slot in address order, the value is null when it isn't a known constant
        public static Dictionary<long, List<(long Address, long? Value)>> SlotWrites(FunctionGraph graph)
        {
            Dictionary<long, List<(long Address, long? Value)>> writes = new();
            Dictionary<string, long> registerConstants = new();

            void Write(long slot, long address, long? value)
            {
                if (!writes.TryGetValue(slot, out List<(long Address, long? Value)>? list))
                {
                    list = new();
                    writes[slot] = list;
                }
                list.Add((address, value));
            }

            foreach (long address in graph.SortedAddresses())
            {
                Instruction instruction = graph.Nodes[address];
                Operand[] operands = instruction.Operands;

                if (instruction.Mnemonic == "mov" && operands.Length == 2)
                {
                    Operand destination = operands[0];
                    long? constant = ConstantOf(registerConstants, operands[1]);

                    if (destination.Kind == OperandKind.Memory && destination.Size == 4)
                    {
                        long? slot = Propagation.SlotKey(destination);
                        if (slot.HasValue) Write(slot.Value, address, constant);
                        continue;
                    }

                    if (destination.Kind == OperandKind.Register)
                    {
                        string? register = Registers.Full32(destination.Register);
                        if (register == null) continue;

                        if (constant.HasValue) registerConstants[register] = constant.Value;
                        else registerConstants.Remove(register);
                        continue;
                    }
                }

                if (operands.Length == 0 || instruction.Mnemonic is "cmp" or "test") continue;

                if (operands[0].Kind == OperandKind.Register)
                {
                    string? register = Registers.Full32(operands[0].Register);
                    if (register != null) registerConstants.Remove(register);
                }
                else if (operands[0].Kind == OperandKind.Memory)
                {
                    long? slot = Propagation.SlotKey(operands[0]);
                    if (slot.HasValue) Write(slot.Value, address, null);
                }
            }
            return writes;
        }

        private static long? ConstantOf(Dictionary<string, long> constants, Operand source)
        {
            if (source.Kind == OperandKind.Immediate) return source.Immediate & Bits.Mask32;

            string? register = source.Kind == OperandKind.Register ? Registers.Full32(source.Register) : null;
            return register != null && constants.TryGetValue(register, out long value) ? value : null;
        }

        // value of the latest write before the address
        public static long? SlotAt(Dictionary<long, List<(long Address, long? Value)>> writes, long slot, long address)
        {
            if (!writes.TryGetValue(slot, out List<(long Address, long? Value)>? list)) return null;

            long bestAddress = long.MinValue;
            long? best = null;
            foreach ((long writeAddress, long? value) in list)
            {
                if (writeAddress >= address || writeAddress <= bestAddress) continue;

                bestAddress = writeAddress;
                best = value;
            }
            return best;
        }

        #endregion

        #region Gates

        public static (long Address, string Escape)? ControllingGate(FunctionGraph graph, Dictionary<long, long> idom, long sink)
        {
            int bestDepth = int.MaxValue;
            (long Address, string Escape)? best = null;
            foreach (KeyValuePair<long, (long Taken, long Next)> branch in graph.Branches)
            {
                long address = branch.Key;
                long taken = branch.Value.Taken;
                long next = branch.Value.Next;
                if (!ControlFlow.Dominates(idom, address, sink)) continue;

                // exactly one side may still reach the sink
                bool reachableFromTaken = ControlFlow.CanReach(graph, taken, sink, address);
                bool reachableFromNext = ControlFlow.CanReach(graph, next, sink, address);
                if (reachableFromTaken == reachableFromNext) continue;

                string escape = reachableFromTaken ? "fall" : "taken";
                if (!ControlFlow.ReachesExit(graph, escape == "taken" ? taken : next, address)) continue;

                int depth = ControlFlow.DominatorDepth(idom, address);
                if (best.HasValue && depth >= bestDepth) continue;

                bestDepth = depth;
                best = (address, escape);
            }
            return best;
        }

        public static OrderedMap<long, string> GateDecisions(FunctionGraph graph, Dictionary<long, long> idom)
        {
            OrderedMap<long, string> decisions = new();
            foreach (long sink in graph.Sinks)
            {
                (long Address, string Escape)? gate = ControllingGate(graph, idom, sink);
                if (gate != null) decisions.SetDefault(gate.Value.Address, gate.Value.Escape);
            }
            return decisions;
        }

        #endregion

        #region Hash checks

        public static long? ConsumingBranch(FunctionGraph graph, long compareAddress)
        {
            foreach (long address in graph.SortedAddresses().Where(candidate => candidate > compareAddress))
            {
                string mnemonic = graph.Nodes[address].Mnemonic;
                if (Condition.IsConditionalJump(mnemonic)) return address;
                if (mnemonic == "call" || FlagSetters.Contains(mnemonic) || Condition.EndsPath(mnemonic) || mnemonic == "jmp") return null;
            }
            return null;
        }

        private static bool IsZeroFlagBranch(string mnemonic) => mnemonic is "je" or "jz" or "jne" or "jnz";

        // sub/cmp/xor of a register against a value the function wrote a non-code constant to
        public static List<(long Compare, long? Branch)> FindHashChecks(FunctionGraph graph)
        {
            Dictionary<long, List<(long Address, long? Value)>> writes = SlotWrites(graph);
            Dictionary<string, bool> tagged = new();
            List<(long Compare, long? Branch)> results = new();

            bool IsExpectedSlot(long slot, long at)
            {
                long? value = SlotAt(writes, slot, at);
                return value.HasValue && !InCodeRange(graph, value.Value);
            }

            foreach (long address in graph.SortedAddresses())
            {
                Instruction instruction = graph.Nodes[address];
                string mnemonic = instruction.Mnemonic;
                Operand[] operands = instruction.Operands;

                if (mnemonic is "sub" or "cmp" or "xor" && operands.Length == 2 && operands[0].Kind == OperandKind.Register)
                {
                    string? destination = Registers.Full32(operands[0].Register);
                    Operand source = operands[1];
                    bool candidate = false;

                    if (source.Kind == OperandKind.Memory)
                    {
                        long? slot = Propagation.SlotKey(source);
                        candidate = slot.HasValue && IsExpectedSlot(slot.Value, address);
                    }
                    else if (mnemonic == "xor" && source.Kind == OperandKind.Register && Registers.Full32(source.Register) is string sourceRegister)
                    {
                        candidate = (IsTagged(tagged, destination) || IsTagged(tagged, sourceRegister)) && destination != sourceRegister;
                    }

                    if (candidate)
                    {
                        long? branch = ConsumingBranch(graph, address);
                        if (branch.HasValue && IsZeroFlagBranch(graph.Nodes[branch.Value].Mnemonic)) results.Add((address, branch));
                        else if (mnemonic is "sub" or "xor" && destination != null && BooleanizedReturn(graph, address, destination)) results.Add((address, null));
                    }
                }

                if (operands.Length == 0 || operands[0].Kind != OperandKind.Register) continue;

                string? target = Registers.Full32(operands[0].Register);
                if (target == null) continue;

                if (mnemonic == "mov" && operands.Length == 2)
                {
                    long? slot = operands[1].Kind == OperandKind.Memory ? Propagation.SlotKey(operands[1]) : null;
                    bool fromExpected = slot.HasValue && IsExpectedSlot(slot.Value, address);
                    bool fromTagged = operands[1].Kind == OperandKind.Register && IsTagged(tagged, Registers.Full32(operands[1].Register));

                    if (fromExpected || fromTagged) tagged[target] = true;
                    else tagged.Remove(target);
                }
                else if (mnemonic is not ("cmp" or "test")) tagged.Remove(target);
            }
            return results;
        }

        private static bool IsTagged(Dictionary<string, bool> tagged, string? register) => register != null && tagged.TryGetValue(register, out bool value) && value;

        // sub/xor followed by neg, sbb, neg turns the difference into 0/1
        private static bool BooleanizedReturn(FunctionGraph graph, long compareAddress, string register)
        {
            List<string> sequence = new();
            foreach (long address in graph.SortedAddresses().Where(candidate => candidate > compareAddress).Take(BooleanLookahead))
            {
                Instruction instruction = graph.Nodes[address];
                string mnemonic = instruction.Mnemonic;
                Operand[] operands = instruction.Operands;
                bool writesRegister = operands.Length > 0 && operands[0].Kind == OperandKind.Register;

                if (mnemonic is "pop" or "push" or "nop" || mnemonic == "mov" && writesRegister && Registers.Full32(operands[0].Register) != register) continue;

                if (mnemonic is not ("neg" or "sbb") || !writesRegister || Registers.Full32(operands[0].Register) != register) break;

                sequence.Add(mnemonic);
                if (sequence.Count == 3 && sequence[0] == "neg" && sequence[1] == "sbb" && sequence[2] == "neg") return true;
            }
            return false;
        }

        private static bool FlagsDiscardedByTest(FunctionGraph graph, long compareAddress)
        {
            foreach (long address in graph.SortedAddresses().Where(candidate => candidate > compareAddress).Take(DiscardLookahead))
            {
                string mnemonic = graph.Nodes[address].Mnemonic;
                if (Condition.IsConditionalJump(mnemonic)) return false;
                if (mnemonic is "test" or "cmp") return true;
                if (FlagSetters.Contains(mnemonic)) return false;
            }
            return false;
        }

        #endregion

        #region Accumulator checks

        // same idea for loops that keep the hash in a register or slot, the checks sit after the loop exit
        public static List<(long Compare, long? Branch)> FindHashChecksAccumulator(FunctionGraph graph, HashLoop? loop)
        {
            if (loop == null || loop.Exit is not long exit || !graph.Nodes.ContainsKey(exit)) return [];

            HashSet<long> body = loop.Body;
            HashSet<long> seen = [];
            Stack<long> work = new();
            List<long> order = new();
            work.Push(exit);
            while (work.Count > 0)
            {
                long node = work.Pop();
                if (seen.Contains(node) || node == FunctionGraph.Exit || !graph.Nodes.ContainsKey(node) || body.Contains(node)) continue;

                seen.Add(node);
                order.Add(node);
                foreach (long successor in graph.Successors(node))
                {
                    work.Push(successor);
                }
            }

            string? hashRegister = BodyHashRegister(graph, body, order);
            HashSet<long> accumulatorSlots = CarriedSlots(graph, body);
            if (hashRegister != null)
            {
                foreach (long node in body.Order())
                {
                    Instruction instruction = graph.Nodes[node];
                    Operand[] operands = instruction.Operands;
                    if (instruction.Mnemonic != "mov" || operands.Length != 2 || operands[0].Kind != OperandKind.Memory || operands[1].Kind != OperandKind.Register) continue;
                    if (Registers.Full32(operands[1].Register) != hashRegister) continue;

                    long? slot = Propagation.SlotKey(operands[0]);
                    if (slot.HasValue) accumulatorSlots.Add(slot.Value);
                }
            }
            if (hashRegister == null && accumulatorSlots.Count == 0) return [];

            Dictionary<long, List<(long Address, long? Value)>> writes = SlotWrites(graph);
            HashSet<string> accumulator = [];
            if (hashRegister != null) accumulator.Add(hashRegister);

            List<(long Compare, long? Branch)> results = [];
            foreach (long address in order.Order())
            {
                Instruction instruction = graph.Nodes[address];
                string mnemonic = instruction.Mnemonic;
                Operand[] operands = instruction.Operands;

                if (mnemonic is "sub" or "cmp" or "xor" && operands.Length == 2 && operands[0].Kind == OperandKind.Register)
                {
                    string? destination = Registers.Full32(operands[0].Register);
                    string? sourceRegister = operands[1].Kind == OperandKind.Register ? Registers.Full32(operands[1].Register) : null;
                    bool sourceMemory = operands[1].Kind == OperandKind.Memory;
                    long? sourceSlot = sourceMemory ? Propagation.SlotKey(operands[1]) : null;
                    bool written = sourceSlot.HasValue && SlotAt(writes, sourceSlot.Value, address).HasValue;
                    bool memoryAccumulator = sourceSlot.HasValue && accumulatorSlots.Contains(sourceSlot.Value);
                    bool expectedMemory = sourceMemory && (memoryAccumulator || written);
                    bool expectedRegister = sourceRegister != null && accumulator.Contains(sourceRegister);
                    bool hashIsDestination = destination != null && accumulator.Contains(destination);

                    if (hashIsDestination && (expectedMemory || expectedRegister) || memoryAccumulator)
                    {
                        long? branch = ConsumingBranch(graph, address);
                        bool hasBranch = branch.HasValue && IsZeroFlagBranch(graph.Nodes[branch.Value].Mnemonic) && graph.Branches[branch.Value].Taken > branch.Value;
                        if (hasBranch)
                        {
                            if (mnemonic != "cmp" || sourceMemory) results.Add((address, branch));
                        }
                        else if (mnemonic == "sub" && sourceMemory && !memoryAccumulator && written && FlagsDiscardedByTest(graph, address))
                        {
                            results.Add((address, null));
                        }
                    }
                }

                if (mnemonic is "cmp" or "test" || operands.Length == 0 || operands[0].Kind != OperandKind.Register) continue;

                string? target = Registers.Full32(operands[0].Register);
                if (target == null) continue;

                if (mnemonic is "mov" or "movzx" or "movsx")
                {
                    long? slot = operands[1].Kind == OperandKind.Memory ? Propagation.SlotKey(operands[1]) : null;
                    bool fromAccumulator = operands[1].Kind == OperandKind.Register && InAccumulator(accumulator, Registers.Full32(operands[1].Register));
                    bool fromSlot = slot.HasValue && accumulatorSlots.Contains(slot.Value);

                    if (fromAccumulator || fromSlot) accumulator.Add(target);
                    else accumulator.Remove(target);
                }
                else if (mnemonic is "shr" or "shl" or "sar" or "sal" or "ror" or "rol" or "imul" or "lea" or "add" or "xor" or "or" or "and" or "sub" or "neg" or "not")
                {
                    if (ReadsAccumulator(accumulator, operands, accumulator.Contains(target))) accumulator.Add(target);
                    else accumulator.Remove(target);
                }
                else accumulator.Remove(target);
            }
            return results;
        }

        private static bool InAccumulator(HashSet<string> accumulator, string? register) => register != null && accumulator.Contains(register);

        private static bool ReadsAccumulator(HashSet<string> accumulator, Operand[] operands, bool reads)
        {
            for (int i = 1; i < operands.Length; i++)
            {
                if (operands[i].Kind == OperandKind.Register && InAccumulator(accumulator, Registers.Full32(operands[i].Register))) reads = true;
                if (operands[i].Kind != OperandKind.Memory) continue;

                if (InAccumulator(accumulator, operands[i].Base) || InAccumulator(accumulator, operands[i].Index)) reads = true;
            }
            return reads;
        }

        // registers read by the loop body before it writes them
        private static HashSet<string> CarriedRegisters(FunctionGraph graph, HashSet<long> body)
        {
            HashSet<string> written = [];
            HashSet<string> carried = [];
            foreach (long node in body.Order())
            {
                Instruction instruction = graph.Nodes[node];
                foreach (string register in RegisterReads(instruction))
                {
                    if (!written.Contains(register) && register is not ("ebp" or "esp")) carried.Add(register);
                }

                if (instruction.Operands.Length == 0 || instruction.Operands[0].Kind != OperandKind.Register || instruction.Mnemonic is "cmp" or "test" or "push") continue;

                string? destination = Registers.Full32(instruction.Operands[0].Register);
                if (destination != null) written.Add(destination);
            }
            return carried;
        }

        // [ebp+disp] slots the loop body both reads and updates
        private static HashSet<long> CarriedSlots(FunctionGraph graph, HashSet<long> body)
        {
            HashSet<long> read = [];
            HashSet<long> written = [];
            foreach (long node in body.Order())
            {
                Instruction instruction = graph.Nodes[node];
                Operand[] operands = instruction.Operands;
                foreach (Operand operand in operands)
                {
                    long? slot = operand.Kind == OperandKind.Memory ? Propagation.SlotKey(operand) : null;
                    if (slot.HasValue && operand.Size == 4) read.Add(slot.Value);
                }

                if (operands.Length == 0 || operands[0].Kind != OperandKind.Memory || instruction.Mnemonic is not ("mov" or "xor" or "add" or "sub" or "shl" or "shr" or "imul")) continue;

                long? target = Propagation.SlotKey(operands[0]);
                if (target.HasValue) written.Add(target.Value);
            }
            read.IntersectWith(written);
            return read;
        }

        private static string? BodyHashRegister(FunctionGraph graph, HashSet<long> body, List<long> order)
        {
            HashSet<string> carried = CarriedRegisters(graph, body);
            if (carried.Count == 0) return null;

            // the register multiplied by a constant is the running hash
            string? imulDestination = null;
            foreach (long node in body.Order())
            {
                Instruction instruction = graph.Nodes[node];
                if (instruction.Mnemonic != "imul" || instruction.Operands.Length == 0 || instruction.Operands[0].Kind != OperandKind.Register) continue;
                if (!instruction.Operands.Any(operand => operand.Kind == OperandKind.Immediate)) continue;

                string? destination = Registers.Full32(instruction.Operands[0].Register);
                if (destination != null && carried.Contains(destination)) imulDestination = destination;
            }

            if (imulDestination != null)
            {
                // follow it through plain register copies
                string? current = imulDestination;
                foreach (long node in body.Order())
                {
                    Operand[] operands = graph.Nodes[node].Operands;
                    if (graph.Nodes[node].Mnemonic == "mov" && operands.Length == 2 && operands[0].Kind == OperandKind.Register && operands[1].Kind == OperandKind.Register && Registers.Full32(operands[1].Register) == current)
                    {
                        current = Registers.Full32(operands[0].Register);
                    }
                }
                if (current != null && carried.Contains(current)) return current;
            }

            foreach (long address in order.Order())
            {
                foreach (string register in RegisterReads(graph.Nodes[address]))
                {
                    if (carried.Contains(register)) return register;
                }
            }
            return carried.OrderBy(register => register, StringComparer.Ordinal).First();
        }

        private static HashSet<string> RegisterReads(Instruction instruction)
        {
            HashSet<string> reads = [];
            for (int i = 0; i < instruction.Operands.Length; i++)
            {
                Operand operand = instruction.Operands[i];
                if (operand.Kind == OperandKind.Register)
                {
                    bool writeOnly = i == 0 && (instruction.Mnemonic is "mov" or "movzx" or "movsx" or "lea" or "pop" || SetInstructionsWriteOnly.Contains(instruction.Mnemonic));
                    string? register = writeOnly ? null : Registers.Containing(operand.Register);
                    if (register != null) reads.Add(register);
                }
                else if (operand.Kind == OperandKind.Memory)
                {
                    foreach (string? component in new[] { operand.Base, operand.Index })
                    {
                        string? register = component == null ? null : Registers.Containing(component);
                        if (register != null) reads.Add(register);
                    }
                }
            }
            return reads;
        }

        #endregion

        #region Hash loop

        private static HashSet<long> LoopBody(FunctionGraph graph, long header, long latch)
        {
            HashSet<long> body = [header, latch];
            Stack<long> work = new();
            Dictionary<long, List<long>> predecessors = graph.Predecessors();
            work.Push(latch);
            while (work.Count > 0)
            {
                if (!predecessors.TryGetValue(work.Pop(), out List<long>? parents)) continue;

                foreach (long parent in parents)
                {
                    if (body.Contains(parent) || !graph.Nodes.ContainsKey(parent)) continue;

                    body.Add(parent);
                    work.Push(parent);
                }
            }
            return body;
        }

        public static HashLoop? FindHashLoop(FunctionGraph graph, Dictionary<long, long> idom, List<long> hashReadAddresses)
        {
            List<long> anchors = hashReadAddresses.Where(address => graph.Entry <= address && address < graph.End).ToList();
            if (anchors.Count == 0) return null;

            DominatorTree tree = new(idom, graph.Entry);
            int bestSpan = int.MaxValue;
            long bestHeader = 0;
            long bestLatch = 0;
            HashSet<long>? bestBody = null;
            foreach (long latch in graph.Nodes.Keys)
            {
                foreach (long successor in graph.Successors(latch))
                {
                    if (successor == FunctionGraph.Exit || !graph.Nodes.ContainsKey(successor) || !tree.Dominates(successor, latch)) continue;

                    HashSet<long> body = LoopBody(graph, successor, latch);
                    if (!anchors.Any(body.Contains)) continue;
                    if (bestBody != null && body.Count >= bestSpan) continue;

                    bestSpan = body.Count;
                    bestHeader = successor;
                    bestLatch = latch;
                    bestBody = body;
                }
            }
            if (bestBody == null) return null;

            long anchor = anchors.Where(bestBody.Contains).DefaultIfEmpty(bestHeader).Min();
            List<long> exits = [];
            foreach (long node in bestBody)
            {
                foreach (long successor in graph.Successors(node))
                {
                    if (successor != FunctionGraph.Exit && !bestBody.Contains(successor) && graph.Nodes.ContainsKey(successor)) exits.Add(successor);
                }
            }

            long cursor = anchor;
            while (true)
            {
                if (graph.Branches.TryGetValue(cursor, out (long Taken, long Next) branch))
                {
                    bool reachableFromTaken = ControlFlow.CanReach(graph, branch.Taken, anchor, cursor);
                    bool reachableFromNext = ControlFlow.CanReach(graph, branch.Next, anchor, cursor);
                    if (reachableFromTaken != reachableFromNext)
                    {
                        return new HashLoop
                        {
                            Header = bestHeader,
                            Latch = bestLatch,
                            Body = bestBody,
                            Exit = exits.Count > 0 ? exits.Min() : null,
                            SkipBranch = cursor,
                            SkipForce = reachableFromTaken ? "fall" : "taken",
                        };
                    }
                }

                if (!idom.TryGetValue(cursor, out long parent) || parent == cursor) return null;
                cursor = parent;
            }
        }

        #endregion
    }
}
