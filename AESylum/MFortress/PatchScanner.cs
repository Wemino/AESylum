namespace AESylum.MFortress
{
    // derives the DRM patch set from the binary itself instead of a baked-in table, the result
    // has the shape ApplyPatches expects so it drops straight in
    internal static class PatchScanner
    {
        public static Patch[] Scan(byte[] raw)
        {
            BinaryImage image = BuildImage(raw);
            (long low, long high) = image.CodeExtent();
            Decoder decoder = new(image.Bytes, image.Base, low, high);

            List<Patch> patches = Run(image, decoder);
            patches.Sort((left, right) => left.Rva.CompareTo(right.Rva));
            return patches.ToArray();
        }

        #region Image

        private static BinaryImage BuildImage(byte[] raw)
        {
            int ntHeadersOffset = Program.ToInt32(raw, 0x3C);
            int optionalHeaderOffset = ntHeadersOffset + 4 + 20;
            long imageBase = (uint)Program.ToInt32(raw, optionalHeaderOffset + 28);
            long imageLength = (uint)Program.ToInt32(raw, optionalHeaderOffset + 56);
            int sectionCount = Program.ToInt16(raw, ntHeadersOffset + 4 + 2);
            int optionalHeaderSize = Program.ToInt16(raw, ntHeadersOffset + 4 + 16);
            int sectionTableOffset = optionalHeaderOffset + optionalHeaderSize;

            List<(long VirtualAddress, long VirtualSize, long RawSize, long RawPointer, long Characteristics)> sections = new();
            for (int i = 0; i < sectionCount; i++)
            {
                int header = sectionTableOffset + i * 40;
                long virtualSize = (uint)Program.ToInt32(raw, header + 8);
                long virtualAddress = (uint)Program.ToInt32(raw, header + 12);
                long rawSize = (uint)Program.ToInt32(raw, header + 16);
                long rawPointer = (uint)Program.ToInt32(raw, header + 20);
                long characteristics = (uint)Program.ToInt32(raw, header + 36);

                sections.Add((virtualAddress, virtualSize, rawSize, rawPointer, characteristics));
                imageLength = Math.Max(imageLength, virtualAddress + Math.Max(virtualSize, rawSize));
            }

            byte[] bytes = new byte[imageLength];
            List<CodeSection> code = new();
            foreach ((long virtualAddress, long virtualSize, long rawSize, long rawPointer, long characteristics) in sections)
            {
                long count = Math.Min(rawSize, raw.Length - rawPointer);
                if (count > 0) Array.Copy(raw, (int)rawPointer, bytes, (int)virtualAddress, (int)count);

                // IMAGE_SCN_MEM_EXECUTE
                if ((characteristics & 0x20000000) != 0) code.Add(new CodeSection { VirtualAddress = virtualAddress, VirtualSize = virtualSize, RawSize = rawSize });
            }
            return new BinaryImage { Bytes = bytes, Base = imageBase, Code = code.ToArray() };
        }

        #endregion

        #region Scan

        private static List<Patch> Run(BinaryImage image, Decoder decoder)
        {
            List<long> hashReads = Signatures.FindHashReads(image);
            List<long> entries = Signatures.FindFunctionEntries(image, decoder);
            Dictionary<long, long> bounds = Signatures.FunctionBounds(entries, image);

            // hash reads grouped by the function that contains them
            Dictionary<long, List<long>> functions = new();
            foreach (long read in hashReads)
            {
                int index = entries.BinarySearch(read);
                if (index < 0) index = ~index - 1;
                if (index < 0) continue;

                long entry = entries[index];
                if (!functions.TryGetValue(entry, out List<long>? list))
                {
                    list = [];
                    functions[entry] = list;
                }
                list.Add(read);
            }

            List<Patch> patches = new();
            foreach (long entry in functions.Keys.Order())
            {
                FunctionGraph graph = ControlFlow.Build(decoder, entry, bounds[entry]);
                foreach ((long address, byte[] bytes) in AnalyzeFunction(graph, decoder, functions[entry]))
                {
                    patches.Add(new Patch((uint)(address - image.Base), bytes));
                }
            }
            return patches;
        }

        private static List<(long Address, byte[] Patched)> AnalyzeFunction(FunctionGraph graph, Decoder decoder, List<long> hashReads)
        {
            Dictionary<long, long> idom = ControlFlow.Dominators(graph);
            HashSet<long> must = graph.Sinks.Count > 0 ? ControlFlow.MustReach(graph, graph.Sinks) : [];
            List<(long Address, byte[] Patched)> patches = [];
            HashSet<long> usedBranches = [];

            // the branch that skips the whole hash loop
            HashLoop? loop = Detectors.FindHashLoop(graph, idom, hashReads);
            if (loop != null && PatchEncoding.EncodeSkip(decoder, loop.SkipBranch, loop.SkipForce) is { } skip)
            {
                patches.Add(skip);
                usedBranches.Add(loop.SkipBranch);
            }

            // checks are keyed by their branch, or by the compare when there is none
            OrderedMap<(int, long), (long Compare, long? Branch)> checks = new();
            List<(long Compare, long? Branch)> found = Detectors.FindHashChecks(graph);
            found.AddRange(Detectors.FindHashChecksAccumulator(graph, loop));
            foreach ((long compare, long? branch) in found)
            {
                checks.SetDefault(branch.HasValue ? (0, branch.Value) : (1, compare), (compare, branch));
            }

            Dictionary<long, string> producers = [];
            HashSet<long> zeroed = [];
            foreach ((long compare, long? branch) in checks.Select(entry => entry.Value))
            {
                if (graph.Nodes.TryGetValue(compare, out Instruction? instruction) && instruction.Mnemonic is "sub" or "xor"
                    && instruction.Operands.Length > 0 && instruction.Operands[0].Kind == OperandKind.Register
                    && Registers.Containing(instruction.Operands[0].Register) is string produced)
                {
                    producers[compare] = produced;
                }

                if (branch.HasValue && usedBranches.Contains(branch.Value)) continue;

                if (!branch.HasValue)
                {
                    byte[]? zeroedBytes = PatchEncoding.EncodeZero(decoder, compare);
                    if (zeroedBytes == null) continue;

                    patches.Add((compare, zeroedBytes));
                    zeroed.Add(compare);
                    continue;
                }

                (long address, byte[] bytes) = PatchEncoding.EmitForBranch(graph, decoder, branch.Value, must, compare, null);
                patches.Add((address, bytes));
                usedBranches.Add(branch.Value);
                if (address != branch.Value) zeroed.Add(address);
            }

            // branches that guard the sinks
            foreach ((long branch, string escape) in Detectors.GateDecisions(graph, idom))
            {
                if (usedBranches.Contains(branch)) continue;

                patches.Add(PatchEncoding.EmitForBranch(graph, decoder, branch, must, null, escape));
                usedBranches.Add(branch);
            }

            foreach ((long _, long branch, HashSet<long> definitions) in FindReusedGates(graph, producers))
            {
                if (usedBranches.Contains(branch)) continue;

                (string good, bool _) = PatchEncoding.ValidDirection(graph, decoder, branch, must);
                bool zeroTaken = Condition.OutcomeWhenZero(graph.Nodes[branch].Mnemonic) == true;
                if (definitions.All(zeroed.Contains) && good == (zeroTaken ? "taken" : "fall")) continue;

                patches.Add(PatchEncoding.EmitForBranch(graph, decoder, branch, must, null, good));
                usedBranches.Add(branch);
            }
            return patches;
        }

        #endregion

        #region Reused gates

        private static List<(long Test, long Branch, HashSet<long> Definitions)> FindReusedGates(FunctionGraph graph, Dictionary<long, string> producers)
        {
            List<(long Test, long Branch, HashSet<long> Definitions)> result = [];
            GraphIndex index = graph.Index();
            if (producers.Count == 0 || !index.TryGetIndex(graph.Entry, out int entry) || !index.IsNode(entry)) return result;

            List<string> tracked = producers.Values.Distinct().ToList();
            Dictionary<string, int> trackedIndex = [];
            for (int i = 0; i < tracked.Count; i++)
            {
                trackedIndex[tracked[i]] = i;
            }

            List<long> sites = producers.Keys.Order().ToList();
            int words = (sites.Count + 63) / 64;
            Dictionary<int, ulong[]> states = ReachingDefinitions(graph, index, entry, producers, trackedIndex, sites);

            long? previous = null;
            foreach (long address in graph.SortedAddresses())
            {
                long? priorAddress = previous;
                previous = address;
                if (graph.Nodes[address].Mnemonic is not ("je" or "jz" or "jne" or "jnz") || !priorAddress.HasValue) continue;

                Instruction prior = graph.Nodes[priorAddress.Value];
                if (prior.Mnemonic is not ("test" or "or" or "cmp") || prior.Operands.Length != 2) continue;

                Operand first = prior.Operands[0];
                Operand second = prior.Operands[1];
                if (first.Kind != OperandKind.Register) continue;

                bool selfTest = second.Kind == OperandKind.Register && second.Register == first.Register;
                bool zeroCompare = second.Kind == OperandKind.Immediate && second.Immediate == 0;
                bool testLike = prior.Mnemonic is "test" or "or";
                if (!(testLike ? selfTest : zeroCompare)) continue;

                string? register = Registers.Containing(first.Register);
                if (register == null || !trackedIndex.TryGetValue(register, out int trackedRegister)
                    || !index.TryGetIndex(priorAddress.Value, out int priorNode) || !states.TryGetValue(priorNode, out ulong[]? state)) continue;

                int baseSlot = trackedRegister * (words + 1);
                if (state[baseSlot] != 0) continue;

                HashSet<long> definitions = new();
                for (int site = 0; site < sites.Count; site++)
                {
                    if ((state[baseSlot + 1 + (site >> 6)] & 1UL << (site & 63)) != 0) definitions.Add(sites[site]);
                }
                if (definitions.Count > 0) result.Add((priorAddress.Value, address, definitions));
            }
            return result;
        }

        private static Dictionary<int, ulong[]> ReachingDefinitions(FunctionGraph graph, GraphIndex index, int entry, Dictionary<long, string> producers, Dictionary<string, int> trackedIndex, List<long> sites)
        {
            Dictionary<long, int> siteIndex = [];
            for (int i = 0; i < sites.Count; i++)
            {
                siteIndex[sites[i]] = i;
            }

            // per register: word 0 is the non-producer flag, then the site bits
            int words = (sites.Count + 63) / 64;
            int slots = trackedIndex.Count * (words + 1);
            Dictionary<int, ulong[]> states = [];
            int[]?[] clobbered = new int[index.NodeSlots][];
            bool[] queued = new bool[index.NodeSlots];
            Queue<int> work = new();
            ulong[] empty = new ulong[slots];
            ulong[] output = new ulong[slots];

            work.Enqueue(entry);
            queued[entry] = true;
            while (work.Count > 0)
            {
                int node = work.Dequeue();
                long address = index.AddressOf(node);
                Array.Copy(states.GetValueOrDefault(node, empty), output, slots);

                if (producers.TryGetValue(address, out string? producer))
                {
                    int baseSlot = trackedIndex[producer] * (words + 1);
                    Array.Clear(output, baseSlot, words + 1);

                    int site = siteIndex[address];
                    output[baseSlot + 1 + (site >> 6)] |= 1UL << (site & 63);
                }
                else
                {
                    int[] killed = clobbered[node] ??= Clobbers(graph.Nodes[address]).Where(trackedIndex.ContainsKey).Select(name => trackedIndex[name]).ToArray();
                    foreach (int register in killed)
                    {
                        int baseSlot = register * (words + 1);
                        Array.Clear(output, baseSlot, words + 1);
                        output[baseSlot] = 1;
                    }
                }

                foreach (int successor in index.SuccessorsOf(node))
                {
                    if (!index.IsNode(successor)) continue;

                    if (!states.TryGetValue(successor, out ulong[]? target))
                    {
                        target = new ulong[slots];
                        states[successor] = target;
                    }

                    bool changed = false;
                    for (int i = 0; i < slots; i++)
                    {
                        ulong merged = target[i] | output[i];
                        if (merged == target[i]) continue;

                        target[i] = merged;
                        changed = true;
                    }

                    if (!changed && queued[successor]) continue;

                    queued[successor] = true;
                    work.Enqueue(successor);
                }
            }
            return states;
        }

        // registers the instruction overwrites
        private static HashSet<string> Clobbers(Instruction instruction)
        {
            string mnemonic = instruction.Mnemonic;
            Operand[] operands = instruction.Operands;
            if (mnemonic is "cmp" or "test" or "push" or "jmp" or "ret" or "retn" or "nop" || Condition.IsConditionalJump(mnemonic)) return [];
            if (mnemonic == "call") return ["eax", "ecx", "edx"];
            if (mnemonic is "mul" or "imul" or "div" or "idiv" or "cdq" or "cwde" && operands.Length <= 1) return ["eax", "edx"];

            HashSet<string> result = new();
            if (operands.Length > 0 && operands[0].Kind == OperandKind.Register && Registers.Containing(operands[0].Register) is string destination) result.Add(destination);
            if (mnemonic is "xchg" or "cmpxchg" or "xadd" && operands.Length > 1 && operands[1].Kind == OperandKind.Register && Registers.Containing(operands[1].Register) is string source) result.Add(source);
            if (mnemonic.StartsWith("movs") || mnemonic.StartsWith("stos") || mnemonic.StartsWith("lods") || mnemonic.StartsWith("rep")) result.UnionWith(["esi", "edi", "ecx", "eax"]);
            return result;
        }

        #endregion
    }
}
