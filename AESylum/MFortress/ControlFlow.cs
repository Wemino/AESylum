namespace AESylum.MFortress
{
    internal static class ControlFlow
    {
        private const int JumpTableMaxEntries = 512;
        private const long JumpTableMaxSpread = 0x40000;

        #region Build

        public static FunctionGraph Build(Decoder decoder, long entry, long end)
        {
            FunctionGraph graph = new(entry, end) { CodeLow = decoder.CodeLow, CodeHigh = decoder.CodeHigh };
            OrderedMap<long, Instruction> nodes = graph.Nodes;
            Stack<(long Address, PropagationState State)> work = new();
            work.Push((entry, new PropagationState()));

            while (work.Count > 0)
            {
                (long address, PropagationState state) = work.Pop();
                while (true)
                {
                    if (nodes.ContainsKey(address) || !graph.InRange(address)) break;

                    Instruction? instruction = decoder.Decode(address);
                    if (instruction == null) break;

                    nodes[address] = instruction;
                    string mnemonic = instruction.Mnemonic;
                    Operand[] operands = instruction.Operands;
                    long next = address + instruction.Size;

                    if (mnemonic == "jmp")
                    {
                        AddJump(graph, decoder, work, instruction, state);
                        break;
                    }

                    if (Condition.IsConditionalJump(mnemonic))
                    {
                        long target = operands[0].Immediate;

                        // the outcome is only known right after a self-zeroing xor/sub
                        bool? known = state.Flags == KnownFlags.Zero ? Condition.OutcomeWhenZero(mnemonic) : null;
                        graph.Branches[address] = (target, next);

                        if (known != false)
                        {
                            if (graph.InRange(target))
                            {
                                graph.AddEdge(address, target, "taken");
                                work.Push((target, state.Clone()));
                            }
                            else graph.AddEdge(address, FunctionGraph.Exit, "exit");
                        }

                        if (known == true) break;

                        if (!graph.InRange(next))
                        {
                            graph.AddEdge(address, FunctionGraph.Exit, "exit");
                            break;
                        }

                        graph.AddEdge(address, next, "fall");
                        address = next;
                        continue;
                    }

                    if (Condition.EndsPath(mnemonic))
                    {
                        graph.AddEdge(address, FunctionGraph.Exit, "exit");
                        break;
                    }

                    if (mnemonic == "call" && operands[0].Kind == OperandKind.Register)
                    {
                        long? target = RegisterValue(state, operands[0]);
                        if (target.HasValue && !graph.InRange(target.Value)) graph.Sinks.Add(address);
                    }

                    Propagation.Run(instruction, state);
                    if (!graph.InRange(next))
                    {
                        graph.AddEdge(address, FunctionGraph.Exit, "exit");
                        break;
                    }

                    graph.AddEdge(address, next, "next");
                    address = next;
                }
            }
            return graph;
        }

        private static void AddJump(FunctionGraph graph, Decoder decoder, Stack<(long Address, PropagationState State)> work, Instruction instruction, PropagationState state)
        {
            long address = instruction.Address;
            Operand operand = instruction.Operands[0];

            switch (operand.Kind)
            {
                case OperandKind.Immediate:
                    if (graph.InRange(operand.Immediate))
                    {
                        graph.AddEdge(address, operand.Immediate, "jmp");
                        work.Push((operand.Immediate, state.Clone()));
                    }
                    else graph.AddEdge(address, FunctionGraph.Exit, "exit");
                    break;

                case OperandKind.Register:
                    long? hop = RegisterValue(state, operand);
                    if (hop.HasValue && graph.InRange(hop.Value))
                    {
                        graph.AddEdge(address, hop.Value, "hop");
                        work.Push((hop.Value, state.Clone()));
                    }
                    else graph.Sinks.Add(address);
                    break;

                default:
                    List<long> table = JumpTable(decoder, instruction);
                    if (table.Count == 0)
                    {
                        graph.AddEdge(address, FunctionGraph.Exit, "exit");
                        break;
                    }

                    foreach (long target in table)
                    {
                        if (!graph.InRange(target)) continue;

                        graph.AddEdge(address, target, "table");
                        work.Push((target, new PropagationState()));
                    }
                    break;
            }
        }

        private static long? RegisterValue(PropagationState state, Operand operand)
        {
            string? register = Registers.Full32(operand.Register);
            if (register == null) return null;

            return state.Registers.TryGetValue(register, out long? value) ? value : null;
        }

        // jmp [table + reg * 4], the table is read until an entry stops pointing into the code
        private static List<long> JumpTable(Decoder decoder, Instruction instruction)
        {
            List<long> targets = [];
            byte[] bytes = instruction.Bytes;
            if (bytes.Length < 7 || bytes[0] != 0xFF || bytes[1] != 0x24 || (bytes[2] & 7) != 5 || bytes[2] >> 6 != 2) return targets;

            long tableAddress = BitConverter.ToUInt32(bytes, 3);
            for (int i = 0; i < JumpTableMaxEntries; i++)
            {
                long offset = tableAddress + 4 * i - decoder.Base;
                if (offset < 0 || offset + 4 > decoder.Image.Length) break;

                long target = BitConverter.ToUInt32(decoder.Image, (int)offset);
                if (target < decoder.CodeLow || target >= decoder.CodeHigh) break;

                targets.Add(target);
                if (targets.Count > 1 && Math.Abs(target - targets[0]) > JumpTableMaxSpread)
                {
                    targets.RemoveAt(targets.Count - 1);
                    break;
                }
            }
            return targets;
        }

        #endregion

        #region Reachability

        // nodes whose every outgoing path ends in a sink before leaving the function
        public static HashSet<long> MustReach(FunctionGraph graph, IEnumerable<long> sinks)
        {
            Dictionary<long, List<long>> predecessors = graph.Predecessors();
            HashSet<long> must = new(sinks);
            Stack<long> work = new(must);

            while (work.Count > 0)
            {
                if (!predecessors.TryGetValue(work.Pop(), out List<long>? parents)) continue;

                foreach (long parent in parents)
                {
                    if (must.Contains(parent)) continue;

                    List<long> successors = graph.Successors(parent).ToList();
                    if (successors.Count == 0 || !successors.All(must.Contains)) continue;

                    must.Add(parent);
                    work.Push(parent);
                }
            }
            return must;
        }

        public static bool CanReach(FunctionGraph graph, long start, long target, long avoid)
        {
            if (start == target) return true;

            GraphIndex index = graph.Index();
            if (!index.TryGetIndex(start, out int startIndex) || !index.TryGetIndex(target, out int targetIndex)) return false;

            int visit = index.NewVisit();
            if (avoid != long.MinValue && index.TryGetIndex(avoid, out int avoidIndex)) index.MarkSeen(avoidIndex, visit);

            return Walk(index, startIndex, targetIndex, visit);
        }

        public static bool ReachesExit(FunctionGraph graph, long start, long avoid)
        {
            GraphIndex index = graph.Index();
            if (!index.TryGetIndex(start, out int startIndex)) return false;

            int visit = index.NewVisit();
            if (index.TryGetIndex(avoid, out int avoidIndex)) index.MarkSeen(avoidIndex, visit);

            return Walk(index, startIndex, index.Exit, visit);
        }

        // the target is checked when popped, so an avoided node that is the target still counts
        private static bool Walk(GraphIndex index, int start, int target, int visit)
        {
            int[] stack = index.Stack;
            int top = 0;
            stack[top++] = start;
            while (top > 0)
            {
                int node = stack[--top];
                if (node == target) return true;
                if (index.Seen(node, visit) || !index.IsNode(node)) continue;

                index.MarkSeen(node, visit);
                foreach (int successor in index.SuccessorsOf(node))
                {
                    stack[top++] = successor;
                }
            }
            return false;
        }

        #endregion

        #region Dominators

        // immediate dominators (Cooper-Harvey-Kennedy) over the integer-indexed graph
        public static Dictionary<long, long> Dominators(FunctionGraph graph)
        {
            Dictionary<long, long> result = new() { { graph.Entry, graph.Entry } };
            GraphIndex index = graph.Index();
            if (!index.TryGetIndex(graph.Entry, out int entry) || !index.IsNode(entry)) return result;

            int slots = index.NodeSlots;
            int[] rank = new int[slots];
            Array.Fill(rank, -1);

            int[] order = ReversePostOrder(index, entry);
            for (int i = 0; i < order.Length; i++)
            {
                rank[order[i]] = i;
            }

            // predecessors of every reachable node in compressed form
            int[] parentStart = new int[slots + 1];
            foreach (int node in order)
            {
                foreach (int successor in index.SuccessorsOf(node))
                {
                    if (rank[successor] >= 0) parentStart[successor + 1]++;
                }
            }

            for (int i = 0; i < slots; i++)
            {
                parentStart[i + 1] += parentStart[i];
            }

            int[] parents = new int[parentStart[slots]];
            int[] fill = new int[slots];
            foreach (int node in order)
            {
                foreach (int successor in index.SuccessorsOf(node))
                {
                    if (rank[successor] >= 0) parents[parentStart[successor] + fill[successor]++] = node;
                }
            }

            int[] idom = new int[slots];
            Array.Fill(idom, -1);
            idom[entry] = entry;

            bool changed = true;
            while (changed)
            {
                changed = false;
                foreach (int node in order)
                {
                    if (node == entry) continue;

                    int candidate = -1;
                    for (int i = parentStart[node]; i < parentStart[node + 1]; i++)
                    {
                        int parent = parents[i];
                        if (idom[parent] < 0) continue;

                        candidate = candidate < 0 ? parent : Intersect(idom, rank, candidate, parent);
                    }

                    if (candidate < 0 || idom[node] == candidate) continue;

                    idom[node] = candidate;
                    changed = true;
                }
            }

            foreach (int node in order)
            {
                if (idom[node] >= 0) result[index.AddressOf(node)] = index.AddressOf(idom[node]);
            }
            return result;
        }

        private static int[] ReversePostOrder(GraphIndex index, int entry)
        {
            int slots = index.NodeSlots;
            bool[] visited = new bool[slots];
            int[] postOrder = new int[slots];
            int[] stackNode = new int[slots];
            int[] stackPosition = new int[slots];
            int postCount = 0;
            int depth = 0;

            stackNode[0] = entry;
            visited[entry] = true;
            while (depth >= 0)
            {
                int node = stackNode[depth];
                int[] successors = index.SuccessorsOf(node);
                if (stackPosition[depth] >= successors.Length)
                {
                    postOrder[postCount++] = node;
                    depth--;
                    continue;
                }

                int next = successors[stackPosition[depth]++];
                if (visited[next] || !index.IsNode(next)) continue;

                visited[next] = true;
                depth++;
                stackNode[depth] = next;
                stackPosition[depth] = 0;
            }

            int[] order = new int[postCount];
            for (int i = 0; i < postCount; i++)
            {
                order[i] = postOrder[postCount - 1 - i];
            }
            return order;
        }

        private static int Intersect(int[] idom, int[] rank, int a, int b)
        {
            while (a != b)
            {
                while (rank[a] > rank[b]) a = idom[a];
                while (rank[b] > rank[a]) b = idom[b];
            }
            return a;
        }

        public static bool Dominates(Dictionary<long, long> idom, long a, long b)
        {
            while (a != b)
            {
                if (!idom.TryGetValue(b, out long parent) || parent == b) return false;
                b = parent;
            }
            return true;
        }

        public static int DominatorDepth(Dictionary<long, long> idom, long node)
        {
            int depth = 0;
            while (idom.TryGetValue(node, out long parent) && parent != node)
            {
                node = parent;
                depth++;
            }
            return depth;
        }

        #endregion
    }
}
