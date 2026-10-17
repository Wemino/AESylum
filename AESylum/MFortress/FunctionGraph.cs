namespace AESylum.MFortress
{
    // control-flow graph of a single function, Exit (-1) stands for anything leaving it
    internal class FunctionGraph(long entry, long end)
    {
        public const long Exit = -1;

        public long Entry = entry;
        public long End = end;
        public long CodeLow;
        public long CodeHigh;
        public OrderedMap<long, Instruction> Nodes = new();
        public Dictionary<long, List<(long Target, string Kind)>> Edges = new();
        public OrderedMap<long, (long Taken, long Next)> Branches = new();
        public List<long> Sinks = new();

        // built on demand, dropped whenever an edge is added
        private Dictionary<long, List<long>>? predecessors;
        private GraphIndex? index;
        private long[]? sorted;

        public bool InRange(long target) => Entry <= target && target < End;

        public void AddEdge(long from, long target, string kind)
        {
            if (!Edges.TryGetValue(from, out List<(long Target, string Kind)>? list))
            {
                list = [];
                Edges[from] = list;
            }

            if (list.Contains((target, kind))) return;

            list.Add((target, kind));
            predecessors = null;
            index = null;
        }

        public IEnumerable<long> Successors(long from)
        {
            if (!Edges.TryGetValue(from, out List<(long Target, string Kind)>? list)) yield break;

            foreach ((long target, string _) in list)
            {
                yield return target;
            }
        }

        public Dictionary<long, List<long>> Predecessors()
        {
            if (predecessors != null) return predecessors;

            predecessors = [];
            foreach (KeyValuePair<long, List<(long Target, string Kind)>> entry in Edges)
            {
                foreach ((long target, string _) in entry.Value)
                {
                    if (target == Exit) continue;

                    if (!predecessors.TryGetValue(target, out List<long>? list))
                    {
                        list = [];
                        predecessors[target] = list;
                    }
                    list.Add(entry.Key);
                }
            }
            return predecessors;
        }

        public GraphIndex Index() => index ??= new GraphIndex(this);

        public long[] SortedAddresses()
        {
            if (sorted == null || sorted.Length != Nodes.Count)
            {
                sorted = Nodes.Keys.ToArray();
                Array.Sort(sorted);
            }
            return sorted;
        }
    }

    // same graph with int ids, so the reachability walks don't have to hash anything
    internal class GraphIndex
    {
        private readonly Dictionary<long, int> ids = new();
        private readonly long[] addresses;
        private readonly bool[] isNode;
        private readonly int[][] successors;
        private readonly int[] stamp;
        private int generation;

        public readonly int Exit;
        public readonly int[] Stack;

        public GraphIndex(FunctionGraph graph)
        {
            foreach (long address in graph.Nodes.Keys)
            {
                ids[address] = ids.Count;
            }

            foreach (List<(long Target, string Kind)> list in graph.Edges.Values)
            {
                foreach ((long target, string _) in list)
                {
                    if (!ids.ContainsKey(target)) ids[target] = ids.Count;
                }
            }

            if (!ids.ContainsKey(FunctionGraph.Exit)) ids[FunctionGraph.Exit] = ids.Count;
            Exit = ids[FunctionGraph.Exit];

            int total = ids.Count;
            addresses = new long[total];
            foreach (KeyValuePair<long, int> pair in ids)
            {
                addresses[pair.Value] = pair.Key;
            }

            isNode = new bool[total];
            successors = new int[total][];
            foreach (long address in graph.Nodes.Keys)
            {
                int node = ids[address];
                isNode[node] = true;
                if (!graph.Edges.TryGetValue(address, out List<(long Target, string Kind)>? list)) continue;

                int[] targets = new int[list.Count];
                for (int i = 0; i < targets.Length; i++)
                {
                    targets[i] = ids[list[i].Target];
                }
                successors[node] = targets;
            }

            stamp = new int[total];
            Stack = new int[Math.Max(16, graph.Edges.Values.Sum(list => list.Count) + 2)];
        }

        public int NodeSlots => isNode.Length;

        public bool TryGetIndex(long address, out int index) => ids.TryGetValue(address, out index);

        public long AddressOf(int index) => addresses[index];

        public bool IsNode(int index) => isNode[index];

        public int[] SuccessorsOf(int index) => successors[index] ?? [];

        public int NewVisit() => ++generation;

        public bool Seen(int index, int visit) => stamp[index] == visit;

        public void MarkSeen(int index, int visit) => stamp[index] = visit;
    }

    // constant-time dominance queries over an idom map, same answers as ControlFlow.Dominates
    internal class DominatorTree
    {
        private readonly Dictionary<long, (int In, int Out)> intervals = new();

        public DominatorTree(Dictionary<long, long> idom, long entry)
        {
            Dictionary<long, List<long>> children = new();
            foreach (KeyValuePair<long, long> pair in idom)
            {
                if (pair.Key == pair.Value) continue;

                if (!children.TryGetValue(pair.Value, out List<long>? list))
                {
                    list = new();
                    children[pair.Value] = list;
                }
                list.Add(pair.Key);
            }

            int clock = 0;
            Dictionary<long, int> entered = new();
            Stack<(long Node, bool Done)> work = new();
            work.Push((entry, false));
            while (work.Count > 0)
            {
                (long node, bool done) = work.Pop();
                if (done)
                {
                    intervals[node] = (entered[node], clock++);
                    continue;
                }

                entered[node] = clock++;
                work.Push((node, true));
                if (!children.TryGetValue(node, out List<long>? list)) continue;

                foreach (long child in list)
                {
                    work.Push((child, false));
                }
            }
        }

        public bool Dominates(long a, long b)
        {
            if (a == b) return true;

            return intervals.TryGetValue(a, out (int In, int Out) first)
                && intervals.TryGetValue(b, out (int In, int Out) second)
                && first.In <= second.In && second.Out <= first.Out;
        }
    }
}
