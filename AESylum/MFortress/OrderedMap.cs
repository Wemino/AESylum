using System.Collections;
using System.Diagnostics.CodeAnalysis;

namespace AESylum.MFortress
{
    // Dictionary that keeps insertion order, some of the scan's picks break ties on "first seen"
    internal class OrderedMap<TKey, TValue> : IEnumerable<KeyValuePair<TKey, TValue>> where TKey : notnull
    {
        private readonly Dictionary<TKey, TValue> map = [];
        private readonly List<TKey> order = [];

        public int Count => order.Count;

        public IEnumerable<TKey> Keys => order;

        public TValue this[TKey key]
        {
            get => map[key];
            set
            {
                if (!map.ContainsKey(key)) order.Add(key);
                map[key] = value;
            }
        }

        public bool ContainsKey(TKey key) => map.ContainsKey(key);

        public bool TryGetValue(TKey key, [MaybeNullWhen(false)] out TValue value) => map.TryGetValue(key, out value);

        public TValue SetDefault(TKey key, TValue fallback)
        {
            if (map.TryGetValue(key, out TValue? current)) return current;

            map[key] = fallback;
            order.Add(key);
            return fallback;
        }

        public IEnumerator<KeyValuePair<TKey, TValue>> GetEnumerator()
        {
            foreach (TKey key in order)
            {
                yield return new KeyValuePair<TKey, TValue>(key, map[key]);
            }
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }
}
