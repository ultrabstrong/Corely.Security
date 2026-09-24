namespace Corely.Security.KeyStore;

internal static class ByteArrayExtensions
{
    extension(byte[] bytes)
    {
        public ReadOnlySpan<byte> WithoutSurroundingWhitespace()
        {
            int start = 0,
                end = bytes.Length;
            while (start < end && IsWhitespace(bytes[start]))
                start++;
            while (end > start && IsWhitespace(bytes[end - 1]))
                end--;
            return bytes.AsSpan(start, end - start);
        }

        public List<(int Start, int Length)> NonEmptyLineRanges()
        {
            List<(int, int)> lines = [];
            var start = 0;
            for (var i = 0; i <= bytes.Length; i++)
            {
                if (i == bytes.Length || bytes[i] == (byte)'\n')
                {
                    var end = i;
                    if (end > start && bytes[end - 1] == (byte)'\r')
                        end--;
                    if (end > start)
                        lines.Add((start, end - start));
                    start = i + 1;
                }
            }
            return lines;
        }
    }

    private static bool IsWhitespace(byte b) => b is 0x20 or 0x09 or 0x0A or 0x0D;
}
