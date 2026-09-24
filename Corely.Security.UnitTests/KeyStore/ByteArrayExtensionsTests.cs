using System.Text;
using Corely.Security.KeyStore;

namespace Corely.Security.UnitTests.KeyStore;

public class ByteArrayExtensionsTests
{
    [Theory]
    [InlineData("abc", "abc")]
    [InlineData(" \t\r\nabc\r\n ", "abc")]
    [InlineData("a b", "a b")]
    [InlineData(" \n ", "")]
    [InlineData("", "")]
    public void WithoutSurroundingWhitespace_TrimsOnlyTheEnds(string input, string expected)
    {
        var trimmed = Encoding.UTF8.GetBytes(input).WithoutSurroundingWhitespace();

        Assert.Equal(expected, Encoding.UTF8.GetString(trimmed));
    }

    [Fact]
    public void NonEmptyLineRanges_SplitsOnLfAndCrLf()
    {
        var bytes = Encoding.UTF8.GetBytes("ab\r\ncde\nf");

        Assert.Equal([(0, 2), (4, 3), (8, 1)], bytes.NonEmptyLineRanges());
    }

    [Fact]
    public void NonEmptyLineRanges_SkipsBlankLines()
    {
        var bytes = Encoding.UTF8.GetBytes("\n\r\nab\n\n");

        Assert.Equal([(3, 2)], bytes.NonEmptyLineRanges());
    }

    [Fact]
    public void NonEmptyLineRanges_ReturnsNone_ForEmptyInput()
    {
        Assert.Empty(Array.Empty<byte>().NonEmptyLineRanges());
    }
}
