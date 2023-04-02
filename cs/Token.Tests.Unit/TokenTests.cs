using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Linq;

namespace Semifinals.Utils.Tokens;

[TestClass]
public class TokenTests
{
    public static readonly string TestSecret = "secret";

    [TestMethod]
    public void Epoch()
    {
        // Arrange
        long epoch = 1672531200;

        // Act
        long res = Token.Epoch;

        // Assert
        Assert.AreEqual(epoch, res);
    }

    [TestMethod]
    public void Separator()
    {
        // Arrange
        char separator = '.';

        // Act
        char res = Token.Separator;

        // Assert
        Assert.AreEqual(separator, res);
    }

    [TestMethod]
    public void Generate()
    {
        // Arrange
        string id = "test";

        // Act
        string res = Token.Generate(id, TestSecret);

        // Assert
        string resId = Token.GetId(res)!;
        long resTimestamp = (long)Token.GetTimestamp(res)!;
        string resSignature = Token.GetSignature(res)!;
        Assert.AreEqual(id, resId);

        string payload = Token.Payload(resId, resTimestamp);
        string signature = Token.Sign(payload, TestSecret);
        Assert.AreEqual(resSignature, signature);
    }

    [TestMethod]
    [DataRow("id", (1672531200L + 1) * 1000, "aWQ=.MQ==")]
    [DataRow("test", (1672531200L + 86400) * 1000, "dGVzdA==.ODY0MDA=")]
    [DataRow("working", (1672531200L + 1234567890) * 1000, "d29ya2luZw==.MTIzNDU2Nzg5MA==")]
    public void Payload(string id, long timestamp, string expected)
    {
        // Arrange

        // Act
        string res = Token.Payload(id, timestamp);

        // Assert
        Assert.AreEqual(expected, res);
    }

    [TestMethod]
    [DataRow("aWQ=.MQ==", "PNvHPV1cdk47r68wzAugWGeHfjNZOa6Su+7qj67U8ok=")]
    [DataRow("dGVzdA==.ODY0MDA=", "iNsbhu5s1rdoPT960fY0Bu7sQAaaP2ysD3RJS9DQUmg=")]
    [DataRow("d29ya2luZw==.MTIzNDU2Nzg5MA==", "YHdIO9UBOvAO7cTrKLJdRvE9FVuGCCVvI6bCZvtCuWE=")]
    public void Sign(string payload, string expected)
    {
        // Arrange

        // Act
        string res = Token.Sign(payload, TestSecret);

        // Assert
        Assert.AreEqual(expected, res);
    }

    [TestMethod]
    [DataRow("aWQ=.MQ==.PNvHPV1cdk47r68wzAugWGeHfjNZOa6Su+7qj67U8ok=", true)]
    [DataRow("dGVzdA==.ODY0MDA=.iNsbhu5s1rdoPT960fY0Bu7sQAaaP2ysD3RJS9DQUmg=", true)]
    [DataRow("d29ya2luZw==.MTIzNDU2Nzg5MA==.YHdIO9UBOvAO7cTrKLJdRvE9FVuGCCVvI6bCZvtCuWE=", true)]
    [DataRow(".invalid.invalid", false)]
    [DataRow("invalid..invalid", false)]
    [DataRow("..", false)]
    [DataRow("", false)]
    public void Validate(string token, bool expected)
    {
        // Arrange

        // Act
        bool res = Token.Validate(token);

        // Assert
        Assert.AreEqual(expected, res);
    }

    [TestMethod]
    [DataRow("aWQ=.MQ==.PNvHPV1cdk47r68wzAugWGeHfjNZOa6Su+7qj67U8ok=", true)]
    [DataRow("dGVzdA==.ODY0MDA=.iNsbhu5s1rdoPT960fY0Bu7sQAaaP2ysD3RJS9DQUmg=", true)]
    [DataRow("d29ya2luZw==.MTIzNDU2Nzg5MA==.YHdIO9UBOvAO7cTrKLJdRvE9FVuGCCVvI6bCZvtCuWE=", true)]
    [DataRow(".invalid.invalid", false)]
    [DataRow("invalid..invalid", false)]
    [DataRow("..", false)]
    [DataRow("", false)]
    public void Verify(string token, bool expected)
    {
        // Arrange

        // Act
        bool res = Token.Verify(token, TestSecret);

        // Assert
        Assert.AreEqual(expected, res);
    }

    [TestMethod]
    [DataRow("MQ==.MQ==.MQ==", "1")]
    [DataRow("ODY0MDA=.ODY0MDA=.ODY0MDA=", "86400")]
    [DataRow("dGVzdA==.invalid", null)]
    [DataRow("dGVzdA==", null)]
    [DataRow("", null)]
    public void GetId(string str, string? expected)
    {
        // Arrange

        // Act
        string? res = Token.GetId(str);

        // Assert
        Assert.AreEqual(expected, res);
    }

    [TestMethod]
    [DataRow("ODY0MDA=.ODY0MDA=.ODY0MDA=", (1672531200L + 86400) * 1000)]
    [DataRow("MQ==.MQ==.MQ==", (1672531200L + 1) * 1000)]
    [DataRow("no.MQ==", null)]
    [DataRow("fail", null)]
    [DataRow("", null)]
    public void GetTimestamp(string str, long? expected)
    {
        // Arrange

        // Act
        long? res = Token.GetTimestamp(str);

        // Assert
        Assert.AreEqual(expected, res);
    }

    [TestMethod]
    [DataRow("ODY0MDA=.ODY0MDA=.valid", "valid")]
    [DataRow("this.isnt", null)]
    [DataRow("", null)]
    public void GetSignature(string str, string? expected)
    {
        // Arrange

        // Act
        string? res = Token.GetSignature(str);

        // Assert
        Assert.AreEqual(expected, res);
    }

    [TestMethod]
    [DataRow(new string[] { "this.has.dots", "this", "has", "dots" })]
    [DataRow(new string[] { "this.also.has.dots", "this", "also", "has", "dots" })]
    [DataRow(new string[] { "!@#.$%^", "!@#", "$%^" })]
    [DataRow(new string[] { "nodots", "nodots" })]
    [DataRow(new string[] { "..", "", "", "" })]
    [DataRow(new string[] { "", "" })]
    public void Split(string[] values)
    {
        // Arrange
        string str = values[0];
        string[] expected = values.Skip(1).ToArray();

        // Act
        string[] res = Token.Split(str);

        // Assert
        bool match = true;
        for (int i = 0; i < res.Length; i++)
            if (res[i] != expected[i])
                match = false;

        Assert.IsTrue(match);
    }

    [TestMethod]
    [DataRow("decoded!", "ZGVjb2RlZCE=")]
    [DataRow("abcdef123456", "YWJjZGVmMTIzNDU2")]
    [DataRow("!@#$%^&*()_", "IUAjJCVeJiooKV8=")]
    [DataRow("", "")]
    public void ToBase64(string utf8, string expected)
    {
        // Arrange

        // Act
        string res = Token.ToBase64(utf8);

        // Assert
        Assert.AreEqual(expected, res);
    }

    [TestMethod]
    [DataRow("ZGVjb2RlZCE=", "decoded!")]
    [DataRow("YWJjZGVmMTIzNDU2", "abcdef123456")]
    [DataRow("IUAjJCVeJiooKV8=", "!@#$%^&*()_")]
    [DataRow("", "")]
    public void ToUtf8(string base64, string expected)
    {
        // Arrange

        // Act
        string res = Token.ToUtf8(base64);

        // Assert
        Assert.AreEqual(expected, res);
    }
}