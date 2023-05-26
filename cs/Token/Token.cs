using System.Security.Cryptography;
using System.Text;

namespace Semifinals.Utils.Tokens;

public class Token
{
    /// <summary>
    /// The Semifinals Authentication Token epoch time (1st January 2023) in seconds.
    /// </summary>
    public static readonly long Epoch = ((DateTimeOffset)new DateTime(2023, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc)).ToUnixTimeSeconds();

    /// <summary>
    /// The separator used to partition the token.
    /// </summary>
    public static readonly char Separator = '.';

    /// <summary>
    /// Generate a token for the given ID.
    /// </summary>
    /// <param name="id">The ID for the token</param>
    /// <param name="secret">The secret used for the sha256 algorithm</param>
    /// <returns>The generated token</returns>
    public static string Generate(string id, string secret)
    {
        long timestamp = ((DateTimeOffset)DateTime.UtcNow).ToUnixTimeMilliseconds();

        string payload = Payload(id, timestamp);
        string signature = Sign(payload, secret);

        return payload + Separator + signature;
    }

    /// <summary>
    /// Generate a payload using the given ID and timestamp.
    /// </summary>
    /// <param name="id">The ID for the token</param>
    /// <param name="timestamp">The timestamp for the token</param>
    /// <returns>The resulting payload</returns>
    public static string Payload(string id, long timestamp)
    {
        string encodedId = ToBase64(id);
        string encodedTimestamp = ToBase64((timestamp / 1000 - Epoch).ToString());

        return encodedId + Separator + encodedTimestamp;
    }

    /// <summary>
    /// Generate a signature for the given payload.
    /// </summary>
    /// <param name="payload">The payload to sign</param>
    /// <param name="secret">The secret used for the sha256 algorithm</param>
    /// <returns>The generated signature</returns>
    public static string Sign(string payload, string secret)
    {
        byte[] payloadBytes = Encoding.UTF8.GetBytes(payload);

        byte[] secretBytes = Encoding.UTF8.GetBytes(secret);

        using HMACSHA256 hmac = new(secretBytes);
        byte[] signatureBytes = hmac.ComputeHash(payloadBytes);

        string signature = Convert.ToBase64String(signatureBytes);
        return signature;
    }

    /// <summary>
    /// Validate that the token looks correct in structure.
    /// </summary>
    /// <param name="token">The token to validate</param>
    /// <returns>Whether or not the token is valid</returns>
    public static bool Validate(string token)
    {
        string[] parts = Split(token);
        if (parts.Length != 3)
            return false;

        string id = ToUtf8(parts[0]);
        if (id.Length == 0)
            return false;

        string unparsedTimestamp = ToUtf8(parts[1]);
        if (unparsedTimestamp.Length == 0)
            return false;

        if (!long.TryParse(unparsedTimestamp, out long _))
            return false;

        string signature = parts[2];
        if (signature.Length == 0)
            return false;

        return true;
    }

    /// <summary>
    /// Verify that the signature of the token is authentic.
    /// </summary>
    /// <param name="token">The full token</param>
    /// <param name="secret">The secret used for the sha256 algorithm</param>
    /// <returns>Whether or not the token was verified to be authentic</returns>
    public static bool Verify(string token, string secret)
    {
        if (!Validate(token))
            return false;

        string? id = GetId(token);
        long? timestamp = GetTimestamp(token);
        string? signature = GetSignature(token);

        if (id is null || timestamp is null || signature is null)
            return false;

        string payload = Payload(id, (long)timestamp);
        string generatedSignature = Sign(payload, secret);

        return signature == generatedSignature;
    }

    /// <summary>
    /// Get the ID of the token.
    /// </summary>
    /// <param name="token">The full token</param>
    /// <returns>The ID of the token</returns>
    public static string? GetId(string token)
    {
        if (!Validate(token))
            return null;

        string[] parts = Split(token);
        string id = ToUtf8(parts[0]);

        return id;
    }

    /// <summary>
    /// Get the unix epoch timestamp of the token.
    /// </summary>
    /// <param name="token">The full token</param>
    /// <returns>The Semifinals epoch timestamp of the token in milliseconds</returns>
    public static long? GetTimestamp(string token)
    {
        if (!Validate(token))
            return null;

        string[] parts = Split(token);
        
        if (!long.TryParse(ToUtf8(parts[1]), out long timestamp))
            return null;
            

        return (Epoch + timestamp) * 1000;
    }

    /// <summary>
    /// Get the signature from a token.
    /// </summary>
    /// <param name="token">The full token</param>
    /// <returns>The token's signature</returns>
    public static string? GetSignature(string token)
    {
        if (!Validate(token))
            return null;

        string[] parts = Split(token);
        string signature = parts[2];

        return signature;
    }

    /// <summary>
    /// Split a string into parts by the token separator.
    /// </summary>
    /// <param name="str">The string to split</param>
    /// <returns>The string split into its parts</returns>
    public static string[] Split(string str)
    {
        return str.Split(Separator);
    }

    /// <summary>
    /// Convert a utf8 string into base64
    /// </summary>
    /// <param name="str">The utf8 string</param>
    /// <returns>The string converted to base64</returns>
    public static string ToBase64(string str)
    {
        try
        {
            byte[] bytes = Encoding.UTF8.GetBytes(str);
            return Convert.ToBase64String(bytes);
        }
        catch (FormatException)
        {
            return "";
        }
    }

    /// <summary>
    /// Convert a base64 string into utf8.
    /// </summary>
    /// <param name="str">The base64 string</param>
    /// <returns>The string converted to utf8</returns>
    public static string ToUtf8(string str)
    {
        try
        {
            byte[] bytes = Convert.FromBase64String(str);
            return Encoding.UTF8.GetString(bytes);
        }
        catch (FormatException)
        {
            return "";
        }
    }
}