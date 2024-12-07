using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using jwt.Token;

namespace jwt;

public class JwtHandler
{
    private const string e1 = "E1: Invalid token structure.";
    public JwtHandler() {

    }

    public bool TryGetValue(string rawToken, [NotNullWhen(true)] out Token.Token? token, [NotNullWhen(false)] out string? error) {
        token = null;
        error = null;

        var splitToken = rawToken.Split(".");
        if (splitToken.Length != 3) {
            error = e1;
            return false;
        }

        var b64UrlHeader = splitToken[0];
        var b64UrlBody = splitToken[1];
        var b64UrlSiganture = splitToken[2];

        var b64Header = ToBase64(b64UrlHeader);
        var b64Body = ToBase64(b64UrlBody);
        var b64Signature = ToBase64(b64UrlSiganture);

        var b64decodedHeader = Convert.FromBase64String(b64Header);
        var b64decodedBody = Convert.FromBase64String(b64Body);

        Header? header = JsonSerializer.Deserialize<Header>(b64decodedHeader);
        Body? body = JsonSerializer.Deserialize<Body>(b64decodedBody);
        var signature = new Signature { RawSignature = b64Signature };

        if (header is null || body is null) {
            error = e1;
            return false;
        }

        token = new Token.Token(header, body, signature);
        return true;
    }

    private static string ToBase64(string b64Url) {
        var b64 = b64Url.Replace('_', '/').Replace('-', '+');
        switch(b64Url.Length % 4) {
            case 2: b64 += "=="; break;
            case 3: b64 += "="; break;
        }
        return b64;
    }
}
