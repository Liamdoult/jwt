using System.Text.Json;
using System.Text.Json.Nodes;
using FluentAssertions;
using jwt.Options;
using jwt.test.utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace jwt.RFC7519.Test;

/// <summary>
/// Asserts 3.1 Example JWT
///
/// The following example JOSE Header declares that the encoded object is a JWT,
/// and the JWT is a JWS that is MACed using the HMAC SHA-256 algorithm:
///
///     {"typ":"JWT", "alg":"HS256"}
///
/// To remove potential ambiguities in the
/// representation of the JSON object above, the octet sequence for the actual
/// UTF-8 representation used in this example for the JOSE Header above is also
/// included below. (Note that ambiguities can arise due to differing platform
/// representations of line breaks (CRLF versus LF), differing spacing at the
/// beginning and ends of lines, whether the last line has a terminating line
/// break or not, and other causes. In the representation used in this example,
/// the first line has no leading or trailing spaces, a CRLF line break (13, 10)
/// occurs between the first and second lines, the second line has one leading
/// space (32) and no trailing spaces, and the last line does not have a
/// terminating line break.) The octets representing the UTF-8 representation of
/// the JOSE Header in this example (using JSON array notation) are:
///
///     [123, 34, 116, 121, 112, 34, 58, 34, 74, 87, 84, 34, 44, 13, 10, 32, 34,
///     97, 108, 103, 34, 58, 34, 72, 83, 50, 53, 54, 34, 125]
///
/// Base64url encoding the octets of the UTF-8 representation of the JOSE Header
/// yields this encoded JOSE Header
/// value:
///
///     eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9
///
/// The following is an example of a JWT Claims Set:
///
///     {"iss":"joe",
///     "exp":1300819380,
///     "http://example.com/is_root":true}
///
/// The following octet sequence, which is
/// the UTF-8 representation used in this example for the JWT Claims Set above,
/// is the JWS Payload:
///
///     [123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10, 32,
///     34, 101, 120, 112, 34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56, 48, 44,
///     13, 10, 32, 34, 104, 116, 116, 112, 58, 47, 47, 101, 120, 97, 109, 112,
///     108, 101, 46, 99, 111, 109, 47, 105, 115, 95, 114, 111, 111, 116, 34,
///     58, 116, 114, 117, 101, 125]
///
/// RFC 7519 JSON Web Token (JWT) May 2015 Base64url encoding the JWS Payload
/// yields this encoded JWS Payload (with line breaks for display purposes
/// only):
///
///     eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ
///
/// Computing the MAC of the encoded JOSE Header and encoded JWS Payload with
/// the HMAC SHA-256 algorithm and base64url encoding the HMAC value in the
/// manner specified in [JWS] yields this encoded JWS Signature:
///
///     dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
///
/// Concatenating these encoded parts in this order with period (’.’) characters
/// between the parts yields this complete JWT (with line breaks for display
/// purposes only):
///
///     eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9 .
///     eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt
///     cGxlLmNvbS9pc19yb290Ijp0cnVlfQ .
///     dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
///
/// This computation is illustrated in more detail in Appendix A.1 of [JWS]. See
/// Appendix A.1 for an example of an encrypted JWT.
/// </summary>
[TestClass]
public class Section3_1 {

    [TestMethod]
    public void ExampleToken_ShouldDecode() {
        const string raw = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        new TokenValidator(
            TestDefaults.DefaultTestOptions,
            clock: new Clock(getCurrentTime: () => 1300819379)
        ).TryGetValue(raw, out var token, out var error).Should().BeTrue();
        token!.Header?.Type.Should().Be("JWT");
        token!.Header?.Algorithm.Should().Be("HS256");
        token!.Body?.Issuer.Should().Be("joe");
        token!.Body?.ExpirationTime.Should().Be(1300819380);
        token!.Body?.Claims.Should().ContainKey("http://example.com/is_root").WhoseValue.As<JsonElement>().GetBoolean().Should().Be(true);
    }

    [TestMethod]
    public void ExampleToken_ShouldEncode() {
        var token = new Token {
            Header = new() {
                Type = "JWT",
                Algorithm = "HS256",
            },
            Body = new() {
                Issuer = "joe",
                ExpirationTime = 1300819380,
                Claims = new() {{ "http://example.com/is_root", true }},
            }
        };

        new TokenIssuer().TryGetValue(token, out var rawToken, out var error).Should().BeTrue();

        // Adjusted example with jwt.io to match claims ordering of this library.
        rawToken.Should().StartWith("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ");
    }
}