using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace jwt.Test;

[TestClass]
public class RFC7519 {

    /// <summary>
    /// Asserts as per Section 4 of RFC 7159 [RFC7159], the JSON object consists of zero
    /// or more name/value pairs (or members)
    /// </summary>
    [TestMethod]
    public void WhenNoClaims_ThenDoeNotFail() {
        const string raw = "eyJhbGciOiJIUzI1NiJ9.e30.ZRrHA1JJJW8opsbCGfG_HACGpVUMN_a9IV7pAx_Zmeo";

        new JwtHandler().TryGetValue(raw, out var token, out var error).Should().BeTrue();
    }

    /// <summary

    /// <summary>
    /// Asserts Decoding Example JWT.
    /// </summary>
    [TestClass]
    public class ExampleToken {

        [TestMethod]
        public void ShouldDecode() {
            const string raw = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

            new JwtHandler().TryGetValue(raw, out var token, out var error).Should().BeTrue();
            token!.Header.Type.Should().Be("JWT");
            token!.Header.Claims.Should().ContainKey("alg").WhoseValue.GetString().Should().Be("HS256");
            token!.Body.Issuer.Should().Be("joe");
            token!.Body.ExpirationTime.Should().Be(1300819380);
            token!.Body.Claims.Should().ContainKey("http://example.com/is_root").WhoseValue.GetBoolean().Should().Be(true);
        }
    }


    /// <summary>
    /// Asserts the Claim Names within a JWT Claims Set MUST be unique; JWT
    /// parsers MUST either reject JWTs with duplicate Claim Names or use a JSON
    /// parser that returns only the lexically last duplicate member name, as
    /// specified in Section 15.12 ("The JSON Object") of ECMAScript 5.1
    /// [ECMAScript].
    /// </summary>
    /// <remarks>
    /// We choose to use the lexically last duplicate member name.
    /// </remarks>
    [TestClass]
    public class ClaimShouldBeUnique {

        [TestMethod]
        public void ClaimShouldBeUnique_WhenRegisteredClaim() {
            const string raw = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJiZW4iLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.H89eqRwfFp7bcvikINKutpNLf0yRFnoTVw3IiYsohu0";

            new JwtHandler().TryGetValue(raw, out var token, out var error).Should().BeTrue();
            token!.Body.Issuer.Should().Be("ben");
        }

        [TestMethod]
        public void ClaimShouldBeUnique_WhenCustomClaim() {
            const string raw = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlLCJjdXN0b20iOiJiIn0.oFN0PtRCcm9FskADmUxMcwTEYkypv0idZr8aIxDCCrI";

            new JwtHandler().TryGetValue(raw, out var token, out var error).Should().BeTrue();
            token!.Body.Claims.Should().ContainKey("custom").WhoseValue.GetString().Should().Be("b");
        }
    }

    /// <summary>
    /// Asserts as per Section 4 of RFC 7159 [RFC7159], the JSON object consists of zero
    /// or more name/value pairs (or members), where the names are strings and
    /// the values are arbitrary JSON values.
    /// 
    /// Also, Asserts specific applications of JWTs will require implementations
    /// to understand and process some claims in particular ways. However, in
    /// the absence of such requirements, all claims that are not understood by
    /// implementations MUST be ignored.
    /// 
    /// Also, Asserts "iss", "sub", "aud", "exp", "nbf", "iat", "jti" are optional.
    /// </summary>
    [TestMethod]
    public void UnknownClaim_DoesNotFail() {
        const string raw = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJjdXN0b20iOiJqb2UifQ.QEk0Kc-0TWZXlczNULRLPszkB4k5fM1a4AZUVGgQx7U";

        new JwtHandler().TryGetValue(raw, out var token, out var error).Should().BeTrue();
    }


}
