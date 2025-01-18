using FluentAssertions;
using jwt.Options;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace jwt.RFC7519.Test;

/// <summary>
/// Asserts Section 5 JOSE Header
///
/// For a JWT object, the members of the JSON object represented by the JOSE
/// Header describe the cryptographic operations applied to the JWT and
/// optionally, additional properties of the JWT. Depending upon whether the JWT
/// is a JWS or JWE, the corresponding rules for the JOSE Header values apply.
/// This specification further specifies the use of the following Header
/// Parameters in both the cases where the JWT is a JWS and where it is a JWE.
/// </summary>
[TestClass]
public class Section5 {

    /// <summary>
    /// Validates token with optional additional properties.
    /// </summary>
    [TestMethod]
    public void WhenOptionalClaim_ThenSucceeds() {
        // Token with custom header value "custom": "custom"
        const string raw = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImN1c3RvbSI6ImN1c3RvbSJ9.eyJqdGkiOiJpZGVudGlmaWVyIn0.lfx5tkSsJGu2WirOcJczR5_-KP9wRyH8YIOPuq0sE3M";

        new JwtHandler(TestDefaults.DefaultTestOptions).TryGetValue(raw, out var token, out var error).Should().BeTrue();
    }
}

/// <summary>
/// Asserts 5.1 "typ" (Type) Header Parameter
///
/// The "typ" (type) Header Parameter defined by [JWS] and [JWE] is used by JWT
/// applications to declare the media type [IANA.MediaTypes] of this complete
/// JWT. This is intended for use by the JWT application when values that are
/// not JWTs could also be present in an application data structure that can
/// contain a JWT object; the application can use this value to disambiguate
/// among the different kinds of objects that might be present. It will
/// typically not be used by applications when it is already known that the
/// object is a JWT. This parameter is ignored by JWT implementations; any
/// processing of this parameter is performed by the JWT application. If
/// present, it is RECOMMENDED that its value be "JWT" to indicate that this
/// object is a JWT. While media type names are not case sensitive, it is
/// RECOMMENDED that "JWT" always be spelled using uppercase characters for
/// compatibility with legacy implementations. Use of this Header Parameter is
/// OPTIONAL.
/// </summary>
[TestClass]
public class Section5_1 {
    private static JwtHandlerOptions TypeDefaultOptions() {
        var options = TestDefaults.DefaultTestOptions;
        options.TypeOptions.IsTypeValidationEnabled = true;
        return options;
    }

    /// <summary>
    /// Validates typ cliam when string.
    /// </summary>
    [TestMethod]
    [DataRow("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.Et9HFtf9R3GEMA0IICOfFMVXY7kkTX1wr4qCyhIf58U")] // Token with typ == "JWT"
    [DataRow("eyJhbGciOiJIUzI1NiIsInR5cCI6Imp3dCJ9.e30.nEP4O6wiqdVpXQk_dUOtGlTf4-oVZk2IxjIU_jmb4YI")] // Token with typ == "jwt"
    public void WhenTypCliam_ThenSucceeds(string raw) {
        new JwtHandler(TypeDefaultOptions())
            .TryGetValue(raw, out var token, out var error)
            .Should()
            .BeTrue();
    }

    /// <summary>
    /// Does not validate when type is not string.
    /// </summary>
    [TestMethod]
    public void WhenTypCliamIsNotString_ThenFails() {
        // Token with typ == 1
        const string raw = "eyJhbGciOiJIUzI1NiIsInR5cCI6MX0.e30.qCNLZuMtTYtnJXA7vW-UZ0C82XrY3oyITuDkYUrwOrM";

        new JwtHandler(TypeDefaultOptions())
            .TryGetValue(raw, out var token, out var error)
            .Should()
            .BeFalse();
    }

    /// <summary>
    /// Use of typ claim is optional.
    /// </summary>
    [TestMethod]
    public void TypClaimIsOptional() {
        const string raw = "eyJhbGciOiJIUzI1NiJ9.e30.ZRrHA1JJJW8opsbCGfG_HACGpVUMN_a9IV7pAx_Zmeo";

        new JwtHandler(TypeDefaultOptions())
            .TryGetValue(raw, out var token, out var error)
            .Should()
            .BeTrue();
    }
}

/// <summary>
/// Asserts 5.2 "cty" (Content Type) Header Parameter
///
/// The "cty" (content type) Header Parameter defined by [JWS] and [JWE] is used
/// by this specification to convey structural information about the JWT.  In
/// the normal case in which nested signing or encryption operations are not
/// employed, the use of this Header Parameter is NOT RECOMMENDED. In the case
/// that nested signing or encryption is employed, this Header Parameter MUST be
/// present; in this case, the value MUST be "JWT", to indicate that a Nested
/// JWT is carried in this JWT. While media type names are not case sensitive,
/// it is RECOMMENDED that "JWT" always be spelled using uppercase characters
/// for compatibility with legacy implementations. See Appendix A.2 for an
/// example of a Nested JWT.
/// </summary>
[TestClass]
public class Section5_2 {
    private static JwtHandlerOptions ContentTypeDefaultOptions() {
        var options = TestDefaults.DefaultTestOptions;
        options.ContentTypeOptions.IsTypeValidationEnabled = true;
        return options;
    }

    /// <summary>
    /// Validates typ cliam when string.
    /// </summary>
    [TestMethod]
    [DataRow("eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.e30.GxKi0Dr5-irrW1FYSrTzafKQHmQRH9l1QU_oLeQ5fK0")] // Token with cty == "JWT"
    [DataRow("eyJhbGciOiJIUzI1NiIsImN0eSI6Imp3dCJ9.e30.DcQVH3aGXTxtzfxkmeXc-EqUh6_0_qzp6r-V6ErNsh0")] // Token with cty == "jwt"
    public void WhenCtyValidationEnabled_AndClaimIsJwt_ThenSucceeds(string raw) {
        new JwtHandler(ContentTypeDefaultOptions())
            .TryGetValue(raw, out var token, out var error)
            .Should()
            .BeTrue();
    }

    /// <summary>
    /// Validates when the cty claim value is not "JWT" variant, then fails.
    /// </summary>
    [TestMethod]
    [DataRow("eyJhbGciOiJIUzI1NiIsImN0eSI6Ik5TUCJ9.e30.xvd8nLkXb5uBHsB6Ri5hZN0HLSO8JNBUEWRXWucLM5k")] // Token with cty == "NSP"
    public void WhenCtyValidationEnabled_andClaimIsNotJwt_ThenFails(string raw) {
        new JwtHandler(ContentTypeDefaultOptions())
            .TryGetValue(raw, out var token, out var error)
            .Should()
            .BeFalse();
    }

    /// <summary>
    /// Validates when the cty claim is an number, then validation fails.
    /// </summary>
    [TestMethod]
    public void WhenCtyValidationEnabled_AndClaimIsNumber_ThenFails() {
        // Token with cty == 1
        const string raw = "eyJhbGciOiJIUzI1NiIsInR5cCI6MX0.e30.qCNLZuMtTYtnJXA7vW-UZ0C82XrY3oyITuDkYUrwOrM";

        new JwtHandler(ContentTypeDefaultOptions())
            .TryGetValue(raw, out var token, out var error)
            .Should()
            .BeFalse();
    }

    /// <summary>
    /// Validates when the cty claim is not present, then validation passes.
    /// </summary>
    [TestMethod]
    public void WhenCtyValidationEnabled_AndClaimNotPresent_ThenSucceeds() {
        // Token with no cty claim
        const string raw = "eyJhbGciOiJIUzI1NiJ9.e30.ZRrHA1JJJW8opsbCGfG_HACGpVUMN_a9IV7pAx_Zmeo";

        new JwtHandler(ContentTypeDefaultOptions())
            .TryGetValue(raw, out var token, out var error)
            .Should()
            .BeTrue();
    }

    /// <summary>
    /// Use of cty claim is optional.
    /// </summary>
    [TestMethod]
    public void WhenCtyValidationDisabled_AndNoClaimNotPresent_ThenSucceeds() {
        // Token with no cty claim
        const string raw = "eyJhbGciOiJIUzI1NiJ9.e30.ZRrHA1JJJW8opsbCGfG_HACGpVUMN_a9IV7pAx_Zmeo";

        new JwtHandler(TestDefaults.DefaultTestOptions)
            .TryGetValue(raw, out var token, out var error)
            .Should()
            .BeTrue();
    }
}
