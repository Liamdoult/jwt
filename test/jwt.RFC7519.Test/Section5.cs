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
    public void IssClaimIsOptional() {
        const string raw = "eyJhbGciOiJIUzI1NiJ9.e30.ZRrHA1JJJW8opsbCGfG_HACGpVUMN_a9IV7pAx_Zmeo";

        new JwtHandler(TypeDefaultOptions())
            .TryGetValue(raw, out var token, out var error)
            .Should()
            .BeTrue();
    }
}
