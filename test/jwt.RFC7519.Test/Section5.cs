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
