using FluentAssertions;
using jwt.Options;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace jwt.RFC7519.Test;

/// <summary>
/// Asserts 6. Unsecured JWTs
///
// To support use cases in which the JWT content is secured by a means other
// than a signature and/or encryption contained within the JWT (such as a
// signature on a data structure containing the JWT), JWTs MAY also be created
// without a signature or encryption. An Unsecured JWT is a JWS using the "alg"
// Header Parameter value "none" and with the empty string for its JWS Signature
// value, as defined in the JWA specification [JWA]; it is an Unsecured JWS with
// the JWT Claims Set as its JWS Payload.
/// </summary>
[TestClass]
public class Section6 {

    public JwtHandlerOptions UnsecuredDefaultOptions() {
        var options = TestDefaults.DefaultTestOptions;
        options.AllowUnsecured = true;
        return options;
    }

    /// <summary>
    /// Validates that an unsecured token without alg set to none fails.
    /// </summary>
    [TestMethod]
    public void WhenUnsecuredAllowed_AndUnsecuredTokenWithAlgNotNone_ThenFails() {
        const string raw = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.";

        new TokenValidator(UnsecuredDefaultOptions())
            .TryGetValue(raw, out var token, out var error)
            .Should()
            .BeFalse();
    }
}

/// <summary>
/// 6.1. Example Unsecured JWT
///
/// The following example JOSE Header declares that the encoded object is an
/// Unsecured JWT:
///
///     {"alg":"none"}
///
/// Base64url encoding the octets of the UTF-8 representation of the JOSE Header
/// yields this encoded JOSE Header value: eyJhbGciOiJub25lIn0 The following is
/// an example of a JWT Claims Set:
///
///     {"iss":"joe",
///      "exp":1300819380,
///      "http://example.com/is_root":true}
///
/// Base64url encoding the octets of the UTF-8 representation of the JWT Claims
/// Set yields this encoded JWS Payload (with line breaks for display purposes
/// only):
///
///     eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt
///     cGxlLmNvbS9pc19yb290Ijp0cnVlfQ
///
/// The encoded JWS Signature is the empty
/// string.
///
/// Concatenating these encoded parts in this order with period (’.’) characters
/// between the parts yields this complete JWT (with line breaks for display
/// purposes only):
///
///     eyJhbGciOiJub25lIn0
///     .
///     eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt
///     cGxlLmNvbS9pc19yb290Ijp0cnVlfQ
///     .
/// </summary>
[TestClass]
public class Section6_1 {

    public JwtHandlerOptions UnsecuredDefaultOptions() {
        var options = TestDefaults.DefaultTestOptions;
        options.AllowUnsecured = true;
        return options;
    }

    /// <summary>
    /// Validates that unsecured token example succeeds.
    /// </summary>
    [TestMethod]
    public void WhenUnsecuredAllowed_AndUnsecured_ThenSucceeds() {
        const string raw = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.";

        new TokenValidator(UnsecuredDefaultOptions())
            .TryGetValue(raw, out var token, out var error)
            .Should()
            .BeTrue();
    }
}