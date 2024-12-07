using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Mono.Cecil.Cil;

namespace jwt.Test;

[TestClass]
public class RFC7519 {

    /// <summary>
    /// Asserts that the <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-3.1">sample token</a> is correctly decoded according to the RFC.
    /// </summary>
    [TestMethod]
    public void ExampleToken_ShouldDecode() {
        const string raw = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        new JwtHandler().TryGetValue(raw, out var token, out var error).Should().BeTrue();
        token!.Header.Type.Should().Be("JWT");
        token!.Header.Claims.Should().ContainKey("alg").WhoseValue.GetString().Should().Be("HS256");
        token!.Body.Issuer.Should().Be("joe");
        token!.Body.ExpirationTime.Should().Be(1300819380);
        token!.Body.Claims.Should().ContainKey("http://example.com/is_root").WhoseValue.GetBoolean().Should().Be(true);
    }
}
