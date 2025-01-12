using FluentAssertions;
using jwt.Options;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace jwt.Test;

[TestClass]
public class ExpirationClaimTests {

    /// <summary>
    /// Ensures that tokens are being validated in the most secure manner by
    /// default.
    /// </summary>
    [TestMethod]
    public void ExpirationOptions_AreSecureByDefault() {
        var expirationOptions = new ExpirationOptions();

        expirationOptions.ClockSkew.Should().Be(TimeSpan.Zero);
        expirationOptions.ExpirationRequired.Should().BeTrue();
    }

    [TestMethod]
    public void WhenExpClaimNotPresent_AndExpirationIsRequired_ThenFails() {
        const string raw = "eyJhbGciOiJIUzI1NiJ9.e30.ZRrHA1JJJW8opsbCGfG_HACGpVUMN_a9IV7pAx_Zmeo";

        new JwtHandler(
            new() {
                ExpirationOptions = new() {
                    ExpirationRequired = true,
                }
            })
            .TryGetValue(raw, out var token, out var error)
            .Should()
            .BeFalse();
    }

    [TestMethod]
    public void WhenExpClaimNotPresent_AndExpirationIsNotRequired_ThenFails() {
        const string raw = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.e30.yXvILkvUUCBqAFlAv6wQ1Q-QRAjfe3eSosO949U73Vo";

        new JwtHandler(
            new() {
                AudianceOptions = new() {
                    IsAudianceValidationEnabled = false,
                },
                ExpirationOptions = new() {
                    ExpirationRequired = false,
                }
            })
            .TryGetValue(raw, out var token, out var error)
            .Should()
            .BeTrue();
    }
}