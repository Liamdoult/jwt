﻿using FluentAssertions;
using jwt.Options;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace jwt.RFC7519.Test;

public static class TestDefaults {
    public static JwtHandlerOptions DefaultTestOptions => new() {
        ExpirationOptions = new() {
            ExpirationRequired = false,
        },
        AudianceOptions = new() {
            IsAudianceValidationEnabled = false,
        }
    };
}

[TestClass]
public class RFC7519 {
    /// <summary>
    /// Asserts as per Section 4 of RFC 7159 [RFC7159], the JSON object consists of zero
    /// or more name/value pairs (or members)
    /// </summary>
    [TestMethod]
    public void WhenNoClaims_ThenDoeNotFail() {
        const string raw = "eyJhbGciOiJIUzI1NiJ9.e30.ZRrHA1JJJW8opsbCGfG_HACGpVUMN_a9IV7pAx_Zmeo";

        new JwtHandler(TestDefaults.DefaultTestOptions).TryGetValue(raw, out var token, out var error).Should().BeTrue();
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

            new JwtHandler(
                TestDefaults.DefaultTestOptions,
                clock: new Clock(getCurrentTime: () => 1300819379)
            ).TryGetValue(raw, out var token, out var error).Should().BeTrue();
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
            const string raw = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJiZW4iLCJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZX0.pKBFZvgZzz1HKAmBNapgM4SDDo53zekCcs6cIM7sVxQ";

            new JwtHandler(TestDefaults.DefaultTestOptions).TryGetValue(raw, out var token, out var error).Should().BeTrue();
            token!.Body.Issuer.Should().Be("ben");
        }

        [TestMethod]
        public void ClaimShouldBeUnique_WhenCustomClaim() {
            const string raw = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLCJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZSwiY3VzdG9tIjoiYiJ9.M6ZXKV11MZ5-cXmPJ6vipk9DH-VD6JUJaXfMc-4KHh0";

            new JwtHandler(TestDefaults.DefaultTestOptions).TryGetValue(raw, out var token, out var error).Should().BeTrue();
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

        new JwtHandler(TestDefaults.DefaultTestOptions).TryGetValue(raw, out var token, out var error).Should().BeTrue();
    }
}

/// <summary>
/// Asserts 4.1.1 "iss" (Issuer) Claim
///
/// The "iss" (issuer) claim identifies the principal that issued the JWT. The
/// processing of this claim is generally application specific.  The "iss" value
/// is a case-sensitive string containing a StringOrURI value. Use of this claim
/// is OPTIONAL.
/// </summary>
[TestClass]
public class Section4_1_1 {

    /// <summary>
    /// Validates Iss claim with string value.
    /// </summary>
    [TestMethod]
    public void WhenIsIssIsString_ThenSucceeds() {
        const string raw = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ0ZXN0LWlzc3VlciJ9.3leULaLh04_dzbdcVZKfmWWkYZQcGSK3E_yUIJw16PM";

        new JwtHandler(TestDefaults.DefaultTestOptions)
            .TryGetValue(raw, out var token, out var error)
            .Should()
            .BeTrue();
    }

    /// <summary>
    /// Validates Iss claim with URI value.
    /// </summary>
    [TestMethod]
    public void WhenIsIssIsUri_ThenSucceeds() {
        const string raw = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci50b2tlbnMuY29tLyJ9.PReUHD0W6L8wguLyhhNuYdfwPNjnD8JJ2LMiGjLDYaY";

        new JwtHandler(TestDefaults.DefaultTestOptions)
            .TryGetValue(raw, out var token, out var error)
            .Should()
            .BeTrue();
    }

    /// <summary>
    /// Validates Iss claim with number value.
    /// </summary>
    [TestMethod]
    public void WhenIsIssIsNumber_ThenFails() {
        const string raw = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOjEyMzR9.3H9GB9WVri4r3VtcgiipPCewk9nL6ZJWQTbNrHLnmpk";

        new JwtHandler(TestDefaults.DefaultTestOptions)
            .TryGetValue(raw, out var token, out var error)
            .Should()
            .BeFalse();
    }

    /// <summary>
    /// Use of iss claim is optional.
    /// </summary>
    [TestMethod]
    public void IssClaimIsOptional() {
        const string raw = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.e30.yXvILkvUUCBqAFlAv6wQ1Q-QRAjfe3eSosO949U73Vo";

        new JwtHandler(TestDefaults.DefaultTestOptions)
            .TryGetValue(raw, out var token, out var error)
            .Should()
            .BeTrue();
    }
}

/// <summary>
/// Asserts 4.1.2 "sub" (Subject) Claim
///
/// The "sub" (subject) claim identifies the principal that is the
/// subject of the JWT. The claims in a JWT are normally statements
/// about the subject. The subject value MUST either be scoped to be
/// locally unique in the context of the issuer or be globally unique.
/// The processing of this claim is generally application specific. The
/// "sub" value is a case-sensitive string containing a StringOrURI
/// value. Use of this claim is OPTIONAL.
/// </summary>
[TestClass]
public class Section4_1_2 {

    /// <summary>
    /// Validates Sub claim with string value.
    /// </summary>
    [TestMethod]
    public void WhenIsSubIsString_ThenSucceeds() {
        const string raw = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0LXN1YmplY3QifQ.UMwEygB84qFqmpBMua-SotBRnpPC_yc3u-HousT0UUQ";

        new JwtHandler(TestDefaults.DefaultTestOptions)
            .TryGetValue(raw, out var token, out var error)
            .Should()
            .BeTrue();
    }

    /// <summary>
    /// Validates Sub claim with URI value.
    /// </summary>
    [TestMethod]
    public void WhenIsSubIsUri_ThenSucceeds() {
        const string raw = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJodHRwczovL3N1Yi5pZGVudGl0eS5jb20vIn0.A-9bulUaIUaB28YZNF780zy2ZSFrJ2A6kQuXmkIRu-s";

        new JwtHandler(TestDefaults.DefaultTestOptions)
            .TryGetValue(raw, out var token, out var error)
            .Should()
            .BeTrue();
    }

    /// <summary>
    /// Validates Sub claim with number value.
    /// </summary>
    [TestMethod]
    public void WhenIsSubIsNumber_ThenFails() {
        const string raw = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOjEyMzR9.VF1APcw202nOG136b30o9rmfgjH9rw97loAuF13bUeY";

        new JwtHandler(TestDefaults.DefaultTestOptions)
            .TryGetValue(raw, out var token, out var error)
            .Should()
            .BeFalse();
    }

    /// <summary>
    /// Use of Sub claim is optional.
    /// </summary>
    [TestMethod]
    public void SubClaimIsOptional() {
        const string raw = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.e30.yXvILkvUUCBqAFlAv6wQ1Q-QRAjfe3eSosO949U73Vo";

        new JwtHandler(TestDefaults.DefaultTestOptions)
            .TryGetValue(raw, out var token, out var error)
            .Should()
            .BeTrue();
    }
}

/// <summary>
/// Asserts 4.1.3 "sub" (Subject) Claim
///
/// The "aud" (audience) claim identifies the recipients that the JWT is
/// intended for. Each principal intended to process the JWT MUST identify
/// itself with a value in the audience claim. If the principal processing the
/// claim does not identify itself with a value in the "aud" claim when this
/// claim is present, then the JWT MUST be rejected. In the general case, the
/// "aud" value is an array of case- sensitive strings, each containing a
/// StringOrURI value. In the special case when the JWT has one audience, the
/// "aud" value MAY be a single case-sensitive string containing a StringOrURI
/// value. The interpretation of audience values is generally application
/// specific.  Use of this claim is OPTIONAL.
/// </summary>
[TestClass]
public class Section4_1_3 {

    /// <summary>
    /// Validates Aud claim with string value.
    /// </summary>
    [TestMethod]
    public void WhenIsAudIsString_ThenSucceeds() {
        const string raw = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJ0ZXN0LWF1ZGlhbmNlIn0.rAhIq2WL933BXimaK5NtgwREKwqL6wCs5a0kXsXdg3g";

        var options = TestDefaults.DefaultTestOptions;
        options.AudianceOptions.IsAudianceValidationEnabled = true;
        options.AudianceOptions.PrincipalAudiance = "test-audiance";

        new JwtHandler(options)
            .TryGetValue(raw, out var token, out var error)
            .Should()
            .BeTrue();
    }

    /// <summary>
    /// Validates Aud claim with URI value.
    /// </summary>
    [TestMethod]
    public void WhenIsAudIsUri_ThenSucceeds() {
        const string raw = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJodHRwczovL2F1ZGlhbmNlLmlkZW50aXR5LmNvbSJ9.A-F4C2PhbvCcmzcnqySbk_tW9q-l7S81O_d8ZVy_mEk";

        var options = TestDefaults.DefaultTestOptions;
        options.AudianceOptions.IsAudianceValidationEnabled = true;
        options.AudianceOptions.PrincipalAudiance = "https://audiance.identity.com";

        new JwtHandler(options)
            .TryGetValue(raw, out var token, out var error)
            .Should()
            .BeTrue();
    }

    /// <summary>
    /// Validates Sub claim with number value.
    /// </summary>
    [TestMethod]
    public void WhenIsAudIsNumber_ThenFails() {
        const string raw = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOjEyMzR9.lK-d4VMUvNCErEJfLlbRlGky_L_VxVkQvY-mLO9hidw";

        var options = TestDefaults.DefaultTestOptions;
        options.AudianceOptions.IsAudianceValidationEnabled = true;

        new JwtHandler(TestDefaults.DefaultTestOptions)
            .TryGetValue(raw, out var token, out var error)
            .Should()
            .BeFalse();
    }

    /// <summary>
    /// Validates Aud claim with List of string and URI values.
    /// </summary>
    [TestMethod]
    public void WhenIsAudIsList_WithStringAndUri_ThenSucceeds() {
        const string raw = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOlsidGVzdC1hdWRpYW5jZSIsImh0dHBzOi8vYXVkaWFuY2UuaWRlbnRpdHkuY29tIl19.1N4c2BvguKhRzYG08HN1z8XI5_SClDuQqMx5I5gGCv4";

        var options = TestDefaults.DefaultTestOptions;
        options.AudianceOptions.IsAudianceValidationEnabled = true;
        options.AudianceOptions.PrincipalAudiance = "test-audiance";

        new JwtHandler(options)
            .TryGetValue(raw, out var token, out var error)
            .Should()
            .BeTrue();
    }

    /// <summary>
    /// Validates Aud claim with List of string and URI values.
    /// </summary>
    [TestMethod]
    public void WhenIsAudIsList_WithNumberValue_ThenFails() {
        // Token aud value `[1234]`
        const string raw = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOlsxMjM0XX0.CigHsjXWqGbzZilbVMGZqnqN25Wi2AczTlWWCg8qrsw";

        var options = TestDefaults.DefaultTestOptions;
        options.AudianceOptions.IsAudianceValidationEnabled = true;

        new JwtHandler(options)
            .TryGetValue(raw, out var token, out var error)
            .Should()
            .BeFalse();
    }

    /// <summary>
    /// Ensure that if the principal is not present in the audiance then the
    /// token is rejected.
    /// </summary>
    [TestMethod]
    public void IfPrincipalIsPresentInAud_ThenSucceeds() {
        const string raw = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOlsidGVzdC1hdWRpYW5jZSIsImh0dHBzOi8vYXVkaWFuY2UuaWRlbnRpdHkuY29tIl19.1N4c2BvguKhRzYG08HN1z8XI5_SClDuQqMx5I5gGCv4";

        var options = TestDefaults.DefaultTestOptions;
        options.AudianceOptions.IsAudianceValidationEnabled = true;
        options.AudianceOptions.PrincipalAudiance = "test-audiance";

        new JwtHandler(options)
            .TryGetValue(raw, out var token, out var error)
            .Should()
            .BeTrue();
    }

    /// <summary>
    /// Ensure that if the principal is not present in the audiance then the
    /// token is rejected.
    /// </summary>
    [TestMethod]
    public void IfPrincipalIsNotPresentInAud_ThenFails() {
        const string raw = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOlsidGVzdC1hdWRpYW5jZSIsImh0dHBzOi8vYXVkaWFuY2UuaWRlbnRpdHkuY29tIl19.1N4c2BvguKhRzYG08HN1z8XI5_SClDuQqMx5I5gGCv4";

        var options = TestDefaults.DefaultTestOptions;
        options.AudianceOptions.IsAudianceValidationEnabled = true;
        options.AudianceOptions.PrincipalAudiance = "different-principal";

        new JwtHandler(options)
            .TryGetValue(raw, out var token, out var error)
            .Should()
            .BeFalse();
    }

    /// <summary>
    /// Use of Aud claim is optional.
    /// </summary>
    [TestMethod]
    public void AudClaimIsOptional() {
        const string raw = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.e30.yXvILkvUUCBqAFlAv6wQ1Q-QRAjfe3eSosO949U73Vo";

        new JwtHandler(TestDefaults.DefaultTestOptions)
            .TryGetValue(raw, out var token, out var error)
            .Should()
            .BeTrue();
    }
}

/// <summary>
/// Asserts 4.1.4 "exp" (Expiration Time) Claim.
///
/// The "exp" (expiration time) claim identifies the expiration time on or
/// after which the JWT MUST NOT be accepted for processing. The processing
/// of the "exp" claim requires that the current date/time MUST be before
/// the expiration date/time listed in the "exp" claim.
/// </summary>
[TestClass]
public class Section4_1_4 {

    /// <summary>
    /// Validates time exactly on expiration is invalid.
    /// </summary>
    [TestMethod]
    public void WhenTimeIsSameAsExp_ThenValidationFails() {
        // Token with exp set to 1736691481
        const string raw = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3MzY2OTE0ODF9.w_5MK3o_6rqJpH8Fl0q9WdSZEs413a2tS_j2Ly0XlH0";

        new JwtHandler(
            clock: new Clock(getCurrentTime: () => 1736691481)
        ).TryGetValue(raw, out var token, out var error).Should().BeFalse();
        error.Should().Be(Errors.TokenExpired);
    }

    /// <summary>
    /// Validates any time after expiration is invalid.
    /// </summary>
    [TestMethod]
    public void WhenTimeIsAfterExp_ThenValidationFails() {
        // Token with exp set to 1736691481
        const string raw = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3MzY2OTE0ODF9.w_5MK3o_6rqJpH8Fl0q9WdSZEs413a2tS_j2Ly0XlH0";

        new JwtHandler(
            clock: new Clock(getCurrentTime: () => 1736691482)
        ).TryGetValue(raw, out var token, out var error).Should().BeFalse();
        error.Should().Be(Errors.TokenExpired);
    }

    /// <summary>
    /// Validates any time before expiration is valid.
    /// </summary>
    [TestMethod]
    public void WhenTimeIsBeforeExp_ThenValidationSucceeds() {
        // Token with exp set to 1736691481
        const string raw = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3MzY2OTE0ODF9.w_5MK3o_6rqJpH8Fl0q9WdSZEs413a2tS_j2Ly0XlH0";

        new JwtHandler(
            TestDefaults.DefaultTestOptions,
            clock: new Clock(getCurrentTime: () => 1736691480)
        ).TryGetValue(raw, out var token, out var error).Should().BeTrue();
    }

    /// <summary>
    /// Validates time exactly on the expiration+clockskew is invalid.
    /// </summary>
    [TestMethod]
    public void WhenTimeAndClockSkewIsSameAsExp_ThenValidationFails() {
        // Token with exp set to 1736691481
        const string raw = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3MzY2OTE0ODF9.w_5MK3o_6rqJpH8Fl0q9WdSZEs413a2tS_j2Ly0XlH0";

        new JwtHandler(
            TestDefaults.DefaultTestOptions,
            clock: new Clock(clockSkew: TimeSpan.FromSeconds(5), getCurrentTime: () => 1736691481 - 5)
        ).TryGetValue(raw, out var token, out var error).Should().BeFalse();
        error.Should().Be(Errors.TokenExpired);
    }

    /// <summary>
    /// Validates any after expiration+clockskew is invalid.
    /// </summary>
    [TestMethod]
    public void WhenTimeAndClockSkewIsAfterExp_ThenValidationFails() {
        // Token with exp set to 1736691481
        const string raw = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3MzY2OTE0ODF9.w_5MK3o_6rqJpH8Fl0q9WdSZEs413a2tS_j2Ly0XlH0";

        new JwtHandler(
            TestDefaults.DefaultTestOptions,
            clock: new Clock(clockSkew: TimeSpan.FromSeconds(5), getCurrentTime: () => 1736691482 - 5)
        ).TryGetValue(raw, out var token, out var error).Should().BeFalse();
        error.Should().Be(Errors.TokenExpired);
    }

    /// <summary>
    /// Validates any time before expiration+clockskew is valid.
    /// </summary>
    [TestMethod]
    public void WhenTimeAndClockSkewIsBeforeExp_ThenValidationSucceeds() {
        // Token with exp set to 1736691481
        const string raw = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3MzY2OTE0ODF9.w_5MK3o_6rqJpH8Fl0q9WdSZEs413a2tS_j2Ly0XlH0";

        new JwtHandler(
            TestDefaults.DefaultTestOptions,
            clock: new Clock(clockSkew: TimeSpan.FromSeconds(5), getCurrentTime: () => 1736691480 - 5)
        ).TryGetValue(raw, out var token, out var error).Should().BeTrue();
    }

    /// <summary>
    /// Validates non-NumericDate fails.
    /// </summary>
    [TestMethod]
    [DataRow("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOiJ0ZXN0In0.OmovxMNN77dbgc_5j1-K-K6GhLoNh1Lyhgolw9x0N2g")] // Token with exp set to "test"
    [DataRow("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjEuMX0.T48rjzoG09qg2goAL_-8GLGDwM5MS1VhKZdkyooi_3c")] // Token with exp set to 1.100
    public void WhenExpClaimIsNotNumericDate_ThenFails(string raw) {

        new JwtHandler().TryGetValue(raw, out var token, out var error).Should().BeFalse();
        error.Should().Be(Errors.InvalidTokenStructure);
    }

    /// <summary>
    /// Use of exp claim is optional.
    /// </summary>
    [TestMethod]
    public void ExpClaimIsOptional() {
        const string raw = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.e30.yXvILkvUUCBqAFlAv6wQ1Q-QRAjfe3eSosO949U73Vo";

        var options = TestDefaults.DefaultTestOptions;

        new JwtHandler(options)
            .TryGetValue(raw, out var token, out var error)
            .Should()
            .BeTrue();
    }
}