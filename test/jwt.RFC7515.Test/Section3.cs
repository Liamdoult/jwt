using System.Text.Json.Serialization;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace jwt.RFC7515.Test;

/// <summary>
/// Assert Section 3 JSON Web Signature (JWS) Overview
///
/// JWS represents digitally signed or MACed content using JSON data structures
/// and base64url encoding. These JSON data structures MAY contain whitespace
/// and/or line breaks before or after any JSON values or structural characters,
/// in accordance with Section 2 of RFC 7159 [RFC7159]. A JWS represents these
/// logical values (each of which is defined in Section 2): o JOSE Header o JWS
/// Payload o JWS Signature For a JWS, the JOSE Header members are the union of
/// the members of these values (each of which is defined in Section 2): o JWS
/// Protected Header o JWS Unprotected Header This document defines two
/// serializations for JWSs: a compact, URL- safe serialization called the JWS
/// Compact Serialization and a JSON serialization called the JWS JSON
/// Serialization. In both serializations, the JWS Protected Header, JWS
/// Payload, and JWS Signature are base64url encoded, since JSON lacks a way to
/// directly represent arbitrary octet sequences.
/// </summary>
[TestClass]
public class Section3 {

    /// <summary>
    /// Asserts that tokens with whitespace or newlines are validated.
    /// </summary>
    [TestMethod]
    public void WhenJsonContainsWhiteSpace_ThenValidates() {
        new TokenIssuer(
            jsonSerializerOptions: new() {
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
                WriteIndented = true,
            }).TryGetValue(TestDefaults.DefaultToken, out var rawToken, out var _);

        Console.WriteLine($"Raw Token: {rawToken}");
        new TokenValidator(TestDefaults.DefaultTestOptions).TryGetValue(rawToken!, out var token, out var error).Should().BeTrue(error);
    }
}

/// <summary>
/// Asserts Section 3.1. JWS Compact Serialization Overview
///
/// In the JWS Compact Serialization, no JWS Unprotected Header is used.
/// In this case, the JOSE Header and the JWS Protected Header are the same.
///
/// In the JWS Compact Serialization, a JWS is represented as the concatenation:
///
///     BASE64URL(UTF8(JWS Protected Header)) || ’.’ ||
///     BASE64URL(JWS Payload) || ’.’ ||
///     BASE64URL(JWS Signature)
///
/// See Section 7.1 for more information about the JWS Compact Serialization.
/// </summary>
[TestClass]
public class Section3_1 {
}