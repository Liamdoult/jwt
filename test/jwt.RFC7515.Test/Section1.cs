using FluentAssertions;
using jwt.Options;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace jwt.RFC7515.Test;

/// <summary>
/// Asserts Section 1 Introduction
///
/// JSON Web Signature (JWS) represents content secured with digital signatures
/// or Message Authentication Codes (MACs) using JSON-based [RFC7159] data
/// structures. The JWS cryptographic mechanisms provide integrity protection
/// for an arbitrary sequence of octets. See Section 10.5 for a discussion on
/// the differences between digital signatures and MACs.
///
/// Two closely related serializations for JWSs are defined. The JWS Compact
/// Serialization is a compact, URL-safe representation intended for
/// space-constrained environments such as HTTP Authorization headers and URI
/// query parameters. The JWS JSON Serialization represents JWSs as JSON objects
/// and enables multiple signatures and/or MACs to be applied to the same
/// content. Both share the same cryptographic underpinnings.
///
/// Cryptographic algorithms and identifiers for use with this specification are
/// described in the separate JSON Web Algorithms (JWA) [JWA] specification and
/// an IANA registry defined by that specification. Related encryption
/// capabilities are described in the separate JSON Web Encryption (JWE) [JWE]
/// specification.
///
/// Names defined by this specification are short because a core goal is for the
/// resulting representations to be compact.
/// </summary>
[TestClass]
public class Section1 {
}

/// <summary>
/// Asserts 1.1 Notational Conventions
///
/// The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
/// "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
/// "OPTIONAL" in this document are to be interpreted as described in "Key words
/// for use in RFCs to Indicate Requirement Levels" [RFC2119].  The
/// interpretation should only be applied when the terms appear in all capital
/// letters.
///
/// BASE64URL(OCTETS) denotes the base64url encoding of OCTETS, per Section 2.
/// UTF8(STRING) denotes the octets of the UTF-8 [RFC3629] representation of
/// STRING, where STRING is a sequence of zero or more Unicode [UNICODE]
/// characters.
///
/// ASCII(STRING) denotes the octets of the ASCII [RFC20] representation of
/// STRING, where STRING is a sequence of zero or more ASCII characters.
///
/// The concatenation of two values A and B is denoted as A || B.
/// </summary>
[TestClass]
public class Section1_1 {
}