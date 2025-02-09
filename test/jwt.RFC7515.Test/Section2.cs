﻿using FluentAssertions;
using jwt.Options;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace jwt.RFC7515.Test;

/// <summary>
/// Asserts Section 2 Terminology
///
/// These terms are defined by this specification:
///
/// JSON Web Signature (JWS)
///     A data structure representing a digitally signed or MACed message.
///
/// JOSE Header
///     JSON object containing the parameters describing the cryptographic
///     operations and parameters employed. The JOSE (JSON Object Signing and
///     Encryption) Header is comprised of a set of Header Parameters.
///
/// JWS Payload
///     The sequence of octets to be secured -- a.k.a. the message. The payload
///     can contain an arbitrary sequence of octets.
///
/// JWS Signature Payload.
///     Digital signature or MAC over the JWS Protected Header and the JWS
///     Header Parameter A name/value pair that is member of the JOSE Header.
///
/// JWS Protected Header
///     JSON object that contains the Header Parameters that are integrity
///     protected by the JWS Signature digital signature or MAC operation. For
///     the JWS Compact Serialization, this comprises the entire JOSE Header.
///     For the JWS JSON Serialization, this is one component of the JOSE
///     Header.
///
/// JWS Unprotected Header
///     JSON object that contains the Header Parameters that are not integrity
///     protected. This can only be present when using the JWS JSON
///     Serialization.
///
/// Base64url Encoding
///     Base64 encoding using the URL- and filename-safe character set defined
///     in Section 5 of RFC 4648 [RFC4648], with all trailing ’=’ characters
///     omitted (as permitted by Section 3.2) and without the inclusion of any
///     line breaks, whitespace, or other additional characters. Note that the
///     base64url encoding of the empty octet sequence is the empty string. (See
///     Appendix C for notes on implementing base64url encoding without
///     padding.)
///
/// JWS Signing Input
///     The input to the digital signature or MAC computation. Its value is
///     ASCII(BASE64URL(UTF8(JWS Protected Header)) || ’.’ || BASE64URL(JWS
///     Payload)).
///
/// JWS Compact Serialization
///     A representation of the JWS as a compact, URL-safe string.
///
/// JWS JSON Serialization
///     A representation of the JWS as a JSON object. Unlike the JWS Compact
///     Serialization, the JWS JSON Serialization enables multiple digital
///     signatures and/or MACs to be applied to the same content.  This
///     representation is neither optimized for compactness nor URL- safe.
///
/// Unsecured JWS
///     A JWS that provides no integrity protection. the "alg" value "none".
///     Unsecured JWSs use "none".
///
/// Collision-Resistant Name
///     A name in a namespace that enables names to be allocated in a manner
///     such that they are highly unlikely to collide with other names. Examples
///     of collision-resistant namespaces include: Domain Names, Object
///     Identifiers (OIDs) as defined in the ITU-T X.660 and X.670
///     Recommendation series, and Universally Unique IDentifiers (UUIDs)
///     [RFC4122]. When using an administratively delegated namespace, the
///     definer of a name needs to take reasonable precautions to ensure they
///     are in control of the portion of the namespace they use to define the
///     name.
///
/// StringOrURI
///     A JSON string value, with the additional requirement that while
///     arbitrary string values MAY be used, any value containing a ":"
///     character MUST be a URI [RFC3986]. StringOrURI values are compared as
///     case-sensitive strings with no transformations or canonicalizations
///     applied.
///
/// The terms "JSON Web Encryption (JWE)", "JWE Compact Serialization", and "JWE
/// JSON Serialization" are defined by the JWE specification [JWE].
///
/// The terms "Digital Signature" and "Message Authentication Code (MAC)" are
/// defined by the "Internet Security Glossary, Version 2" [RFC4949].
/// </summary>
[TestClass]
public class Section2 {
}