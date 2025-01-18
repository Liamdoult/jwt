using System.ComponentModel.DataAnnotations;

namespace jwt.Options;

/// <summary>
/// Configure the validation of `typ` header claim.
/// </summary>
public class TypeOptions
{
    /// <summary>
    /// When optional type header claim enforcment is enabled, this value will be used.
    /// </summary>
    /// <remarks>
    /// Type header claim validation is case-insensitve but it is recommended
    /// ExpectedType be set to all capitals.
    ///
    /// ExpectedType defaults to RFC7519 compliant "JWT" value. It is not
    /// recommended to change.
    /// </remarks>
    [Required]
    public string ExpectedType { get; set; } = "JWT";

    /// <summary>
    /// Enforces that a token has the `typ` header claim and the value matches <see cref="ExpectedType"/>.
    /// </summary>
    /// <remarks>
    /// Disabled by default as all tokens are expected to be JWT.
    ///
    /// If <see cref="IsTypeValidationEnabled"/> is set true and
    /// <see cref="IsTypeHeaderClaimRequired"/> is set false, then only tokens
    /// with type claim in the header will be validated. Otherwise tokens, will
    /// be assumed JWT. To fully enforce every token has typ set to
    /// <see cref="ExpectedType"/>, enable <see cref="IsTypeHeaderClaimRequired"/>.
    /// </remarks>
    [Required]
    public bool IsTypeHeaderClaimRequired { get; set; } = false;

    /// <summary>
    /// Disable type header claim validation completely.
    /// </summary>
    /// <remarks>
    /// Enabled by default as it is recommended that the type value match when
    /// present.
    ///
    /// If <see cref="IsTypeValidationEnabled"/> is set true and
    /// <see href="IsTypeHeaderClaimRequired"/> is set false, then only tokens
    /// with type claim in the header will be validated. Otherwise tokens, will
    /// be assumed JWT. To fully enforce every token has typ set to
    /// <see cref="ExpectedType"/>, enable <see cref="IsTypeHeaderClaimRequired"/>.
    /// </remarks>
    [Required]
    public bool IsTypeValidationEnabled { get; set; } = true;
}
