using System.ComponentModel.DataAnnotations;

namespace jwt.Options;

/// <summary>
/// Configure the validation of `cty` header claim.
/// </summary>
public class ContentTypeOptions
{
    /// <summary>
    /// When optional content type header claim enforcment is enabled, this value will be used.
    /// </summary>
    /// <remarks>
    /// RFC7519 requires this value to be "JWT" when validated.
    /// </remarks>
    [Required]
    public string ExpectedType { get; } = "JWT";

    /// <summary>
    /// Enable content type header claim validation.
    /// </summary>
    /// <remarks>
    /// Disabled by default as recommended by RFC7519.
    ///
    /// When enabled, claims will only be validated when present.
    /// </remarks>
    [Required]
    public bool IsTypeValidationEnabled { get; set; } = false;
}
