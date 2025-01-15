using System.ComponentModel.DataAnnotations;

namespace jwt.Options;

/// <summary>
/// Configure the validation of `Exp` claim.
/// </summary>
public class ExpirationOptions
{
    /// <summary>
    /// Provide a small leeway when validating the expiration, usually no more
    /// than a few minutes, to account for clock skew.
    /// </summary>
    [Required]
    public TimeSpan ClockSkew { get; set; } = TimeSpan.Zero;

    /// <summary>
    /// Enforces that tokens have `exp` claim.
    /// </summary>
    /// <remarks>
    /// It is highly recommended that this value remains true.
    /// </remarksprincipal>
    [Required]
    public bool IsExpirationClaimRequired { get; set; } = true;

    /// <summary>
    /// Disable Expiration validation completely.
    /// </summary>
    /// <remarks>
    /// It is highly recommended that this feature is enabled.
    /// </remarks>
    [Required]
    public bool IsExpirationValidationEnabled { get; set; } = true;
}
