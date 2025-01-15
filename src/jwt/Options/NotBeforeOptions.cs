using System.ComponentModel.DataAnnotations;

namespace jwt.Options;

/// <summary>
/// Configure the validation of `Nbf` claim.
/// </summary>
public class NotBeforeOptions
{
    /// <summary>
    /// Provide a small leeway when validating Not Before, usually no more
    /// than a few minutes, to account for clock skew.
    /// </summary>
    [Required]
    public TimeSpan ClockSkew { get; set; } = TimeSpan.Zero;

    /// <summary>
    /// Enforces that tokens have `nbf` claim.
    /// </summary>
    /// <remarks>
    /// It is highly recommended that this value remains true.
    /// </remarksprincipal>
    [Required]
    public bool IsNotBeforeClaimRequired { get; set; } = true;

    /// <summary>
    /// Disable Not Before validation completely.
    /// </summary>
    /// <remarks>
    /// It is highly recommended that this feature is enabled.
    /// </remarks>
    [Required]
    public bool IsNotBeforeValidationEnabled { get; set; } = true;
}
