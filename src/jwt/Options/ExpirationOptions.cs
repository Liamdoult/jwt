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
    /// Expiration will always be validated if the claim is found in the token.
    /// But if set to false, tokens without `exp` claim will fail. It is highly
    /// recommended that this value remains true.
    /// </remarksprincipal>
    [Required]
    public bool ExpirationRequired { get; set; } = true;
}
