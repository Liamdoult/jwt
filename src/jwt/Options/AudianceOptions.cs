using System.ComponentModel.DataAnnotations;

namespace jwt.Options;

/// <summary>
/// Configure the validation of `Aud` claim.
/// </summary>
public class AudianceOptions
{
    /// <summary>
    /// Principal used to validate the `aud` claim in the token. If this
    /// Principal in not present in the aud claim, the token will be rejected.
    ///
    /// If the <see cref="PrincipalAudiance"/> is not set and the token contains
    /// an audiance value, the token will be rejected.
    /// </summary>
    [Required]
    public string? PrincipalAudiance { get; set; }

    /// <summary>
    /// Enforces that a token has the `aud` claim.
    /// </summary>
    /// <remarks>
    /// If the `aud` claim is present, the audiance must match that of the
    /// <see cref="PrincipalAudiance"/>. But if a token does not have audiance,
    /// and <see cref="PrincipalAudiance"/> is not set, the token will be
    /// valid. It is recommended that this value remains required.
    /// </remarks>
    [Required]
    public bool IsAudianceClaimRequired { get; set; } = true;

    /// <summary>
    /// Disable audiance validation completely.
    /// </summary>
    /// <remarks>
    /// It is highly recommended that this feature is enabled.
    /// </remarks>
    [Required]
    public bool IsAudianceValidationEnabled { get; set; } = true;
}
