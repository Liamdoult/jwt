using System.ComponentModel.DataAnnotations;

namespace jwt.Options;

public class JwtHandlerOptions
{
    /// <inheritdoc cref="TypeOptions" />
    [Required]
    public TypeOptions TypeOptions { get; init; } = new();

    /// <inheritdoc cref="ContentTypeOptions" />
    [Required]
    public ContentTypeOptions ContentTypeOptions { get; init; } = new();

    /// <inheritdoc cref="ExpirationOptions" />
    [Required]
    public ExpirationOptions ExpirationOptions { get; init; } = new();

    /// <inheritdoc cref="NotBeforeOptions" />
    [Required]
    public NotBeforeOptions NotBeforeOptions { get; init; } = new();

    /// <inheritdoc cref="AudianceOptions" />
    [Required]
    public AudianceOptions AudianceOptions { get; init; } = new();

    /// <summary>
    /// Enable validation of tokens without a signature.
    /// </summary>
    /// <remarks>
    /// This feature is disabled by default and is HIGHLY not recommended.
    ///
    /// This feature will allow tokens without signatures to be valid.
    /// </remarks>
    [Required]
    public bool AllowUnsecured { get; set; } = false;
}