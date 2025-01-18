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
}
