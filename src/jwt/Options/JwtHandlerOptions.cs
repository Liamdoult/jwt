using System.ComponentModel.DataAnnotations;

namespace jwt.Options;

public class JwtHandlerOptions
{
    /// <inheritdoc cref="ExpirationOptions" />
    [Required]
    public ExpirationOptions ExpirationOptions { get; init; } = new();
}
