using System.Text.Json;
using System.Text.Json.Serialization;

namespace jwt.Token;

public class Body
{
    [JsonPropertyName("iss")]
    public string? Issuer { get; init; }
    [JsonPropertyName("sub")]
    public string? Subject { get; init; }
    [JsonPropertyName("aud")]
    public string? Audience { get; init; }
    [JsonPropertyName("exp")]
    public long? ExpirationTime { get; init; }
    [JsonPropertyName("nbf")]
    public string? NotBefore { get; init; }
    [JsonPropertyName("iat")]
    public string? IssuedAt { get; init; }
    [JsonPropertyName("jti")]
    public string? JwtId { get; init; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? Claims { get; set; }
}
