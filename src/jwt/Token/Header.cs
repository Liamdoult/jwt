using System.Text.Json;
using System.Text.Json.Serialization;

namespace jwt.Token;

public class Header {
    [JsonPropertyName("typ")]
    public string? Type { get; init; }
    [JsonPropertyName("cty")]
    public string? ContentType { get; init; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? Claims { get; set; }
}
