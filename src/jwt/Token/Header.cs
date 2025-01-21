using System.Text.Json;
using System.Text.Json.Serialization;

namespace jwt;

public class Header {

    [JsonPropertyName("alg")]
    public string? Algorithm { get; init; }

    [JsonPropertyName("typ")]
    public string? Type { get; init; }

    [JsonPropertyName("cty")]
    public string? ContentType { get; init; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? Claims { get; set; }
}
