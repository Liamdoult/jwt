using System.Text.Json;
using System.Text.Json.Serialization;

namespace jwt.Converters;

/// <summary>
/// Handles cases where a claim can be either a string value or a list of
/// strings.
/// </summary>
public class OptionalListConverter : JsonConverter<string[]>
{
    public override string[] Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.StartArray)
        {
            var arr = JsonSerializer.Deserialize<string[]>(ref reader, options);
            if (arr is null)
                return default;
            else
                return  arr;
        }

        if (reader.TokenType == JsonTokenType.String)
        {
            return [ reader.GetString() ];
        }

        throw new JsonException();
    }

    public override void Write(Utf8JsonWriter writer, string[] value, JsonSerializerOptions options)
    {
        throw new NotImplementedException();
    }
}