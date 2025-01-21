using jwt.Options;

namespace jwt.RFC7515.Test;

public static class TestDefaults {
    public static ValidationOptions DefaultTestOptions => new() {
        AllowUnsecured = true,
        TypeOptions = new() {
            IsTypeValidationEnabled = false,
        },
        ExpirationOptions = new() {
            IsExpirationValidationEnabled = false,
        },
        NotBeforeOptions = new() {
            IsNotBeforeValidationEnabled = false,
        },
        AudianceOptions = new() {
            IsAudianceValidationEnabled = false,
        }
    };

    public static Token.Token DefaultToken => new() {
        Header = new() {
            Algorithm = "none",
        },
        Body = new() {
            IssuedAt = DateTimeOffset.Now.AddHours(1).ToUnixTimeSeconds(),
            NotBefore = DateTimeOffset.Now.ToUnixTimeSeconds(),
        }
    };

    public static string DefaultRawToken => _defaultRawToken();

    private static string _defaultRawToken() {
        if (new TokenIssuer().TryGetValue(TestDefaults.DefaultToken, out var rawToken, out var error))
            return rawToken;

        throw new Exception($"Something failed when creating the default token. Error: {error}");
    }
}