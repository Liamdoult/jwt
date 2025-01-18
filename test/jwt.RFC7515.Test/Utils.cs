using jwt.Options;

namespace jwt.RFC7519.Test;

public static class TestDefaults {
    public static JwtHandlerOptions DefaultTestOptions => new() {
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
}