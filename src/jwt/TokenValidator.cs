using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using jwt.Options;
using jwt.Token;

namespace jwt;

public class TokenValidator
{
    private Clock _clock { get; init; }

    private ValidationOptions _options { get; init; }

    public TokenValidator(
        ValidationOptions? options = null,
        Clock? clock = null
    ) {
        _options = options ?? new();
        _clock = clock ?? new();
    }

    public bool TryGetValue(string rawToken, [NotNullWhen(true)] out Token.Token? token, [NotNullWhen(false)] out string? error) {
        token = null;
        error = null;

        var splitToken = rawToken.Split(".");
        if (splitToken.Length != 3) {
            error = Errors.InvalidTokenStructure;
            return false;
        }

        var b64UrlHeader = splitToken[0];
        var b64UrlBody = splitToken[1];
        var b64UrlSiganture = splitToken[2];

        var b64Header = ToBase64(b64UrlHeader);
        var b64Body = ToBase64(b64UrlBody);
        var b64Signature = ToBase64(b64UrlSiganture);

        var b64decodedHeader = Convert.FromBase64String(b64Header);
        var b64decodedBody = Convert.FromBase64String(b64Body);

        Header? header;
        Body? body;
        try {
            header = JsonSerializer.Deserialize<Header>(b64decodedHeader);
            body = JsonSerializer.Deserialize<Body>(b64decodedBody);
        } catch (JsonException)
        {
            error = Errors.InvalidTokenStructure;
            return false;
        }

        var signature = b64Signature == "" ? null : new Signature { RawSignature = b64Signature };

        if (header is null || body is null) {
            error = Errors.InvalidTokenStructure;
            return false;
        }

        token = new Token.Token(header, body, signature);

        // Validate Token Content Type (cty)
        if (_options.ContentTypeOptions.IsTypeValidationEnabled) {
            if (token.Header.ContentType is not null && token.Header.ContentType.ToUpperInvariant() != _options.ContentTypeOptions.ExpectedType.ToUpperInvariant()) {
                error = Errors.InvalidTokenType;
                return false;
            }
        }

        // Validate Token Type (typ)
        if (_options.TypeOptions.IsTypeValidationEnabled) {
            if (token.Header.Type is null) {
                if (_options.TypeOptions.IsTypeHeaderClaimRequired) {
                    error = Errors.MissingRequiredClaim;
                    return false;
                }
            }
            else if (token.Header.Type.ToUpperInvariant() != _options.TypeOptions.ExpectedType.ToUpperInvariant()) {
                error = Errors.InvalidTokenType;
                return false;
            }
        }

        // Validate Token Expiration (exp)
        if (_options.ExpirationOptions.IsExpirationValidationEnabled) {
            if (token.Body.ExpirationTime is null)
            {
                if (_options.ExpirationOptions.IsExpirationClaimRequired) {
                    error = Errors.MissingRequiredClaim;
                    return false;
                }
            }
            else
            {
                int currentEpoch;
                if (token.Body.ExpirationTime <= (currentEpoch = _clock.GetExpirationEpoch(_options.ExpirationOptions.ClockSkew))) {
                    Console.WriteLine($"{Errors.TokenExpired} (token exp: {token.Body.ExpirationTime}, {nameof(_clock.GetExpirationEpoch)}: {currentEpoch}");
                    error = Errors.TokenExpired;
                    return false;
                }
            }
        }

        // Validate Token Not Before (nbf)
        if (_options.NotBeforeOptions.IsNotBeforeValidationEnabled) {
            if (token.Body.NotBefore is null)
            {
                if (_options.NotBeforeOptions.IsNotBeforeClaimRequired) {
                    error = Errors.MissingRequiredClaim;
                    return false;
                }
            }
            else
            {
                int currentEpoch;
                if (token.Body.NotBefore > (currentEpoch = _clock.GetNotBeforeEpoch(_options.NotBeforeOptions.ClockSkew))) {
                    Console.WriteLine($"{Errors.TokenNotBefore} (token nbf: {token.Body.NotBefore}, {nameof(_clock.GetNotBeforeEpoch)}: {currentEpoch}");
                    error = Errors.TokenNotBefore;
                    return false;
                }
            }
        }

        // Validate Token Audiance (aud)
        if (_options.AudianceOptions.IsAudianceValidationEnabled) {
            if (token.Body.Audience is null) {
                if (_options.AudianceOptions.IsAudianceClaimRequired) {
                    error = Errors.MissingRequiredClaim;
                    return false;
                }

                if (_options.AudianceOptions.PrincipalAudiance is not null) {
                    error = Errors.InvalidAudiance;
                    return false;
                }
            }
            else if (!token.Body.Audience.Contains(_options.AudianceOptions.PrincipalAudiance)) {
                error = Errors.InvalidAudiance;
                return false;
            }
        }

        // Validate Signature
        if (token.Signature is null) {
            if (!_options.AllowUnsecured) {
                error = Errors.InvalidTokenSignature;
                return false;
            }

            if (token.Header.Algorithm is null || token.Header.Algorithm.ToLowerInvariant() != "none") {
                error = Errors.InvalidTokenSignature;
                return false;
            }
        }

        return true;
    }

    private static string ToBase64(string b64Url) {
        var b64 = b64Url.Replace('_', '/').Replace('-', '+');
        switch(b64Url.Length % 4) {
            case 2: b64 += "=="; break;
            case 3: b64 += "="; break;
        }
        return b64;
    }
}
