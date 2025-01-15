using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using jwt.Options;
using jwt.Token;

namespace jwt;

public class JwtHandler
{
    private Clock _clock { get; init; }

    private JwtHandlerOptions _options { get; init; }

    public JwtHandler(
        JwtHandlerOptions? options = null,
        Clock? clock = null
    ) {
        _options = options ?? new();
        _clock = clock ?? new(clockSkew: _options.ExpirationOptions.ClockSkew);
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

        var signature = new Signature { RawSignature = b64Signature };

        if (header is null || body is null) {
            error = Errors.InvalidTokenStructure;
            return false;
        }

        token = new Token.Token(header, body, signature);

        // Validate Token Expiration
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
                if (token.Body.ExpirationTime <= (currentEpoch = _clock.GetExpirationEpoch())) {
                    Console.WriteLine($"{Errors.TokenExpired} (token exp: {token.Body.ExpirationTime}, {nameof(_clock.GetExpirationEpoch)}: {currentEpoch}");
                    error = Errors.TokenExpired;
                    return false;
                }
            }
        }

        // Validate Not Before
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

        // Validate Token Audiance
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
