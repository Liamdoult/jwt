namespace jwt;

public static class Errors {
    public const string E1 = "E1: Invalid token structure.";
    public const string InvalidTokenStructure = E1;
    public const string E2 = "E2: Token expired.";
    public const string TokenExpired = E2;
    public const string E3 = "E3: Missing required claim.";
    public const string MissingRequiredClaim = E3;
    public const string E4 = "E4: Invalid Audiance.";
    public const string InvalidAudiance = E4;
    public const string E5 = "E5: Token Not Before.";
    public const string TokenNotBefore = E5;
    public const string E6 = "E6: Invalid Token Type.";
    public const string InvalidTokenType = E6;
    public const string E7 = "E7: Invalid Token Signature.";
    public const string InvalidTokenSignature = E7;
}