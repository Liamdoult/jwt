namespace jwt;

public static class Errors {
    public const string E1 = "E1: Invalid token structure.";
    public const string InvalidTokenStructure = E1;
    public const string E2 = "E2: Token expired.";
    public const string TokenExpired = E2;
    public const string E3 = "E3: Missing required claim.";
    public const string MissingRequiredClaim = E3;
}