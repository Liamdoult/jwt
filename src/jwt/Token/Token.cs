namespace jwt.Token;

public class Token {
    public Header? Header { get; init; }
    public Body? Body { get; init; }
    public Signature? Signature { get; init; }

    internal Token(Header header, Body body, Signature? signature) {
        Header = header;
        Body = body;
        Signature = signature;
    }

    public Token() {
    }

}