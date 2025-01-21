using BenchmarkDotNet.Attributes;

namespace jwt.Benchmark;

[JsonExporterAttribute.Full]
[JsonExporterAttribute.FullCompressed]
[MemoryDiagnoser]
public class Issue
{
    private Token _token;
    private TokenIssuer _issuer;

    public Issue()
    {
        _issuer = new TokenIssuer();
        _token = new() {
            Header = new() {
                Type = "JWT",
                Algorithm = "HS256",
            },
            Body = new() {
                Issuer = "joe",
                ExpirationTime = 1300819380,
                Claims = new() {{ "http://example.com/is_root", true }},
            }
        };
    }

    [Benchmark]
    public bool IssueExample() => _issuer.TryGetValue(_token, out var _, out var _);
}
