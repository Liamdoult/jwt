using BenchmarkDotNet.Attributes;

namespace jwt.Benchmark;

[JsonExporterAttribute.Full]
[JsonExporterAttribute.FullCompressed]
[MemoryDiagnoser]
public class Validate
{
    private const string rawToken = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private TokenValidator _handler;

    public Validate()
    {
        _handler = new TokenValidator(clock: new Clock(getCurrentTime: () => 1300819379));
    }

    [Benchmark]
    public bool ExampleToken() => _handler.TryGetValue(rawToken, out var _, out var _);
}
