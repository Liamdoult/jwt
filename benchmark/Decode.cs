using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;

namespace jwt.Benchmark.Decode;

[JsonExporterAttribute.Full]
[JsonExporterAttribute.FullCompressed]
[MemoryDiagnoser]
public class ExampleToken
{
    private const string rawToken = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private JwtHandler _handler;

    public ExampleToken()
    {
        _handler = new JwtHandler(clock: new Clock(getCurrentTime: () => 1300819379));
    }

    [Benchmark]
    public bool Decode() => _handler.TryGetValue(rawToken, out var _, out var _);
}

public class Program
{
    public static void Main(string[] args)
    {
        var summary = BenchmarkRunner.Run<ExampleToken>();
    }
}