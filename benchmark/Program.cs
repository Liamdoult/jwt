using BenchmarkDotNet.Running;

namespace jwt.Benchmark;

public class Program
{
    public static void Main(string[] args)
    {
        BenchmarkRunner.Run<Issue>();
        BenchmarkRunner.Run<Validate>();
    }
}