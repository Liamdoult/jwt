namespace jwt;

public class Clock {

    private TimeSpan _clockSkew { get; init; }
    private Func<int> _getCurrentTime { get; init; }

    public Clock(TimeSpan? clockSkew = null, Func<int>? getCurrentTime = null) {
        _clockSkew = clockSkew ?? TimeSpan.Zero;
        _getCurrentTime = getCurrentTime ?? (() => (int)(DateTime.UtcNow - DateTime.UnixEpoch).TotalSeconds);
    }

    public int GetExpirationEpoch() => _getCurrentTime() + (int)_clockSkew.TotalSeconds;

    public int GetNotBeforeEpoch(TimeSpan clockSkew) => _getCurrentTime() - (int)clockSkew.TotalSeconds;
}