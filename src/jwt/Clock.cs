namespace jwt;

public class Clock {

    private Func<int> _getCurrentTime { get; init; }

    public Clock(Func<int>? getCurrentTime = null) {
        _getCurrentTime = getCurrentTime ?? (() => (int)(DateTime.UtcNow - DateTime.UnixEpoch).TotalSeconds);
    }

    public int GetExpirationEpoch(TimeSpan clockSkew) => _getCurrentTime() + (int)clockSkew.TotalSeconds;

    public int GetNotBeforeEpoch(TimeSpan clockSkew) => _getCurrentTime() - (int)clockSkew.TotalSeconds;
}