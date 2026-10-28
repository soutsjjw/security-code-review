// Deliberately secure counterexamples to test false positives.
namespace MultiAgentCases;

public static class SafeOrderAccess
{
    // AC-08: authorize at query boundary using verified caller identity.
    public static Order? Load(int id, string callerId, IEnumerable<Order> orders)
        => orders.FirstOrDefault(o => o.Id == id && o.OwnerId == callerId);
}

public static class SafeSessionValidator
{
    // AC-01: reject empty or expired sessions.
    public static bool Valid(string token, DateTimeOffset expiresAt, DateTimeOffset now)
        => !string.IsNullOrWhiteSpace(token) && now < expiresAt;
}
