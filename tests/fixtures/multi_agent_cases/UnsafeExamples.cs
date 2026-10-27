// Deliberately vulnerable examples for detection-regression tests.
namespace MultiAgentCases;
public sealed record Order(int Id, string OwnerId, string Description);

public static class UnsafeOrderAccess
{
    // AC-08: entry controls only the user-supplied object ID, not its owner.
    public static Order? Load(int id, IEnumerable<Order> orders)
        => orders.FirstOrDefault(o => o.Id == id);
}

public static class UnsafeSessionValidator
{
    // AC-01: accepts an expired session; expiry is not checked.
    public static bool Valid(string token, DateTimeOffset expiresAt, DateTimeOffset now)
        => !string.IsNullOrWhiteSpace(token);
}
