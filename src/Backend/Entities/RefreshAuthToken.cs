using TrackingSystem.Backend.Entities.DTOs;

namespace TrackingSystem.Backend.Entities
{
    public class RefreshAuthToken
    {
        public string AccessToken { get; set; } = null!;
        public string RefreshToken { get; set; } = null!;
        public DateTimeOffset Expiration { get; set; }
    }
}
