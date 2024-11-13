using TrackingSystem.Backend.Entities.DTOs;

namespace TrackingSystem.Backend.Entities
{
    public class AuthToken
    {
        public string Token { get; set; } = null!;
        public string RefreshToken { get; set; } = null!;
        public DateTimeOffset Expiration { get; set; }
        public PostUsuarioDTO User { get; set; } = null!;
    }
}
