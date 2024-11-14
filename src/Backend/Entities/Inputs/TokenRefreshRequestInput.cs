namespace TrackingSystem.Backend.Entities.Inputs
{
    public class TokenRefreshRequestInput
    {
        public string AccessToken { get; set; } = null!;
        public string RefreshToken { get; set; } = null!;
    }

}
