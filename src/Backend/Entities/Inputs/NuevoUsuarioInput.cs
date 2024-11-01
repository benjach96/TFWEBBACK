namespace TrackingSystem.Backend.Entities.Inputs
{
    public class NuevoUsuarioInput
    {
        public string Email { get; set; } = null!;

        public string Password { get; set; } = null!;
        public string ConfirmacionDePassword { get; set; } = null!;

        public string Nombres { get; set; } = null!;

        public string Apellidos { get; set; } = null!;
    }
}
