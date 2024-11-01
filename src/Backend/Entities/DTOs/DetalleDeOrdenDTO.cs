namespace TrackingSystem.Backend.Entities.DTOs
{
    public class DetalleDeOrdenDTO
    {
        public int OrdenDeTrabajoId { get; set; }
        public DateTimeOffset FechaEstimadaDeTermino { get; set; }
        public DateTimeOffset FechaEstimadaDeEnvio { get; set; }
        public DateTimeOffset FechaEstimadaDeEntrega { get; set; }
        public DateTimeOffset? FechaDeEntrega { get; set; }
        public DateTimeOffset? FechaDeEnvio { get; set; }
        public DateTimeOffset FechaDeCreacion { get; set; }
        public int ClienteId { get; set; }
        public string CodigoDeSeguimiento { get; set; } = null!;
        public string LugarDeEntrega { get; set; } = null!;
        public string DireccionDeEntrega { get; set; } = null!;
        public decimal PesoEnKilos { get; set; }
        public int FabricaId { get; set; }
        public string NombreDeLaFabrica { get; set; } = null!;
        public int? EnvioId { get; set; }
        public string Estado { get; set; } = null!;
    }
}
