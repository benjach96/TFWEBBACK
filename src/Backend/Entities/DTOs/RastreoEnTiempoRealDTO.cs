using TrackingSystem.DataModel;

namespace TrackingSystem.Backend.Entities.DTOs
{
    public class RastreoEnTiempoRealDTO
    {
        public string CodigoDeSeguimiento { get; set; } = null!;

        public decimal Latitud { get; set; }

        public decimal Longitud { get; set; }

        public DateTimeOffset FechaDeCreacion { get; set; }
    }
}
