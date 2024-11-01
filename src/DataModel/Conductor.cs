using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TrackingSystem.DataModel
{
    public partial class Conductor
    {
        public int ConductorId { get; set; }
        public string Nombres { get; set; }
        public string Apellidos { get; set; }
        public string Telefono { get; set; }
        public DateTimeOffset FechaDeCreacion { get; set; }
        public string Estado { get; set; }

        public virtual ICollection<Envio> Envios { get; set; } = new List<Envio>();
    }
}
