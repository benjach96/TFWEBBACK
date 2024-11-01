using System;
using System.Collections.Generic;

namespace TrackingSystem.DataModel;

public partial class Fabrica
{
    public int FabricaId { get; set; }

    public string Nombre { get; set; } = null!;

    public DateTimeOffset FechaDeCreacion { get; set; }

    public virtual ICollection<OrdenDeTrabajo> OrdenDeTrabajos { get; set; } = new List<OrdenDeTrabajo>();
}
