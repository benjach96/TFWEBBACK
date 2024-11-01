using System;
using System.Collections.Generic;

namespace TrackingSystem.DataModel;

public partial class Envio
{
    public int EnvioId { get; set; }

    public int OrdenDeTrabajoId { get; set; }

    public DateTimeOffset? FechaDeEntrega { get; set; }

    public DateTimeOffset FechaDeCreacion { get; set; }
    public int ConductorId { get; set; }

    public string Estado { get; set; } = null!;

    public virtual OrdenDeTrabajo OrdenDeTrabajo { get; set; } = null!;

    public virtual ICollection<RastreoEnTiempoReal> RastreoEnTiempoReals { get; set; } = new List<RastreoEnTiempoReal>();
    public virtual Conductor Conductor { get; set; } = null!;
}
