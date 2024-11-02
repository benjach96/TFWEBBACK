using System;
using System.Collections.Generic;

namespace TrackingSystem.DataModel;

public partial class OrdenPorUsuario
{
    public int UsuarioId { get; set; }

    public int OrdenDeTrabajoId { get; set; }

    public DateTimeOffset FechaDeCreacion { get; set; }
    public DateTimeOffset FechaDeUltimaConsulta { get; set; }

    public virtual OrdenDeTrabajo OrdenDeTrabajo { get; set; } = null!;

    public virtual Usuario Usuario { get; set; } = null!;
}
