using System;
using System.Collections.Generic;

namespace TrackingSystem.DataModel;

public partial class Cliente
{
    public int ClienteId { get; set; }

    public string Empresa { get; set; } = null!;

    public string NombreDelRepresentante { get; set; } = null!;

    public string ApellidosDelRepresentante { get; set; } = null!;

    public string Cargo { get; set; } = null!;

    public DateTimeOffset FechaDeCreacion { get; set; }

    public string Estado { get; set; } = null!;

    public virtual ICollection<OrdenDeTrabajo> OrdenDeTrabajos { get; set; } = new List<OrdenDeTrabajo>();
}
