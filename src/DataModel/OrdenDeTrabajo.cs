using System;
using System.Collections.Generic;

namespace TrackingSystem.DataModel;

public partial class OrdenDeTrabajo
{
    public int OrdenDeTrabajoId { get; set; }

    public DateTimeOffset FechaEstimadaDeTermino { get; set; }

    public DateTimeOffset FechaEstimadaDeEnvio { get; set; }

    public DateTimeOffset FechaEstimadaDeEntrega { get; set; }

    public DateTimeOffset FechaDeCreacion { get; set; }

    public int ClienteId { get; set; }

    public int FabricaId { get; set; }

    public string CodigoDeSeguimiento { get; set; } = null!;

    public string Descripcion { get; set; } = null!;

    public decimal PesoEnKilos { get; set; }

    public string LugarDeEntrega { get; set; } = null!;

    public string DireccionDeEntrega { get; set; } = null!;

    public string Estado { get; set; } = null!;

    public virtual Cliente Cliente { get; set; } = null!;

    public virtual ICollection<Envio> Envios { get; set; } = new List<Envio>();

    public virtual Fabrica Fabrica { get; set; } = null!;

    public virtual ICollection<OrdenPorUsuario> OrdenPorUsuarios { get; set; } = new List<OrdenPorUsuario>();
}
