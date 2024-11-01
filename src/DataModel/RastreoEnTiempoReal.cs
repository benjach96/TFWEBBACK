using System;
using System.Collections.Generic;

namespace TrackingSystem.DataModel;

public partial class RastreoEnTiempoReal
{
    public int RastreoId { get; set; }

    public int EnvioId { get; set; }

    public decimal Latitud { get; set; }

    public decimal Longitud { get; set; }

    public DateTimeOffset FechaDeCreacion { get; set; }

    public virtual Envio Envio { get; set; } = null!;
}
