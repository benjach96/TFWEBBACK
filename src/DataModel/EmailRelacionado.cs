using System;
using System.Collections.Generic;

namespace TrackingSystem.DataModel;

public partial class EmailRelacionado
{
    public int ClienteId { get; set; }

    public string Email { get; set; } = null!;

    public DateTimeOffset FechaDeCreacion { get; set; }

    public virtual Cliente Cliente { get; set; } = null!;
}
