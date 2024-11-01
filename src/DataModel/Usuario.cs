using System;
using System.Collections.Generic;

namespace TrackingSystem.DataModel;

public partial class Usuario
{
    public int UsuarioId { get; set; }

    public string Email { get; set; } = null!;

    public string PasswordHash { get; set; } = null!;

    public string Nombres { get; set; } = null!;

    public string Apellidos { get; set; } = null!;

    public DateTimeOffset FechaDeCreacion { get; set; }

    public string Estado { get; set; } = null!;

    public virtual ICollection<OrdenPorUsuario> OrdenPorUsuarios { get; set; } = new List<OrdenPorUsuario>();
}
