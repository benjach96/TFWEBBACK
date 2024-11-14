using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TrackingSystem.DataModel
{
    public class RefreshToken
    {
        public int RefreshTokenId { get; set; }
        public string Token { get; set; } = null!;
        public int UsuarioId { get; set; }
        public DateTime FechaDeExpiracion { get; set; }
        public bool EstaRevocada { get; set; }
        public DateTime FechaDeCreacion { get; set; }
        public DateTime? FechaDeRevocacion { get; set; }
    }
}
