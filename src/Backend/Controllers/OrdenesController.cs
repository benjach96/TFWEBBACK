using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using TrackingSystem.Backend.Auth;
using TrackingSystem.Backend.Entities.DTOs;
using TrackingSystem.DataModel;

namespace TrackingSystem.Backend.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class OrdenesController : ControllerBase
    {
        private readonly TrackingDataContext _context;

        public OrdenesController(TrackingDataContext context)
        {
            _context = context;
        }

        // GET: api/usuario/5/ordenes
        [HttpGet("/api/Ordenes")]
        public async Task<ActionResult<List<ResumenDeOrdenDTO>>> GetOrdenes()
        {
            // Obtener el id del usuario actual
            var userId = BasicAuthenticationHelper.GetUsuarioId(User);

            // Recuperar las ordenes de trabajo del usuario
            var ordenPorUsuario = await _context.OrdenesPorUsuario
                .Include(m => m.OrdenDeTrabajo)
                .Include(m => m.OrdenDeTrabajo.Envios)
                .Where(m => m.UsuarioId == userId)
                .ToListAsync();

            // Si no hay ordenes de trabajo, devolver un 404
            if (ordenPorUsuario == null)
            {
                return NotFound();
            }

            // Mapear las ordenes de trabajo a un DTO
            var result = ordenPorUsuario.Select(m => new ResumenDeOrdenDTO
            {
                OrdenDeTrabajoId = m.OrdenDeTrabajoId,
                FechaEstimadaDeEnvio = m.OrdenDeTrabajo.FechaEstimadaDeEnvio,
                CodigoDeSeguimiento = m.OrdenDeTrabajo.CodigoDeSeguimiento,
                Estado = m.OrdenDeTrabajo.Estado,
                FechaDeEntrega = m.OrdenDeTrabajo.Envios.FirstOrDefault()?.FechaDeEntrega,
                FechaDeEnvio = m.OrdenDeTrabajo.Envios.FirstOrDefault()?.FechaDeCreacion,
                FechaDeCreacion = m.FechaDeCreacion

            }).ToList();

            return result;
        }

        [HttpGet("/api/Ordenes/{codigoDeSeguimiento}")]
        public async Task<ActionResult<DetalleDeOrdenDTO>> GetOrdenPorCodigoDeSeguimiento(string codigoDeSeguimiento)
        {
            // Recuperar la orden de trabajo por el codigo de seguimiento (ignorar el usuario actual)
            var orden = await _context.OrdenesDeTrabajo
                .Include(m => m.Fabrica)
                .Include(m => m.Envios)
                .Where(m => m.CodigoDeSeguimiento == codigoDeSeguimiento)
                .FirstOrDefaultAsync();

            // Si no se encuentra la orden de trabajo, devolver un 404
            if (orden == null)
            {
                return NotFound();
            }

            // Recuperar el id del usuario actual
            var usuarioId = BasicAuthenticationHelper.GetUsuarioId(User);

            var orderPorUsuario=new OrdenPorUsuario
            {
                OrdenDeTrabajoId = orden.OrdenDeTrabajoId,
                UsuarioId = usuarioId,
                FechaDeCreacion = DateTime.Now
            };

            // Agregar la orden de trabajo al usuario
            _context.OrdenesPorUsuario.Add(orderPorUsuario);
            await _context.SaveChangesAsync()
                .ConfigureAwait(false);

            // Mapear la orden de trabajo a un DTO
            var result = new DetalleDeOrdenDTO
            {
                OrdenDeTrabajoId = orden.OrdenDeTrabajoId,
                FechaEstimadaDeTermino = orden.FechaEstimadaDeTermino,
                FechaEstimadaDeEnvio = orden.FechaEstimadaDeEnvio,
                FechaDeCreacion = orden.FechaDeCreacion,
                ClienteId = orden.ClienteId,
                CodigoDeSeguimiento = orden.CodigoDeSeguimiento,
                DireccionDeEntrega = orden.DireccionDeEntrega,
                Estado = orden.Estado,
                FechaDeEntrega = orden.Envios.FirstOrDefault()?.FechaDeEntrega,
                FechaDeEnvio = orden.Envios.FirstOrDefault()?.FechaDeCreacion,
                EnvioId = orden.Envios.FirstOrDefault()?.EnvioId,
                FechaEstimadaDeEntrega = orden.FechaEstimadaDeEntrega,
                LugarDeEntrega = orden.LugarDeEntrega,
                PesoEnKilos = orden.PesoEnKilos,
                FabricaId = orden.FabricaId,
                NombreDeLaFabrica = orden.Fabrica.Nombre
            };

            return result;
        }

        // Agregar DeleteOrdenPorUsuario(orderByTrabajoId)
    }
}
