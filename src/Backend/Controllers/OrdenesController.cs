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
        public async Task<ActionResult<List<ResumenDeOrdenDTO>>> GetOrdenes([FromQuery] int? cantidad)
        {
            // Obtener el id del usuario actual
            var userId = BasicAuthenticationHelper.GetUsuarioId(User);

            // Recuperar las ordenes de trabajo del usuario
            var ordenPorUsuario = await _context.OrdenesPorUsuario
                .Include(m => m.OrdenDeTrabajo)
                .Include(m => m.OrdenDeTrabajo.Envios)
                .Where(m => m.UsuarioId == userId)
                .OrderByDescending(m => m.FechaDeUltimaConsulta)
                .Take(cantidad ?? 10)
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
                FechaDeCreacion = m.FechaDeCreacion,
                FechaEstimadaDeEntrega = m.OrdenDeTrabajo.FechaEstimadaDeEntrega

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
                    .ThenInclude(m => m.Conductor)
                .Where(m => m.CodigoDeSeguimiento == codigoDeSeguimiento)
                .FirstOrDefaultAsync();

            // Si no se encuentra la orden de trabajo, devolver un 404
            if (orden == null)
            {
                return NotFound();
            }

            // Recuperar el id del usuario actual
            var usuarioId = BasicAuthenticationHelper.GetUsuarioId(User);

            // Agregar la orden de trabajo al usuario si no lo esta
            var orderPorUsuario = _context.OrdenesPorUsuario
                .Where(m => m.OrdenDeTrabajoId == orden.OrdenDeTrabajoId && m.UsuarioId == usuarioId)
                .FirstOrDefault();

            if (orderPorUsuario == null)
            {
                // No se encontro, agregarlo
                orderPorUsuario = new OrdenPorUsuario
                {
                    OrdenDeTrabajoId = orden.OrdenDeTrabajoId,
                    UsuarioId = usuarioId,
                    FechaDeCreacion = DateTime.Now,
                    FechaDeUltimaConsulta = DateTime.Now
                };

                _context.OrdenesPorUsuario.Add(orderPorUsuario);
            }
            else
            {
                // Se encontro, actualizar la fecha de consulta
                orderPorUsuario.FechaDeUltimaConsulta = DateTime.Now;
            }

            await _context.SaveChangesAsync().ConfigureAwait(false);

            // Obtener el ultimo envio
            var ultimoEnvio = orden.Envios.OrderByDescending(m => m.FechaDeCreacion).FirstOrDefault();

            // Mapear la orden de trabajo a un DTO
            var result = new DetalleDeOrdenDTO
            {
                OrdenDeTrabajoId = orden.OrdenDeTrabajoId,
                FechaEstimadaDeTermino = orden.FechaEstimadaDeTermino,
                FechaEstimadaDeEnvio = orden.FechaEstimadaDeEnvio,
                FechaEstimadaDeEntrega = orden.FechaEstimadaDeEntrega,
                FechaDeCreacion = orden.FechaDeCreacion,
                ClienteId = orden.ClienteId,
                CodigoDeSeguimiento = orden.CodigoDeSeguimiento,
                DireccionDeEntrega = orden.DireccionDeEntrega,
                Estado = orden.Estado,
                LugarDeEntrega = orden.LugarDeEntrega,
                PesoEnKilos = orden.PesoEnKilos,
                FabricaId = orden.FabricaId,
                NombreDeLaFabrica = orden.Fabrica.Nombre,

                FechaDeEntrega = ultimoEnvio?.FechaDeEntrega,
                FechaDeEnvio = ultimoEnvio?.FechaDeCreacion,
                EnvioId = ultimoEnvio?.EnvioId,
                ConductorId = ultimoEnvio?.ConductorId,
                ConductorApellidos = ultimoEnvio?.Conductor.Apellidos,
                ConductorNombres = ultimoEnvio?.Conductor.Nombres,
                ConductorTelefono = ultimoEnvio?.Conductor.Telefono
            };

            return result;
        }

        [HttpDelete("/api/Ordenes/{ordenDeTrabajoId}")]
        public async Task<ActionResult> DeleteOrdenPorUsuario(int ordenDeTrabajoId)
        {
            // Recuperar el id del usuario actual
            var usuarioId = BasicAuthenticationHelper.GetUsuarioId(User);

            // Recuperar la orden de trabajo por el codigo de seguimiento (ignorar el usuario actual)
            var orden = await _context.OrdenesPorUsuario
                .Where(m => m.OrdenDeTrabajoId == ordenDeTrabajoId && m.UsuarioId == usuarioId)
                .FirstOrDefaultAsync();

            // Si no se encuentra la orden de trabajo, devolver un 404
            if (orden == null)
            {
                return NotFound();
            }

            _context.OrdenesPorUsuario.Remove(orden);
            await _context.SaveChangesAsync().ConfigureAwait(false);

            return Ok();
        }
    }
}
