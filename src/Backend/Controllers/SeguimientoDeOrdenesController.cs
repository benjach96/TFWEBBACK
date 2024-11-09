using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Metadata.Ecma335;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using TrackingSystem.Backend.Auth;
using TrackingSystem.Backend.Entities;
using TrackingSystem.Backend.Entities.DTOs;
using TrackingSystem.DataModel;

namespace TrackingSystem.Backend.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class SeguimientoDeOrdenesController : ControllerBase
    {
        class LatLong
        {
            public decimal Lat { get; set; }
            public decimal Lng { get; set; }
        }

        private readonly TrackingDataContext _context;
        readonly IMemoryCache _memoryCache;
        // Simulacion de ubicacion
        readonly LatLong[] _simulatedLatLongs;
        readonly ILogger<SeguimientoDeOrdenesController> _logger;

        public SeguimientoDeOrdenesController(TrackingDataContext context, IMemoryCache memoryCache, ILogger<SeguimientoDeOrdenesController> logger)
        {
            this._logger = logger;
            this._memoryCache = memoryCache;
            _context = context;

            // Simulacion de ubicacion
            _simulatedLatLongs = new[]
            {
                new LatLong { Lat = -12.104526m, Lng = -76.979138m },
                new LatLong { Lat = -12.106939m, Lng = -76.978806m },
                new LatLong { Lat = -12.109079m, Lng = -76.978463m },
                new LatLong { Lat = -12.110180m, Lng = -76.977701m },
                new LatLong { Lat = -12.110023m, Lng = -76.976381m },
                new LatLong { Lat = -12.109929m, Lng = -76.974514m },
                new LatLong { Lat = -12.109824m, Lng = -76.972476m },
                new LatLong { Lat = -12.109069m, Lng = -76.970716m },
                new LatLong { Lat = -12.108009m, Lng = -76.969246m },
                new LatLong { Lat = -12.107054m, Lng = -76.968034m },
                new LatLong { Lat = -12.106310m, Lng = -76.966908m },
                new LatLong { Lat = -12.105617m, Lng = -76.966039m },
                new LatLong { Lat = -12.104883m, Lng = -76.965030m },
                new LatLong { Lat = -12.104369m, Lng = -76.964268m },
                new LatLong { Lat = -12.103687m, Lng = -76.963421m }
            };
        }

        // GET: api/usuario/5/ordenes
        [HttpGet("/api/SeguimientoDeOrdenes")]
        public async Task<ActionResult<List<ResumenDeOrdenDTO>>> GetOrdenes([FromQuery] int? cantidad)
        {
            _logger?.LogDebug("GetOrdenes:START");
            // Obtener el id del usuario actual
            var userId = AuthenticationHelper.GetUsuarioId(User);
            _logger?.LogDebug("GetOrdenes:UserId={0}", userId);

            // Recuperar las ordenes de trabajo del usuario
            var ordenPorUsuario = await _context.OrdenesPorUsuario
                .Include(m => m.OrdenDeTrabajo)
                .Include(m => m.OrdenDeTrabajo.Envios)
                .Where(m => m.UsuarioId == userId)
                .OrderByDescending(m => m.FechaDeUltimaConsulta)
                .Take(cantidad ?? 10)
                .ToListAsync();

            _logger?.LogDebug("GetOrdenes:OrdenPorUsuario={0}", ordenPorUsuario.Count);

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

        [HttpGet("/api/SeguimientoDeOrdenes/{codigoDeSeguimiento}")]
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
            var usuarioId = AuthenticationHelper.GetUsuarioId(User);

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

        [HttpDelete("/api/SeguimientoDeOrdenes/{codigoDeSeguimiento}")]
        public async Task<ActionResult> DeleteOrdenPorUsuario(string codigoDeSeguimiento)
        {
            // Recuperar el id del usuario actual
            var usuarioId = AuthenticationHelper.GetUsuarioId(User);

            // Recuperar OrdenPorUsuario basado en el codigo de seguimiento
            var orden = await _context.OrdenesPorUsuario
                .Where(m => m.OrdenDeTrabajo.CodigoDeSeguimiento == codigoDeSeguimiento && m.UsuarioId == usuarioId)
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

        [HttpGet("/api/SeguimientoDeOrdenes/{codigoDeSeguimiento}/ubicacion")]
        [ProducesResponseType<RastreoEnTiempoRealDTO>(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public ActionResult<RastreoEnTiempoRealDTO> GetUbicacionActual(string codigoDeSeguimiento)
        {
            // TODO ESTO ES UNA SIMULACION DE UBICACION
            // Para una aplicacion real, se deberia recuperar la ubicacion actual del envio de la base de datos
            // Y esta informacion deberia ser actualizada por un receptor de GPS que este ubicada en el vehiculo
            // que transporta la orden de trabajo

            _logger?.LogDebug("GetUbicacionActual:CodigoDeSeguimiento={0}", codigoDeSeguimiento);

            // Esta simulacion solo funciona con un solo codigo de seguimiento
            if (codigoDeSeguimiento != "ABC5202024")
            {
                _logger?.LogDebug("GetUbicacionActual:NOT SUPPORTED");
                return NotFound();
            }

            // Obtener la ultima ubicacion reportada
            if (!_memoryCache.TryGetValue("LastPostReported", out int lastPostReported))
            {
                lastPostReported = 0;
            }

            _logger?.LogDebug("GetUbicacionActual:LastPostReported={0}", lastPostReported);

            // Obtener la siguiente ubicacion
            int nextPost = lastPostReported + 1;

            if (nextPost >= _simulatedLatLongs.Length)
            {
                nextPost = 0;
            }

            _logger?.LogDebug("GetUbicacionActual:NextPost={0}", nextPost);

            // Actualizar la ultima ubicacion reportada
            _memoryCache.Set("LastPostReported", nextPost);
            //_memoryCache.Set("LastPostReported", lastPostReported, TimeSpan.FromMinutes(5));

            // Generar resultado
            var location = _simulatedLatLongs[nextPost];
            var result = new RastreoEnTiempoRealDTO
            {
                Latitud = location.Lat,
                Longitud = location.Lng,
                FechaDeCreacion = DateTime.Now,
                CodigoDeSeguimiento = codigoDeSeguimiento
            };

            return Ok(result);
        }
    }
}
