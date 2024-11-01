using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.EntityFrameworkCore;
using TrackingSystem.Backend.Auth;
using TrackingSystem.Backend.Entities;
using TrackingSystem.Backend.Entities.Inputs;
using TrackingSystem.Backend.Entities.DTOs;
using TrackingSystem.DataModel;

namespace TrackingSystem.Backend.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UsuariosController : ControllerBase
    {
        private readonly TrackingDataContext _context;
        readonly IMapper _mapper;

        public UsuariosController(TrackingDataContext context, IMapper mapper)
        {
            this._mapper = mapper;
            _context = context;
        }

        // POST: api/Usuarios
        [HttpPost]
        [ProducesResponseType<PostUsuarioDTO>(StatusCodes.Status200OK)]
        [ProducesResponseType<ErrorSimple>(StatusCodes.Status400BadRequest)]
        public async Task<ActionResult> PostUsuario(NuevoUsuarioInput nuevoUsuario)
        {
            if (nuevoUsuario.Password != nuevoUsuario.ConfirmacionDePassword)
            {
                return BadRequest(new ErrorSimple(101, "Las contraseñas no coinciden"));
            }

            // TODO: Verificar si el email ya existe

            var usuario = _mapper.Map<Usuario>(nuevoUsuario);
            usuario.PasswordHash = BasicAuthenticationHelper.GetPasswordHash(nuevoUsuario.Password);
            usuario.FechaDeCreacion = DateTimeOffset.Now;
            usuario.Estado = "A";

            _context.Usuarios.Add(usuario);
            try
            {
                await _context.SaveChangesAsync();

                var result = _mapper.Map<PostUsuarioDTO>(usuario);

                return Ok(result);
            }
            catch (DbUpdateException ex)
            {
                if (ex.InnerException is Microsoft.Data.SqlClient.SqlException sqlEx)
                {
                    if (sqlEx.Number == 2627)
                    {
                        return BadRequest(new ErrorSimple(102, "El email ya está registrado"));
                    }
                }
                throw;
            }
        }


        [HttpPost("Verificar")]
        public async Task<ActionResult> VerificarCredenciales(VerificarCredencialesInput credenciales)
        {
            var usuario = await _context.Usuarios
                .Where(m => m.Email == credenciales.Email && m.Estado == "A")
                .SingleOrDefaultAsync();

            if (usuario == null)
            {
                return Unauthorized(new ErrorSimple(100, "Usuario no existe o el password es incorrecto."));
            }
            var hashedPassword = BasicAuthenticationHelper.GetPasswordHash(credenciales.Password);

            if (hashedPassword != usuario.PasswordHash)
            {
                // Nota: Se retorna el mismo error que antes para no dar pistas a los atacantes.
                return Unauthorized(new ErrorSimple(100, "Usuario no existe o el password es incorrecto."));
            }

            var result = _mapper.Map<PostUsuarioDTO>(usuario);

            return Ok(result);
        }

    }
}
