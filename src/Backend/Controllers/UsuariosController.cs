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
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace TrackingSystem.Backend.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UsuariosController : ControllerBase
    {
        private readonly TrackingDataContext _context;
        readonly IMapper _mapper;
        readonly IConfiguration _configuration;
        readonly string _jwtKey;

        public UsuariosController(TrackingDataContext context, IConfiguration configuration, IMapper mapper)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _mapper = mapper ?? throw new ArgumentNullException(nameof(mapper));
            _context = context ?? throw new ArgumentNullException(nameof(context));
            _jwtKey = _configuration["JWT:Key"] ?? throw new ArgumentNullException("JWT:Key");
        }

        /// <summary>
        /// Registra un nuevo usuario en el sistema.
        /// </summary>
        /// <param name="nuevoUsuario"></param>
        /// <response code="200">Usuario registrado correctamente</response>
        /// <response code="400">Se produjo un error al crear el usuario, verifique la respuesta para mas detalles.</response>
        /// <returns></returns>
        [HttpPost("Registrar")]
        [ProducesResponseType<PostUsuarioDTO>(StatusCodes.Status200OK)]
        [ProducesResponseType<ErrorSimple>(StatusCodes.Status400BadRequest)]
        public async Task<ActionResult> Registrar(NuevoUsuarioInput nuevoUsuario)
        {
            if (nuevoUsuario.Password != nuevoUsuario.ConfirmacionDePassword)
            {
                return BadRequest(new ErrorSimple(101, "Las contraseñas no coinciden"));
            }



            var usuario = _mapper.Map<Usuario>(nuevoUsuario);
            usuario.PasswordHash = AuthenticationHelper.GetPasswordHash(nuevoUsuario.Password);
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

        /// <summary>
        /// Genera un token JWT para un usuario autenticado usanso "oauth2" y el flujo "Resource Owner Password Credentials Grant".
        /// </summary>
        /// <param name="credenciales">Email y Password</param>
        /// <returns>JWT Token con usa expiracion de 4 horas</returns>
        /// <response code="200">Usuario Autenticado</response>
        /// <response code="401">Usuario no existe o el password es incorrecto.</response>
        [HttpPost("Login")]
        [ProducesResponseType<AuthToken>(StatusCodes.Status200OK)]
        [ProducesResponseType<ErrorSimple>(StatusCodes.Status401Unauthorized)]
        public async Task<ActionResult> Login(VerificarCredencialesInput credenciales)
        {
            var usuario = await _context.Usuarios
                .Where(m => m.Email == credenciales.Email && m.Estado == "A")
                .SingleOrDefaultAsync();

            if (usuario == null)
            {
                return Unauthorized(new ErrorSimple(100, "Usuario no existe o el password es incorrecto."));
            }
            var hashedPassword = AuthenticationHelper.GetPasswordHash(credenciales.Password);

            if (hashedPassword != usuario.PasswordHash)
            {
                // Nota: Se retorna el mismo error que antes para no dar pistas a los atacantes.
                return Unauthorized(new ErrorSimple(100, "Usuario no existe o el password es incorrecto."));
            }

            // Generar token JWT
            SecurityToken token;
            string tokenString;
            GenerateJwtToken(usuario, out token, out tokenString);

            // Retornar el token e informacion basica del usuario
            return Ok(new
            {
                token = tokenString,
                expiration = token.ValidTo.ToUniversalTime(),
                user = usuario
            });

            // NOTA: No se esta considerando REFRESH TOKENS. Para este ejemplo se asume que el token expira en 4 horas.

        }

        private void GenerateJwtToken(Usuario usuario, out SecurityToken token, out string tokenString)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_jwtKey);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Name, usuario.Email),
                    new Claim(AuthenticationHelper.UserIdClaimName, usuario.UsuarioId.ToString())
                }),
                Expires = DateTime.UtcNow.AddHours(4), // Token expiration
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            token = tokenHandler.CreateToken(tokenDescriptor);
            tokenString = tokenHandler.WriteToken(token);
        }
    }
}
