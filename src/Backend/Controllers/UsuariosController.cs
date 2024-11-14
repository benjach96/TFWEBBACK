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
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore.Metadata.Internal;

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
        readonly ILogger _logger;

        public UsuariosController(TrackingDataContext context, IConfiguration configuration, IMapper mapper, ILogger<UsuariosController> logger)
        {
            this._logger = logger;
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
        [HttpPost("registrar")]
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
        /// Genera un token JWT para un usuario autenticado usando "oauth2" y el flujo "Resource Owner Password Credentials Grant".
        /// </summary>
        /// <param name="credenciales">Email y Password</param>
        /// <returns>JWT Token con usa expiración de 4 horas</returns>
        /// <response code="200">Usuario Autenticado</response>
        /// <response code="401">Usuario no existe o el password es incorrecto.</response>
        [HttpPost("login")]
        [ProducesResponseType<AuthToken>(StatusCodes.Status200OK)]
        [ProducesResponseType<ErrorSimple>(StatusCodes.Status401Unauthorized)]
        public async Task<ActionResult> Login([FromBody] VerificarCredencialesInput credenciales)
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
            // Generar un refresh token
            var refreshToken = GenerateRefreshToken();

            // Almacenar el refresh token en la base de datos
            _context.RefreshTokens.Add(new RefreshToken
            {
                UsuarioId = usuario.UsuarioId,
                Token = refreshToken,
                FechaDeCreacion = DateTime.UtcNow,
                EstaRevocada = false,
                FechaDeExpiracion = DateTime.UtcNow.AddHours(4),
                FechaDeRevocacion = null
            });
            await _context.SaveChangesAsync().ConfigureAwait(false);

            // Retornar el token e información básica del usuario
            var usuarioDTO = _mapper.Map<PostUsuarioDTO>(usuario);

            return Ok(new AuthToken
            {
                AccessToken = tokenString,
                Expiration = token.ValidTo.ToUniversalTime(),
                RefreshToken = refreshToken,
                User = usuarioDTO
            });
        }

        /// <summary>
        /// Crea un nuevo Access Token y Refresh Token a partir de un Access Token expirado y un Refresh Token válido.
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        /// <response code="200">Nuevo Auth Token</response>
        /// <response code="401">Access or Refresh Token son inválidos.</response>
        [HttpPost("refresh")]
        [ProducesResponseType<RefreshAuthToken>(StatusCodes.Status200OK)]
        [ProducesResponseType<ErrorSimple>(StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> Refresh([FromBody] TokenRefreshRequestInput model)
        {
            // Obtener el principal del token expirado
            var principal = GetPrincipalFromExpiredToken(model.AccessToken);
            var rawUserId = principal.FindFirst(AuthenticationHelper.UserIdClaimName)?.Value;
            if (rawUserId == null || !int.TryParse(rawUserId, out var userId))
            {
                return Unauthorized(new ErrorSimple(101, "Access token es Invalido."));
            }

            // Verificar que el refresh token sea válido
            var savedRefreshToken = await _context.RefreshTokens
                .FirstOrDefaultAsync(x => x.Token == model.RefreshToken && x.UsuarioId == userId && !x.EstaRevocada);

            if (savedRefreshToken == null || savedRefreshToken.FechaDeExpiracion <= DateTime.UtcNow)
            {
                return Unauthorized(new ErrorSimple(102, "Refresh token es Invalido o expirado."));
            }

            // Revocar el refresh token actual para que no pueda ser usado nuevamente
            savedRefreshToken.EstaRevocada = true;
            savedRefreshToken.FechaDeRevocacion = DateTime.UtcNow;

            // Generar un nuevo refresh token
            var newRefreshToken = GenerateRefreshToken();
            var newRefreshTokenEntity = new RefreshToken
            {
                Token = newRefreshToken,
                UsuarioId = userId,
                FechaDeExpiracion = DateTime.UtcNow.AddHours(4),
                FechaDeCreacion = DateTime.UtcNow
            };
            _context.RefreshTokens.Add(newRefreshTokenEntity);

            // Generar un nuevo access token
            GenerateJwtToken(principal.Claims, out var token, out var newAccessToken);

            // Almacenar los cambios en la base de datos
            await _context.SaveChangesAsync();

            return Ok(new RefreshAuthToken
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken,
                Expiration = token.ValidTo.ToUniversalTime()
            });
        }

        /// <summary>
        /// Revoca un Refresh Token.
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        /// <response code="204"></response>
        /// <response code="400">Token invalido</response>
        [HttpPost("revoke")]
        public async Task<IActionResult> Revoke([FromBody] RevokeTokenRequestInput model)
        {
            var refreshToken = await _context.RefreshTokens
                .FirstOrDefaultAsync(x => x.Token == model.RefreshToken);

            if (refreshToken == null)
                return BadRequest("Token invalido");

            refreshToken.EstaRevocada = true;
            refreshToken.FechaDeRevocacion = DateTime.UtcNow;

            await _context.SaveChangesAsync();

            return NoContent();
        }

        private ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_jwtKey)),
                ValidateLifetime = false // We are validating an expired token here
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
            var jwtSecurityToken = securityToken as JwtSecurityToken;

            if (jwtSecurityToken == null ||
                !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            {
                throw new SecurityTokenException("Invalid token");
            }

            return principal;
        }

        private void GenerateJwtToken(IEnumerable<Claim> claims, out SecurityToken token, out string tokenString)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_jwtKey);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(3), // Token de vida corta
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            token = tokenHandler.CreateToken(tokenDescriptor);
            tokenString = tokenHandler.WriteToken(token);
        }

        private void GenerateJwtToken(Usuario usuario, out SecurityToken token, out string tokenString)
        {
            var claims = new Claim[]
                {
                    new Claim(ClaimTypes.Name, usuario.Nombres),
                    new Claim(ClaimTypes.NameIdentifier, usuario.Email),
                    new Claim(ClaimTypes.Email, usuario.Email),
                    new Claim(AuthenticationHelper.UserIdClaimName, usuario.UsuarioId.ToString())
                };

            GenerateJwtToken(claims, out token, out tokenString);
        }

        private string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }
    }
}
