using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using TrackingSystem.DataModel;

namespace TrackingSystem.Backend.Auth
{
    // Clase para manejar la autenticación básica
    // No se recomienda utilizar este tipo de autenticación en un ambiente de producción
    public class BasicAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        private readonly TrackingDataContext _dbContext;

        public BasicAuthenticationHandler(
            IOptionsMonitor<AuthenticationSchemeOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            TrackingDataContext dbContext
            ) : base(options, logger, encoder)
        {
            _dbContext = dbContext;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var authHeader = Request.Headers["Authorization"].ToString();
            if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Basic "))
            {
                return AuthenticateResult.NoResult();
            }

            var encodedCredentials = authHeader.Substring("Basic ".Length).Trim();
            var decodedBytes = Convert.FromBase64String(encodedCredentials);
            var decodedString = Encoding.UTF8.GetString(decodedBytes);
            var credentials = decodedString.Split(':');

            if (credentials.Length != 2)
            {
                return AuthenticateResult.Fail("Formato del 'authorization header' es incorrecto.");
            }

            var username = credentials[0];
            var password = credentials[1];

            // Verificar si el usuario y contraseña son correctos
            var usuario = await VerifyPasswordAsync(username, password);
            if (usuario == null)
            {
                return AuthenticateResult.Fail("Credenciales incorrectas");
            }

            var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, username),
                    new Claim(BasicAuthenticationHelper.UserIdClaimName, usuario.UsuarioId.ToString())
                };

            var identity = new ClaimsIdentity(claims, Scheme.Name);
            var principal = new ClaimsPrincipal(identity);

            return AuthenticateResult.Success(new AuthenticationTicket(principal, Scheme.Name));


        }

        private async Task<Usuario?> VerifyPasswordAsync(string userName, string password)
        {
            // NOTA: Este método es solo para fines de demostración.
            // Se debe de utilizar algun tipo de CACHE para no estar consultando la base de datos en cada petición.

            var user = await _dbContext.Usuarios
                .Where(m => m.Email == userName)
                .SingleOrDefaultAsync();

            if (user == null)
            {
                return null;
            }
            var hashedPassword = BasicAuthenticationHelper.GetPasswordHash(password);

            if (hashedPassword == user.PasswordHash)
            {
                return user;
            }

            return null;
        }


    }

}
