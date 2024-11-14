
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Reflection;
using System.Text;
using System.Xml.XPath;
using TrackingSystem.Backend.Auth;
using TrackingSystem.Backend.Swagger.Filters;
using TrackingSystem.DataModel;

namespace TrackingSystem.Backend
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Agregar servicios al contenedor de la aplicación.

            // Obtener la configuración de la aplicación
            var config = builder.Configuration;

            builder.Services.AddAutoMapper(typeof(TrackingProfile));

            builder.Services.AddMemoryCache();

            builder.Services.AddDbContext<TrackingDataContext>((options) =>
            {
                options.UseSqlServer(config.GetConnectionString("DefaultConnection"));
            });


            // Configurar Autenticación usando JWT Configure JWT
            var key = Encoding.ASCII.GetBytes(config["JWT:Key"]!);

            builder.Services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false, // Para este ejemplo no se valida el emisor
                    ValidateAudience = false, // Para ese ejemplo no se valida el receptor
                    ClockSkew = System.TimeSpan.Zero
                };
            });

            // Configurar CORS para permitir solicitudes desde cualquier origen
            builder.Services.AddCors(options =>
            {
                options.AddPolicy("AllowAll", builder =>
                {
                    builder.AllowAnyOrigin()
                           .AllowAnyMethod()
                           .AllowAnyHeader();
                });
            });


            // Agregar servicios de controladores a la aplicación.
            builder.Services.AddControllers();
            // Agregar Swagger
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen(c =>
            {
                var info = config.GetRequiredSection("SwaggerDoc").Get<OpenApiInfo>();
                if (info == null)
                {
                    throw new InvalidOperationException("No se encontró la configuración de SwaggerDoc en el archivo de configuración.");
                }

                //c.SwaggerDoc("v1", new() { Title = "BetonDecken - Sistema de Seguimiento API", Version = "v1" });
                c.SwaggerDoc(info.Version, info);

                // Documentar los tipos de respuesta
                var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
                var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
                c.IncludeXmlComments(() => new XPathDocument(xmlPath));

                // Agregar filtros globales
                c.OperationFilter<UnauthorizedResponsesOperationFilter>();
                c.OperationFilter<GlobalExceptionResponseOperationFilter>();

                // Agregar Authorizacion tipo Bearer a Swagger
                c.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
                {
                    In = Microsoft.OpenApi.Models.ParameterLocation.Header,
                    Description = "Por favor ingrese JWT dentro del campo Bearer. El token se puede obtener usando /Usuarios/Login",
                    Name = "Authorization",
                    Type = Microsoft.OpenApi.Models.SecuritySchemeType.Http,
                    Scheme = "bearer"
                });
                c.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement()
                {
                    {
                        new Microsoft.OpenApi.Models.OpenApiSecurityScheme
                        {
                            Reference = new Microsoft.OpenApi.Models.OpenApiReference
                            {
                                Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
                                Id = "Bearer"
                            },
                            Scheme = "oauth2",
                            Name = "Bearer",
                            In = Microsoft.OpenApi.Models.ParameterLocation.Header,

                        },
                        new List<string>()
                    }
                });
            });

            var app = builder.Build();

            // Configurar la canalización de solicitudes HTTP.
            if (app.Environment.IsDevelopment())
            {
                // Habilitar la documentación de Swagger
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseHttpsRedirection();

            app.UseCors("AllowAll");

            app.UseAuthentication();
            app.UseAuthorization();

            app.MapControllers();

            app.Run();
        }
    }
}
