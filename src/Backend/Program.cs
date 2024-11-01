
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.OpenApi.Models;
using TrackingSystem.Backend.Auth;
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

            builder.Services.AddDbContext<TrackingDataContext>((options) =>
            {
                options.UseSqlServer(config.GetConnectionString("DefaultConnection"));
            });


            // Authentication BASICA usando "usuario y password". Es necesario agregar el servicio de autenticación
            builder.Services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = "Basic";
                options.DefaultChallengeScheme = "Basic";
            })
            .AddScheme<AuthenticationSchemeOptions, BasicAuthenticationHandler>("Basic", null);

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
            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen(c =>
            {
                c.AddSecurityDefinition("basic", new OpenApiSecurityScheme
                {
                    Type = SecuritySchemeType.Http,
                    Scheme = "basic",
                    Description = "Basic Authorization header usando el esquema Bearer."
                });

                c.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference
                            {
                                Type = ReferenceType.SecurityScheme,
                                Id = "basic"
                            }
                        },
                        new string[] { }
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

            app.UseCors("AllowAll"); // Apply CORS globally to allow all origins

            app.UseAuthorization();

            app.MapControllers();

            app.Run();
        }
    }
}
