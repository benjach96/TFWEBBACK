using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ApiExplorer;
using Microsoft.OpenApi.Models;
using NuGet.Protocol;
using Swashbuckle.AspNetCore.SwaggerGen;

namespace TrackingSystem.Backend.Swagger.Filters
{
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.OpenApi.Models;
    using Swashbuckle.AspNetCore.SwaggerGen;

    public class UnauthorizedResponsesOperationFilter : IOperationFilter
    {
        public void Apply(OpenApiOperation operation, OperationFilterContext context)
        {
            // Verificar si el controlador o el método tiene el atributo AllowAnonymous
            var declaringType = context.MethodInfo.DeclaringType;
            var hasAllowAnonymous = declaringType != null && (declaringType.GetCustomAttributes(true).OfType<AllowAnonymousAttribute>().Any()
                                     || context.MethodInfo.GetCustomAttributes(true).OfType<AllowAnonymousAttribute>().Any());

            if (!hasAllowAnonymous)
            {
                // Agregar respuesta 401 Unauthorized
                operation.Responses.TryAdd("401", new OpenApiResponse { Description = "Unauthorized" });
            }
        }
    }
}
