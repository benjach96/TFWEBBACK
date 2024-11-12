namespace TrackingSystem.Backend.Swagger.Filters
{
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.OpenApi.Models;
    using Swashbuckle.AspNetCore.SwaggerGen;
    using TrackingSystem.Backend.Entities;

    public class GlobalExceptionResponseOperationFilter : IOperationFilter
    {
        public void Apply(OpenApiOperation operation, OperationFilterContext context)
        {
            // Check if a response with the same status code already exists
            if (!operation.Responses.ContainsKey("500"))
            {
                var errorSchema = context.SchemaGenerator.GenerateSchema(typeof(ErrorSimple), context.SchemaRepository);

                operation.Responses.Add("500", new OpenApiResponse
                {
                    Description = "Internal Server Error",
                    Content = new Dictionary<string, OpenApiMediaType>
                {
                    {
                        "application/json", new OpenApiMediaType
                        {
                            Schema = errorSchema
                        }
                    }
                }
                });
            }
        }
    }
}
