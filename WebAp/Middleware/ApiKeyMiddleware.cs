
namespace WebAp
{

    public class ApiKeyMiddleware
    {
        private readonly RequestDelegate _next;
        private const string APIKEYNAME = "ApiKey";
        public ApiKeyMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            //Jos avainta ei löydy
            if (!context.Request.Headers.TryGetValue(APIKEYNAME, out var extractedApiKey))
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("Api key missing");
                return;
            }

            //Avain löytyy, määritellään avain asetuksista ja tarkistetaan mätsäävyys
            var appSettings = context.RequestServices.GetRequiredService<IConfiguration>();
            var apiKey = appSettings.GetValue<string>(APIKEYNAME);

            //Eli jos arvot ovat erisuuret
            if (!apiKey.Equals(extractedApiKey))
            {
                context.Response.StatusCode = 403;
                await context.Response.WriteAsync("Unauthorized client");
            }
            //Kaikki ookoo, etteenpäin!
            await _next(context);
        }
    }
}