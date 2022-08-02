using AspNetCoreRateLimit;
using AuthNET6.API.Extensions;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddIdentityDependencyInjectionExtension(builder.Configuration);

builder.Services.AddSecurityDependencyInjectionExtension(builder.Configuration);

builder.Services.AddSwaggerDependencyInjectionExtension();

builder.Services.AddMemoryCache();

builder.Services.Configure<IpRateLimitOptions>(builder.Configuration.GetSection("IpRateLimiting"));

builder.Services.AddSingleton<IIpPolicyStore, MemoryCacheIpPolicyStore>();

builder.Services.AddSingleton<IRateLimitCounterStore, MemoryCacheRateLimitCounterStore>();

builder.Services.AddSingleton<IRateLimitConfiguration, RateLimitConfiguration>();

builder.Services.AddSingleton<IProcessingStrategy, AsyncKeyLockProcessingStrategy>();

builder.Services.AddInMemoryRateLimiting();

builder.Services.AddControllers();

builder.Services.AddEndpointsApiExplorer();

var app = builder.Build();

if (app.Environment.IsDevelopment()) { }

await app.UseDatabaseDependencyInjectionExtension();

app.UseSwaggerDependencyInjectionExtension();

app.UseIpRateLimiting();

app.UseHttpsRedirection();

app.UseCors(options => options.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader());

app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();

app.Run();