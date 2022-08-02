using AuthNET6.API.Contexts;
using AuthNET6.API.Models;
using AuthNET6.API.Security;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;

namespace AuthNET6.API.Extensions;

public static class DependencyInjectionExtension
{
    public static IServiceCollection AddIdentityDependencyInjectionExtension(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddDbContext<ApplicationDbContext>(options
            => options.UseSqlServer(configuration.GetConnectionString("DefaultConnection")));

        services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

        return services;
    }

    public static IServiceCollection AddSecurityDependencyInjectionExtension(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddScoped<ITokenSecurity, TokenSecurity>();

        var key = Encoding.ASCII.GetBytes(configuration["JWT:ApiKey"]);

        services.AddAuthentication(x =>
            {
                x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(x =>
            {
                x.RequireHttpsMetadata = false;
                x.SaveToken = true;

                x.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false
                };
            });

        return services;
    }

    public static void AddSwaggerDependencyInjectionExtension(this IServiceCollection services)
    {
        services.AddSwaggerGen(options =>
        {
            options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme()
            {
                Name = "Authorization",
                Type = SecuritySchemeType.ApiKey,
                Scheme = "Bearer",
                BearerFormat = "JWT",
                In = ParameterLocation.Header,
                Description = "JWT Authorization header using the Bearer scheme."
            });

            options.AddSecurityDefinition("ApiKey", new OpenApiSecurityScheme()
            {
                Name = "ApiKey",
                Type = SecuritySchemeType.ApiKey,
                In = ParameterLocation.Header,
                Description = "ApiKey Authorization header"
            });

            options.AddSecurityRequirement(new OpenApiSecurityRequirement
            {
                {
                    new OpenApiSecurityScheme
                    {
                        Reference = new OpenApiReference
                        {
                            Type = ReferenceType.SecurityScheme,
                            Id = "Bearer"
                        },
                    },

                    Array.Empty<string>()
                }
            });

            options.AddSecurityRequirement(new OpenApiSecurityRequirement
            {
                {
                    new OpenApiSecurityScheme
                    {
                        Reference = new OpenApiReference
                        {
                            Type = ReferenceType.SecurityScheme,
                            Id = "ApiKey"
                        },
                    },

                    Array.Empty<string>()
                }
            });
        });
    }

    public static WebApplication UseSwaggerDependencyInjectionExtension(this WebApplication app)
    {
        app.UseSwagger();

        app.UseSwaggerUI(options =>
        {
            options.DefaultModelsExpandDepth(-1);
        });

        return app;
    }

    public static async Task<WebApplication> UseDatabaseDependencyInjectionExtension(this WebApplication app)
    {
        using var scope = app.Services.CreateScope();

        var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

        await context.Database.MigrateAsync();

        if (context.Users.Any()) return app;

        var user = new ApplicationUser
        {
            Email = "user@domain.com",
            NormalizedEmail = "USER@DOMAIN.COM",
            UserName = "user@domain.com",
            NormalizedUserName = "USER@DOMAIN.COM",
            EmailConfirmed = true,
            SecurityStamp = Guid.NewGuid().ToString("D")
        };

        var password = new PasswordHasher<ApplicationUser>();

        var hashed = password.HashPassword(user, "User@123");

        user.PasswordHash = hashed;

        context.Users.Add(user);

        await context.SaveChangesAsync();

        return app;
    }
}