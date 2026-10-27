using System.Security.Claims;
using System.Text;
using System.Threading.RateLimiting;
using Api;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using BCryptNet = BCrypt.Net.BCrypt;

var builder = WebApplication.CreateBuilder(args);
var config = builder.Configuration;

// ---------- Configuración (solo desde variables de entorno / user-secrets, nunca en el código) ----------
var connectionString = config.GetConnectionString("Default")
    ?? throw new InvalidOperationException("Falta la variable de entorno ConnectionStrings__Default.");

var jwtKey = config["Jwt:Key"];
if (string.IsNullOrWhiteSpace(jwtKey) || jwtKey.Length < 32)
    throw new InvalidOperationException("Falta Jwt__Key o es demasiado corta (mínimo 32 caracteres).");

var jwtIssuer = config["Jwt:Issuer"] ?? "App1.Api";
var jwtAudience = config["Jwt:Audience"] ?? "App1.Maui";
var jwtMinutes = config.GetValue("Jwt:Minutes", 60);
var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));

// ---------- Servicios ----------
// EF Core genera consultas parametrizadas: no hay concatenación de SQL (previene inyección SQL).
builder.Services.AddDbContext<AppDb>(o => o.UseNpgsql(connectionString));

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(o =>
    {
        o.MapInboundClaims = false;
        o.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = jwtIssuer,
            ValidateAudience = true,
            ValidAudience = jwtAudience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = signingKey,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromMinutes(1),
            NameClaimType = "name",
            RoleClaimType = "role"
        };
    });

builder.Services.AddAuthorizationBuilder()
    .AddPolicy("Admin", p => p.RequireRole("Administrador"));

// Limita los intentos de login por IP para frenar fuerza bruta.
builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    o.AddPolicy("login", ctx => RateLimitPartition.GetFixedWindowLimiter(
        ctx.Connection.RemoteIpAddress?.ToString() ?? "desconocida",
        _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 8,
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0
        }));
});

var app = builder.Build();

// ---------- Creación de tabla y usuario administrador inicial ----------
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDb>();
    db.Database.EnsureCreated();

    if (!db.Usuarios.Any())
    {
        var seedUser = (config["Seed:AdminUser"] ?? "admin").Trim().ToLowerInvariant();
        var seedPass = config["Seed:AdminPassword"];
        if (string.IsNullOrWhiteSpace(seedPass) || seedPass.Length < 8)
        {
            app.Logger.LogWarning("No hay usuarios y falta Seed__AdminPassword (mínimo 8 caracteres): no se creó el administrador inicial.");
        }
        else
        {
            db.Usuarios.Add(new Usuario
            {
                NombreUsuario = seedUser,
                PasswordHash = BCryptNet.HashPassword(seedPass, 12),
                Rol = "Administrador"
            });
            db.SaveChanges();
            app.Logger.LogInformation("Administrador inicial '{User}' creado.", seedUser);
        }
    }
}

app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

// Hash falso para que el tiempo de respuesta sea parecido exista o no el usuario.
var dummyHash = BCryptNet.HashPassword("contrasena-falsa-para-igualar-tiempos", 12);

(string Token, DateTime Expira) CrearToken(Usuario u)
{
    var expira = DateTime.UtcNow.AddMinutes(jwtMinutes);
    var descriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(new[]
        {
            new Claim("sub", u.Id.ToString()),
            new Claim("name", u.NombreUsuario),
            new Claim("role", u.Rol)
        }),
        Expires = expira,
        Issuer = jwtIssuer,
        Audience = jwtAudience,
        SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256)
    };
    return (new JsonWebTokenHandler().CreateToken(descriptor), expira);
}

// ---------- Endpoints ----------
app.MapGet("/health", () => Results.Ok(new { status = "ok" }));

app.MapPost("/api/auth/login", async (LoginRequest req, AppDb db) =>
{
    var nombre = (req.Usuario ?? string.Empty).Trim().ToLowerInvariant();
    var pass = req.Contrasena ?? string.Empty;

    if (nombre.Length == 0 || pass.Length == 0)
        return Results.BadRequest(new { error = "Ingresa usuario y contraseña." });
    if (nombre.Length > 50 || pass.Length > 128)
        return Results.Json(new { error = "Usuario o contraseña incorrectos." }, statusCode: 401);

    var user = await db.Usuarios.AsNoTracking().FirstOrDefaultAsync(u => u.NombreUsuario == nombre);

    // Siempre se ejecuta BCrypt.Verify (con hash falso si el usuario no existe).
    var valido = BCryptNet.Verify(pass, user?.PasswordHash ?? dummyHash);
    if (user is null || !valido)
    {
        app.Logger.LogWarning("Login fallido para '{User}'.", nombre);
        return Results.Json(new { error = "Usuario o contraseña incorrectos." }, statusCode: 401);
    }

    var (token, expira) = CrearToken(user);
    return Results.Ok(new LoginResponse(token, expira, new UsuarioDto(user.Id, user.NombreUsuario, user.Rol)));
}).RequireRateLimiting("login");

var usuarios = app.MapGroup("/api/usuarios").RequireAuthorization("Admin");

usuarios.MapGet("", async (AppDb db) =>
    Results.Ok(await db.Usuarios.AsNoTracking()
        .OrderBy(u => u.Id)
        .Select(u => new UsuarioDto(u.Id, u.NombreUsuario, u.Rol))
        .ToListAsync()));

usuarios.MapGet("{id:int}", async (int id, AppDb db) =>
{
    var u = await db.Usuarios.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id);
    return u is null
        ? Results.NotFound(new { error = "Usuario no encontrado." })
        : Results.Ok(new UsuarioDto(u.Id, u.NombreUsuario, u.Rol));
});

usuarios.MapPost("", async (UsuarioGuardar req, AppDb db) =>
{
    var nombre = (req.NombreUsuario ?? string.Empty).Trim().ToLowerInvariant();
    var error = Reglas.Validar(nombre, req.Contrasena, req.Rol, contrasenaObligatoria: true);
    if (error is not null) return Results.BadRequest(new { error });

    if (await db.Usuarios.AnyAsync(x => x.NombreUsuario == nombre))
        return Results.Conflict(new { error = "Ese nombre de usuario ya existe." });

    var nuevo = new Usuario
    {
        NombreUsuario = nombre,
        PasswordHash = BCryptNet.HashPassword(req.Contrasena!, 12),
        Rol = req.Rol!
    };
    db.Usuarios.Add(nuevo);

    try { await db.SaveChangesAsync(); }
    catch (DbUpdateException) { return Results.Conflict(new { error = "Ese nombre de usuario ya existe." }); }

    return Results.Created($"/api/usuarios/{nuevo.Id}", new UsuarioDto(nuevo.Id, nuevo.NombreUsuario, nuevo.Rol));
});

usuarios.MapPut("{id:int}", async (int id, UsuarioGuardar req, AppDb db, ClaimsPrincipal caller) =>
{
    var user = await db.Usuarios.FirstOrDefaultAsync(x => x.Id == id);
    if (user is null) return Results.NotFound(new { error = "Usuario no encontrado." });

    var nombre = (req.NombreUsuario ?? string.Empty).Trim().ToLowerInvariant();
    var cambiaPass = !string.IsNullOrEmpty(req.Contrasena);
    var error = Reglas.Validar(nombre, cambiaPass ? req.Contrasena : null, req.Rol, contrasenaObligatoria: false);
    if (error is not null) return Results.BadRequest(new { error });

    if (caller.FindFirst("sub")?.Value == id.ToString() && req.Rol != "Administrador")
        return Results.BadRequest(new { error = "No puedes quitarte a ti mismo el rol de administrador." });

    if (await db.Usuarios.AnyAsync(x => x.NombreUsuario == nombre && x.Id != id))
        return Results.Conflict(new { error = "Ese nombre de usuario ya existe." });

    user.NombreUsuario = nombre;
    user.Rol = req.Rol!;
    if (cambiaPass) user.PasswordHash = BCryptNet.HashPassword(req.Contrasena!, 12);

    try { await db.SaveChangesAsync(); }
    catch (DbUpdateException) { return Results.Conflict(new { error = "Ese nombre de usuario ya existe." }); }

    return Results.Ok(new UsuarioDto(user.Id, user.NombreUsuario, user.Rol));
});

usuarios.MapDelete("{id:int}", async (int id, AppDb db, ClaimsPrincipal caller) =>
{
    if (caller.FindFirst("sub")?.Value == id.ToString())
        return Results.BadRequest(new { error = "No puedes eliminar tu propia cuenta." });

    var user = await db.Usuarios.FirstOrDefaultAsync(x => x.Id == id);
    if (user is null) return Results.NotFound(new { error = "Usuario no encontrado." });

    db.Usuarios.Remove(user);
    await db.SaveChangesAsync();
    return Results.NoContent();
});

app.Run();
