using System.Text;
using System.Text.RegularExpressions;

namespace Api;

public record LoginRequest(string? Usuario, string? Contrasena);

public record UsuarioGuardar(string? NombreUsuario, string? Contrasena, string? Rol);

public record UsuarioDto(int Id, string NombreUsuario, string Rol);

public record LoginResponse(string Token, DateTime ExpiraUtc, UsuarioDto Usuario);

public static class Reglas
{
    public static readonly string[] Roles = ["Administrador", "Coordinador", "Docente", "Alumno"];

    private static readonly Regex NombreRx = new("^[a-z0-9_.-]{3,50}$");

    /// <summary>Valida las entradas del servidor. Devuelve null si todo es correcto.</summary>
    public static string? Validar(string nombreNormalizado, string? contrasena, string? rol, bool contrasenaObligatoria)
    {
        if (!NombreRx.IsMatch(nombreNormalizado))
            return "El usuario debe tener de 3 a 50 caracteres (letras, números, punto, guion o guion bajo).";

        if (string.IsNullOrEmpty(contrasena))
        {
            if (contrasenaObligatoria) return "La contraseña es obligatoria.";
        }
        else
        {
            if (contrasena.Length < 8) return "La contraseña debe tener al menos 8 caracteres.";
            // BCrypt solo procesa los primeros 72 bytes.
            if (Encoding.UTF8.GetByteCount(contrasena) > 72) return "La contraseña es demasiado larga (máximo 72 bytes).";
        }

        if (rol is null || !Roles.Contains(rol))
            return "El rol no es válido.";

        return null;
    }
}
