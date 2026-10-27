using Microsoft.EntityFrameworkCore;

namespace Api;

public class Usuario
{
    public int Id { get; set; }
    public string NombreUsuario { get; set; } = string.Empty;

    // Nunca se guarda la contraseña: solo el hash BCrypt (incluye sal y factor de costo).
    public string PasswordHash { get; set; } = string.Empty;

    public string Rol { get; set; } = string.Empty;
}

public class AppDb(DbContextOptions<AppDb> options) : DbContext(options)
{
    public DbSet<Usuario> Usuarios => Set<Usuario>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Usuario>(e =>
        {
            e.ToTable("usuarios");
            e.HasIndex(u => u.NombreUsuario).IsUnique();
            e.Property(u => u.NombreUsuario).HasMaxLength(50).IsRequired();
            e.Property(u => u.PasswordHash).HasMaxLength(100).IsRequired();
            e.Property(u => u.Rol).HasMaxLength(30).IsRequired();
        });
    }
}
