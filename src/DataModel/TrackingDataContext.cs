using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore;

namespace TrackingSystem.DataModel;

public partial class TrackingDataContext : DbContext
{
    public TrackingDataContext()
    {
    }

    public TrackingDataContext(DbContextOptions<TrackingDataContext> options)
        : base(options)
    {
    }

    public virtual DbSet<Cliente> Clientes { get; set; }


    public virtual DbSet<Envio> Envios { get; set; }

    public virtual DbSet<Fabrica> Fabricas { get; set; }
    public virtual DbSet<Conductor> Conductores { get; set; }

    public virtual DbSet<OrdenDeTrabajo> OrdenesDeTrabajo { get; set; }

    public virtual DbSet<OrdenPorUsuario> OrdenesPorUsuario { get; set; }

    public virtual DbSet<RastreoEnTiempoReal> RastreosEnTiempoReal { get; set; }

    public virtual DbSet<Usuario> Usuarios { get; set; }

    //    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    //        => optionsBuilder.UseSqlServer("Server=***REMOVED***;Database=tracking;User ID=***REMOVED***;Password=***REMOVED***");

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Cliente>(entity =>
        {
            entity.ToTable("Cliente");

            entity.Property(e => e.ApellidosDelRepresentante)
                .HasMaxLength(100)
                .IsUnicode(false);
            entity.Property(e => e.Cargo)
                .HasMaxLength(100)
                .IsUnicode(false);
            entity.Property(e => e.Empresa)
                .HasMaxLength(100)
                .IsUnicode(false);
            entity.Property(e => e.Estado)
                .HasMaxLength(1)
                .IsUnicode(false)
                .HasDefaultValue("A")
                .IsFixedLength();
            entity.Property(e => e.NombreDelRepresentante)
                .HasMaxLength(100)
                .IsUnicode(false);
        });


        modelBuilder.Entity<Envio>(entity =>
        {
            entity.ToTable("Envio");

            entity.HasIndex(e => e.OrdenDeTrabajoId, "IX_Relationship6");

            entity.Property(e => e.Estado)
                .HasMaxLength(1)
                .IsUnicode(false)
                .HasDefaultValue("A")
                .IsFixedLength();

            entity.HasOne(d => d.OrdenDeTrabajo).WithMany(p => p.Envios)
                .HasForeignKey(d => d.OrdenDeTrabajoId)
                .OnDelete(DeleteBehavior.ClientSetNull)
                .HasConstraintName("Enviado");
        });

        modelBuilder.Entity<Fabrica>(entity =>
        {
            entity.ToTable("Fabrica");

            entity.Property(e => e.Nombre)
                .HasMaxLength(100)
                .IsUnicode(false);
        });

        modelBuilder.Entity<Conductor>(entity =>
        {
            entity.ToTable("Conductor");

            entity.Property(e => e.Nombres)
                .HasMaxLength(100)
                .IsUnicode(false);

            entity.Property(e => e.Apellidos)
                .HasMaxLength(100)
                .IsUnicode(false);

            entity.Property(e => e.Telefono)
                .HasMaxLength(30)
                .IsUnicode(false);

            entity.Property(e => e.Estado)
                .HasMaxLength(1)
                .IsUnicode(false)
                .HasDefaultValue("A")
                .IsFixedLength();
        });

        modelBuilder.Entity<OrdenDeTrabajo>(entity =>
        {
            entity.ToTable("OrdenDeTrabajo");

            entity.HasIndex(e => e.ClienteId, "IX_Relationship3");

            entity.HasIndex(e => e.FabricaId, "IX_Relationship7");

            entity.Property(e => e.CodigoDeSeguimiento)
                .HasMaxLength(10)
                .IsUnicode(false)
                .IsFixedLength();
            entity.Property(e => e.Descripcion)
                .HasMaxLength(500)
                .IsUnicode(false);
            entity.Property(e => e.DireccionDeEntrega)
                .HasMaxLength(500)
                .IsUnicode(false);
            entity.Property(e => e.Estado)
                .HasMaxLength(1)
                .IsUnicode(false)
                .HasDefaultValue("A")
                .IsFixedLength();
            entity.Property(e => e.LugarDeEntrega)
                .HasMaxLength(100)
                .IsUnicode(false);
            entity.Property(e => e.PesoEnKilos).HasColumnType("decimal(6, 2)");

            entity.HasOne(d => d.Cliente).WithMany(p => p.OrdenDeTrabajos)
                .HasForeignKey(d => d.ClienteId)
                .OnDelete(DeleteBehavior.ClientSetNull)
                .HasConstraintName("Solicita");

            entity.HasOne(d => d.Fabrica).WithMany(p => p.OrdenDeTrabajos)
                .HasForeignKey(d => d.FabricaId)
                .OnDelete(DeleteBehavior.ClientSetNull)
                .HasConstraintName("Producido");
        });

        modelBuilder.Entity<OrdenPorUsuario>(entity =>
        {
            entity.HasKey(e => new { e.UsuarioId, e.OrdenDeTrabajoId });

            entity.ToTable("OrdenPorUsuario");

            entity.HasOne(d => d.OrdenDeTrabajo).WithMany(p => p.OrdenPorUsuarios)
                .HasForeignKey(d => d.OrdenDeTrabajoId)
                .OnDelete(DeleteBehavior.ClientSetNull)
                .HasConstraintName("Asignado");

            entity.HasOne(d => d.Usuario).WithMany(p => p.OrdenPorUsuarios)
                .HasForeignKey(d => d.UsuarioId)
                .OnDelete(DeleteBehavior.ClientSetNull)
                .HasConstraintName("Sigue");
        });

        modelBuilder.Entity<RastreoEnTiempoReal>(entity =>
        {
            entity.HasKey(e => e.RastreoId);

            entity.ToTable("RastreoEnTiempoReal");

            entity.HasIndex(e => e.EnvioId, "IX_Relationship8");

            entity.Property(e => e.Latitud).HasColumnType("decimal(10, 6)");
            entity.Property(e => e.Longitud).HasColumnType("decimal(10, 6)");

            entity.HasOne(d => d.Envio).WithMany(p => p.RastreoEnTiempoReals)
                .HasForeignKey(d => d.EnvioId)
                .OnDelete(DeleteBehavior.ClientSetNull)
                .HasConstraintName("Rastreado");
        });

        modelBuilder.Entity<Usuario>(entity =>
        {
            entity.ToTable("Usuario");

            entity.Property(e => e.UsuarioId).UseIdentityColumn();

            entity.HasIndex(e => e.Email, "Email").IsUnique();

            entity.Property(e => e.Apellidos)
                .HasMaxLength(100)
                .IsUnicode(false);
            entity.Property(e => e.Email)
                .HasMaxLength(100)
                .IsUnicode(false);
            entity.Property(e => e.Estado)
                .HasMaxLength(1)
                .IsUnicode(false)
                .IsFixedLength();
            entity.Property(e => e.Nombres)
                .HasMaxLength(100)
                .IsUnicode(false);
            entity.Property(e => e.PasswordHash)
                .HasMaxLength(50)
                .IsUnicode(false);
        });

        OnModelCreatingPartial(modelBuilder);
    }

    partial void OnModelCreatingPartial(ModelBuilder modelBuilder);
}
