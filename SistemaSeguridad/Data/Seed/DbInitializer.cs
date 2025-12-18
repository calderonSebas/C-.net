using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace SistemaSeguridad.Data
{
    public static class DbInitializer
    {
        public static async Task SeedAsync(IServiceProvider service)
        {
            using var scope = service.CreateScope();
            var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();

            // ================================
            //   1. ROLES INICIALES DEL SISTEMA
            // ================================
            string[] roles = new[]
            {
                "Administrador",
                "Almacenista",
                "Tecnico",
                "Secretario"
            };

            foreach (var roleName in roles)
            {
                if (!await roleManager.RoleExistsAsync(roleName))
                {
                    var roleResult = await roleManager.CreateAsync(new IdentityRole(roleName));
                    if (!roleResult.Succeeded)
                    {
                        throw new Exception($"Error creando rol '{roleName}': " +
                            string.Join("; ", roleResult.Errors.Select(e => e.Description)));
                    }
                }
            }

            // ================================
            //   2. USUARIO ADMINISTRADOR
            // ================================
            var adminEmail = "admin@sigot.com";
            var adminPassword = "Admin123$";

            var adminUser = await userManager.FindByEmailAsync(adminEmail);

            if (adminUser == null)
            {
                adminUser = new IdentityUser
                {
                    UserName = adminEmail,
                    Email = adminEmail,
                    EmailConfirmed = true
                };

                var result = await userManager.CreateAsync(adminUser, adminPassword);

                if (!result.Succeeded)
                    throw new Exception("Error creando usuario admin: " +
                        string.Join("; ", result.Errors.Select(e => e.Description)));
            }

            // Asignar TODOS los roles al admin
            foreach (var role in roles)
            {
                if (!await userManager.IsInRoleAsync(adminUser, role))
                {
                    var addRoleResult = await userManager.AddToRoleAsync(adminUser, role);
                    if (!addRoleResult.Succeeded)
                    {
                        throw new Exception($"Error asignando rol '{role}' al admin: " +
                            string.Join("; ", addRoleResult.Errors.Select(e => e.Description)));
                    }
                }
            }

            // ================================
            //   3. USUARIO TÉCNICO (opcional)
            // ================================
            var tecnicoEmail = "tecnico@sigot.com";
            var tecnicoPassword = "Tecnico123$";

            var tecnicoUser = await userManager.FindByEmailAsync(tecnicoEmail);

            if (tecnicoUser == null)
            {
                tecnicoUser = new IdentityUser
                {
                    UserName = tecnicoEmail,
                    Email = tecnicoEmail,
                    EmailConfirmed = true
                };

                var result = await userManager.CreateAsync(tecnicoUser, tecnicoPassword);

                if (!result.Succeeded)
                    throw new Exception("Error creando usuario técnico: " +
                        string.Join("; ", result.Errors.Select(e => e.Description)));
            }

            // Asignar solo rol Tecnico
            if (!await userManager.IsInRoleAsync(tecnicoUser, "Tecnico"))
            {
                var addRoleResult = await userManager.AddToRoleAsync(tecnicoUser, "Tecnico");
                if (!addRoleResult.Succeeded)
                {
                    throw new Exception("Error asignando rol Tecnico al usuario técnico: " +
                        string.Join("; ", addRoleResult.Errors.Select(e => e.Description)));
                }
            }

            // ================================
            //   LISTO ✔️ Seed SIGOT creado
            // ================================
        }
    }
}
