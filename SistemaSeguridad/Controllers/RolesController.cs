using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using SistemaSeguridad.Models.ViewModels;
using SistemaSeguridad.Security;

namespace SistemaSeguridad.Controllers
{
    [Authorize(Roles = "Administrador")]
    public class RolesController : Controller
    {
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly UserManager<IdentityUser> _userManager;

        public RolesController(
            RoleManager<IdentityRole> roleManager,
            UserManager<IdentityUser> userManager)
        {
            _roleManager = roleManager;
            _userManager = userManager;
        }

        // ===============================
        // LISTADO
        // ===============================
        public async Task<IActionResult> Index()
        {
            var roles = _roleManager.Roles.ToList();
            var model = new System.Collections.Generic.List<RoleViewModel>();

            foreach (var role in roles)
            {
                var usersInRole = await _userManager.GetUsersInRoleAsync(role.Name!);

                model.Add(new RoleViewModel
                {
                    Id = role.Id,
                    Name = role.Name!,
                    UsersCount = usersInRole.Count
                });
            }

            return View(model);
        }

        // ===============================
        // DETAILS
        // ===============================
        public async Task<IActionResult> Details(string id)
        {
            if (id == null) return NotFound();

            var role = await _roleManager.FindByIdAsync(id);
            if (role == null) return NotFound();

            var usersInRole = await _userManager.GetUsersInRoleAsync(role.Name!);

            ViewBag.Users = usersInRole;

            return View(new RoleViewModel
            {
                Id = role.Id,
                Name = role.Name!,
                UsersCount = usersInRole.Count
            });
        }

        // ===============================
        // CREATE
        // ===============================
        public IActionResult Create()
        {
            return View(new RoleViewModel());
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(RoleViewModel model)
        {
            if (!ModelState.IsValid) return View(model);

            if (await _roleManager.RoleExistsAsync(model.Name))
            {
                ModelState.AddModelError(string.Empty, "Ya existe un rol con ese nombre.");
                return View(model);
            }

            var result = await _roleManager.CreateAsync(new IdentityRole(model.Name));

            if (result.Succeeded)
            {
                TempData["SuccessMessage"] = "Rol creado correctamente.";
                return RedirectToAction(nameof(Index));
            }

            foreach (var error in result.Errors)
                ModelState.AddModelError(string.Empty, error.Description);

            return View(model);
        }

        // ===============================
        // EDIT
        // ===============================
        public async Task<IActionResult> Edit(string id)
        {
            if (id == null) return NotFound();

            var role = await _roleManager.FindByIdAsync(id);
            if (role == null) return NotFound();

            return View(new RoleViewModel
            {
                Id = role.Id,
                Name = role.Name!
            });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(string id, RoleViewModel model)
        {
            if (id != model.Id) return NotFound();
            if (!ModelState.IsValid) return View(model);

            var role = await _roleManager.FindByIdAsync(id);
            if (role == null) return NotFound();

            var existingRole = await _roleManager.FindByNameAsync(model.Name);
            if (existingRole != null && existingRole.Id != role.Id)
            {
                ModelState.AddModelError(string.Empty, "Ya existe otro rol con ese nombre.");
                return View(model);
            }

            role.Name = model.Name;
            var result = await _roleManager.UpdateAsync(role);

            if (result.Succeeded)
            {
                TempData["SuccessMessage"] = "Rol actualizado correctamente.";
                return RedirectToAction(nameof(Index));
            }

            foreach (var error in result.Errors)
                ModelState.AddModelError(string.Empty, error.Description);

            return View(model);
        }

        // ===============================
        // DELETE
        // ===============================
        public async Task<IActionResult> Delete(string id)
        {
            if (id == null) return NotFound();

            var role = await _roleManager.FindByIdAsync(id);
            if (role == null) return NotFound();

            var usersInRole = await _userManager.GetUsersInRoleAsync(role.Name!);

            return View(new RoleViewModel
            {
                Id = role.Id,
                Name = role.Name!,
                UsersCount = usersInRole.Count
            });
        }

        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(string id)
        {
            var role = await _roleManager.FindByIdAsync(id);
            if (role == null) return NotFound();

            // 🔒 NO eliminar rol Administrador
            if (role.Name!.Equals("Administrador", System.StringComparison.OrdinalIgnoreCase))
            {
                TempData["ErrorMessage"] = "No se puede eliminar el rol Administrador.";
                return RedirectToAction(nameof(Index));
            }

            var usersInRole = await _userManager.GetUsersInRoleAsync(role.Name!);
            if (usersInRole.Any())
            {
                TempData["ErrorMessage"] = "No se puede eliminar un rol con usuarios asignados.";
                return RedirectToAction(nameof(Index));
            }

            await _roleManager.DeleteAsync(role);

            TempData["SuccessMessage"] = "Rol eliminado correctamente.";
            return RedirectToAction(nameof(Index));
        }

        // ===============================
        // MANAGE PERMISSIONS
        // ===============================
        public async Task<IActionResult> ManagePermissions(string id)
        {
            if (id == null) return NotFound();

            var role = await _roleManager.FindByIdAsync(id);
            if (role == null) return NotFound();

            var roleClaims = await _roleManager.GetClaimsAsync(role);

            var model = new ManageRolePermissionsViewModel
            {
                RoleId = role.Id,
                RoleName = role.Name!
            };

            foreach (var perm in Permissions.All)
            {
                model.Permissions.Add(new PermissionSelectionViewModel
                {
                    Name = perm,
                    DisplayName = perm.Replace(".", " - "),
                    IsSelected = roleClaims.Any(c => c.Type == "permission" && c.Value == perm)
                });
            }

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ManagePermissions(ManageRolePermissionsViewModel model)
        {
            var role = await _roleManager.FindByIdAsync(model.RoleId);
            if (role == null) return NotFound();

            var isAdminRole = role.Name!.Equals("Administrador", System.StringComparison.OrdinalIgnoreCase);

            var currentClaims = await _roleManager.GetClaimsAsync(role);
            var currentPermissions = currentClaims
                .Where(c => c.Type == "permission")
                .Select(c => c.Value)
                .ToList();

            var selectedPermissions = model.Permissions
                .Where(p => p.IsSelected)
                .Select(p => p.Name)
                .ToList();

            // 🔒 PROTECCIÓN ADMIN
            if (isAdminRole && currentPermissions.Any(p => !selectedPermissions.Contains(p)))
            {
                TempData["ErrorMessage"] = "No se pueden eliminar permisos del rol Administrador.";
                return RedirectToAction(nameof(ManagePermissions), new { id = role.Id });
            }

            // Quitar permisos
            foreach (var perm in currentPermissions.Where(p => !selectedPermissions.Contains(p)))
            {
                var claim = currentClaims.First(c => c.Type == "permission" && c.Value == perm);
                await _roleManager.RemoveClaimAsync(role, claim);
            }

            // Agregar permisos
            foreach (var perm in selectedPermissions.Where(p => !currentPermissions.Contains(p)))
            {
                await _roleManager.AddClaimAsync(role, new Claim("permission", perm));
            }

            TempData["SuccessMessage"] = "Permisos actualizados correctamente.";
            return RedirectToAction(nameof(Index));
        }
    }
}
