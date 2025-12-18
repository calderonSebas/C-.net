using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using SistemaSeguridad.Models.ViewModels;

namespace SistemaSeguridad.Controllers
{
    [Authorize(Roles = "Administrador")]
    public class UsersController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public UsersController(
            UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
        }

        // ===============================
        // HELPERS
        // ===============================
        private async Task<bool> IsAdminUser(IdentityUser user)
        {
            var roles = await _userManager.GetRolesAsync(user);
            return roles.Any(r => r.Equals("Administrador", System.StringComparison.OrdinalIgnoreCase));
        }

        // ===============================
        // INDEX
        // ===============================
        public async Task<IActionResult> Index()
        {
            var users = _userManager.Users.ToList();
            var model = new System.Collections.Generic.List<UserViewModel>();

            foreach (var user in users)
            {
                var roles = await _userManager.GetRolesAsync(user);

                model.Add(new UserViewModel
                {
                    Id = user.Id,
                    Email = user.Email ?? user.UserName ?? string.Empty,
                    UserName = user.UserName,
                    EmailConfirmed = user.EmailConfirmed,
                    LockoutEnabled = user.LockoutEnabled,
                    LockoutEnd = user.LockoutEnd,
                    Roles = roles
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

            var user = await _userManager.FindByIdAsync(id);
            if (user == null) return NotFound();

            return View(new UserViewModel
            {
                Id = user.Id,
                Email = user.Email ?? user.UserName ?? string.Empty,
                UserName = user.UserName,
                EmailConfirmed = user.EmailConfirmed,
                LockoutEnabled = user.LockoutEnabled,
                LockoutEnd = user.LockoutEnd,
                Roles = await _userManager.GetRolesAsync(user)
            });
        }

        // ===============================
        // MANAGE ROLES
        // ===============================
        public async Task<IActionResult> ManageRoles(string id)
        {
            if (id == null) return NotFound();

            var user = await _userManager.FindByIdAsync(id);
            if (user == null) return NotFound();

            var model = new ManageUserRolesViewModel
            {
                UserId = user.Id,
                Email = user.Email ?? user.UserName ?? string.Empty,
                UserName = user.UserName
            };

            var allRoles = _roleManager.Roles.ToList();
            var userRoles = await _userManager.GetRolesAsync(user);

            foreach (var role in allRoles)
            {
                model.Roles.Add(new RoleSelectionViewModel
                {
                    RoleId = role.Id,
                    RoleName = role.Name!,
                    IsSelected = userRoles.Contains(role.Name!)
                });
            }

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ManageRoles(ManageUserRolesViewModel model)
        {
            var user = await _userManager.FindByIdAsync(model.UserId);
            if (user == null) return NotFound();

            // 🔒 NO modificar roles de admins
            if (await IsAdminUser(user))
            {
                TempData["ErrorMessage"] = "No se pueden modificar los roles de un usuario Administrador.";
                return RedirectToAction(nameof(Index));
            }

            var currentRoles = await _userManager.GetRolesAsync(user);
            var selectedRoles = model.Roles.Where(r => r.IsSelected).Select(r => r.RoleName).ToList();

            await _userManager.RemoveFromRolesAsync(user, currentRoles.Except(selectedRoles));
            await _userManager.AddToRolesAsync(user, selectedRoles.Except(currentRoles));

            TempData["SuccessMessage"] = "Roles del usuario actualizados.";
            return RedirectToAction(nameof(Index));
        }

        // ===============================
        // LOCK / UNLOCK
        // ===============================
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Lock(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null) return NotFound();

            if (await IsAdminUser(user))
            {
                TempData["ErrorMessage"] = "No se puede bloquear un usuario Administrador.";
                return RedirectToAction(nameof(Index));
            }

            user.LockoutEnabled = true;
            user.LockoutEnd = System.DateTimeOffset.UtcNow.AddYears(1);

            await _userManager.UpdateAsync(user);

            TempData["SuccessMessage"] = "Usuario bloqueado correctamente.";
            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Unlock(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null) return NotFound();

            if (await IsAdminUser(user))
            {
                TempData["ErrorMessage"] = "No se puede modificar un usuario Administrador.";
                return RedirectToAction(nameof(Index));
            }

            user.LockoutEnd = null;
            user.LockoutEnabled = false;

            await _userManager.UpdateAsync(user);

            TempData["SuccessMessage"] = "Usuario desbloqueado correctamente.";
            return RedirectToAction(nameof(Index));
        }
    }
}
