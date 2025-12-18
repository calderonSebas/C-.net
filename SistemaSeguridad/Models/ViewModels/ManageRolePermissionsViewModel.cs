using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace SistemaSeguridad.Models.ViewModels
{
    /// <summary>
    /// Modelo para la pantalla donde se gestionan los permisos de un rol concreto.
    /// </summary>
    public class ManageRolePermissionsViewModel
    {
        [Required]
        public string RoleId { get; set; } = string.Empty;

        [Display(Name = "Rol")]
        public string RoleName { get; set; } = string.Empty;

        /// <summary>
        /// Lista de todos los permisos posibles, marcados o no.
        /// </summary>
        public List<PermissionSelectionViewModel> Permissions { get; set; } = new();
    }
}
