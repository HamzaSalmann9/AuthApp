using AuthApp.Interfaces;
using AuthApp.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthApp.Controllers
{
    /// <summary>
    /// Demonstrates Role-Based Access Control (RBAC).
    ///
    ///   GET  /api/admin/users          → Admin only
    ///   PUT  /api/admin/users/role     → Admin only
    ///   GET  /api/admin/reports        → Admin + Manager
    ///   GET  /api/admin/dashboard      → Any authenticated user
    /// </summary>
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]   // All endpoints require authentication unless overridden
    public class AdminController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly IInputValidationService _validationService;

        public AdminController(IAuthService authService, IInputValidationService validationService)
        {
            _authService = authService;
            _validationService = validationService;
        }

        // ── GET /api/admin/users ──────────────────────────────────────────────────
        /// <summary>List all users. Admin only.</summary>
        [HttpGet("users")]
        [Authorize(Roles = Roles.Admin)]
        public async Task<IActionResult> GetAllUsers()
        {
            var users = await _authService.GetAllUsersAsync();

            // Never expose password hashes to callers
            var safeView = users.Select(u => new
            {
                u.Id,
                u.Username,
                u.Email,
                u.Role,
                u.IsActive,
                u.CreatedAt,
                u.LastLoginAt,
                u.FailedLoginAttempts,
                IsLockedOut = u.LockoutUntil.HasValue && u.LockoutUntil > DateTime.UtcNow
            });

            return Ok(safeView);
        }

        // ── PUT /api/admin/users/role ─────────────────────────────────────────────
        /// <summary>Change a user's role. Admin only.</summary>
        [HttpPut("users/role")]
        [Authorize(Roles = Roles.Admin)]
        public async Task<IActionResult> ChangeUserRole([FromBody] ChangeRoleRequest request)
        {
            if (!ModelState.IsValid) return BadRequest(ModelState);

            if (_validationService.ContainsMaliciousContent(request.Username) ||
                _validationService.ContainsMaliciousContent(request.NewRole))
                return BadRequest(new { Message = "Invalid input." });

            if (!Roles.All.Contains(request.NewRole))
                return BadRequest(new { Message = $"Invalid role. Valid roles: {string.Join(", ", Roles.All)}" });

            // Prevent an admin from demoting themselves
            var currentUser = User.Identity?.Name;
            if (currentUser?.Equals(request.Username, StringComparison.OrdinalIgnoreCase) == true)
                return BadRequest(new { Message = "Admins cannot change their own role." });

            var success = await _authService.UpdateUserRoleAsync(request.Username, request.NewRole);
            if (!success)
                return NotFound(new { Message = $"User '{request.Username}' not found." });

            return Ok(new { Message = $"Role updated to '{request.NewRole}' for user '{request.Username}'." });
        }

        // ── GET /api/admin/reports ────────────────────────────────────────────────
        /// <summary>View reports. Admin and Manager only.</summary>
        [HttpGet("reports")]
        [Authorize(Roles = $"{Roles.Admin},{Roles.Manager}")]
        public IActionResult GetReports()
        {
            // In a real app this would query a reporting layer
            var report = new
            {
                GeneratedAt = DateTime.UtcNow,
                GeneratedBy = User.Identity?.Name,
                TotalUsers = 3,
                ActiveSessions = 1,
                RecentActivity = new[]
                {
                    new { Action = "User registered",    Timestamp = DateTime.UtcNow.AddHours(-2) },
                    new { Action = "Password changed",   Timestamp = DateTime.UtcNow.AddHours(-1) },
                    new { Action = "Role updated",       Timestamp = DateTime.UtcNow.AddMinutes(-30) }
                }
            };

            return Ok(report);
        }

        // ── GET /api/admin/dashboard ──────────────────────────────────────────────
        /// <summary>Basic dashboard. Any authenticated user.</summary>
        [HttpGet("dashboard")]
        [Authorize]
        public IActionResult GetDashboard()
        {
            var role = User.FindFirst(System.Security.Claims.ClaimTypes.Role)?.Value;

            // Return role-appropriate content in a single endpoint
            object content = role switch
            {
                Roles.Admin => new { Message = "Welcome, Admin!", Features = new[] { "User Management", "Reports", "System Settings", "Audit Logs" } },
                Roles.Manager => new { Message = "Welcome, Manager!", Features = new[] { "Reports", "Team Overview" } },
                _ => new { Message = "Welcome!", Features = new[] { "Profile", "My Data" } }
            };

            return Ok(new
            {
                User = User.Identity?.Name,
                Role = role,
                Content = content
            });
        }
    }
}