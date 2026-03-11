using AuthApp.Interfaces;
using AuthApp.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace AuthApp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly IInputValidationService _validationService;

        public AuthController(IAuthService authService, IInputValidationService validationService)
        {
            _authService = authService;
            _validationService = validationService;
        }

        // ── POST /api/auth/register ───────────────────────────────────────────────
        /// <summary>Register a new user account (role defaults to "User").</summary>
        [HttpPost("register")]
        [AllowAnonymous]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            if (!ModelState.IsValid) return BadRequest(ModelState);

            if (_validationService.ContainsMaliciousContent(request.Username) ||
                _validationService.ContainsMaliciousContent(request.Email))
                return BadRequest(new { Message = "Input contains potentially malicious content." });

            if (!_validationService.IsValidUsername(request.Username))
                return BadRequest(new { Message = "Invalid username format." });

            if (!_validationService.IsValidEmail(request.Email))
                return BadRequest(new { Message = "Invalid email format." });

            if (!IsPasswordStrong(request.Password))
                return BadRequest(new { Message = "Password must be at least 8 characters and include uppercase, lowercase, digit, and special character." });

            var user = await _authService.RegisterAsync(request);
            if (user == null)
                return Conflict(new { Message = "Username or email already exists." });

            return CreatedAtAction(nameof(Register), new
            {
                Message = "Registration successful.",
                Username = user.Username,
                Role = user.Role
            });
        }

        // ── POST /api/auth/login ──────────────────────────────────────────────────
        /// <summary>Authenticate and receive a JWT + refresh token.</summary>
        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] AppLoginRequest request)
        {
            if (!ModelState.IsValid) return BadRequest(ModelState);

            // Reject obviously malicious payloads early
            if (_validationService.ContainsMaliciousContent(request.Username))
                return BadRequest(new { Message = "Invalid input." });

            var user = await _authService.ValidateCredentialsAsync(request.Username, request.Password);
            if (user == null)
                // Generic message prevents username enumeration
                return Unauthorized(new { Message = "Invalid credentials or account is locked." });

            var response = _authService.GenerateTokens(user);
            return Ok(response);
        }

        // ── POST /api/auth/refresh ────────────────────────────────────────────────
        /// <summary>Rotate an expired JWT using a valid refresh token.</summary>
        [HttpPost("refresh")]
        [AllowAnonymous]
        public async Task<IActionResult> Refresh([FromBody] RefreshTokenRequest request)
        {
            if (!ModelState.IsValid) return BadRequest(ModelState);

            var response = await _authService.RefreshTokensAsync(request.RefreshToken);
            if (response == null)
                return Unauthorized(new { Message = "Invalid or expired refresh token." });

            return Ok(response);
        }

        // ── POST /api/auth/logout ─────────────────────────────────────────────────
        /// <summary>Revoke the current refresh token (server-side logout).</summary>
        [HttpPost("logout")]
        [Authorize]
        public async Task<IActionResult> Logout([FromBody] RefreshTokenRequest request)
        {
            await _authService.RevokeRefreshTokenAsync(request.RefreshToken);
            return Ok(new { Message = "Logged out successfully." });
        }

        // ── GET /api/auth/me ──────────────────────────────────────────────────────
        /// <summary>Return the profile of the currently authenticated user.</summary>
        [HttpGet("me")]
        [Authorize]
        public async Task<IActionResult> Me()
        {
            var username = User.FindFirstValue(ClaimTypes.Name)
                           ?? User.FindFirstValue(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.UniqueName);

            if (username == null) return Unauthorized();

            var user = await _authService.GetUserByUsernameAsync(username);
            if (user == null) return NotFound();

            return Ok(new
            {
                user.Id,
                user.Username,
                user.Email,
                user.Role,
                user.CreatedAt,
                user.LastLoginAt
            });
        }

        // ── Helpers ───────────────────────────────────────────────────────────────
        private static bool IsPasswordStrong(string password) =>
            password.Length >= 8 &&
            password.Any(char.IsUpper) &&
            password.Any(char.IsLower) &&
            password.Any(char.IsDigit) &&
            password.Any(c => !char.IsLetterOrDigit(c));
    }
}