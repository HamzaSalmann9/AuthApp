using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using AuthApp.Interfaces;
using AuthApp.Models;
using Microsoft.IdentityModel.Tokens;

namespace AuthApp.Services
{
    public class AuthService : IAuthService
    {
        private readonly IConfiguration _configuration;
        private readonly IInputValidationService _validationService;

        // ── In-memory stores (swap for EF Core / a real DB in production) ──────
        private static readonly List<AppUser> _users = new();
        private static readonly List<RefreshTokenRecord> _refreshTokens = new();
        private static int _nextId = 1;

        // Lockout policy
        private const int MaxFailedAttempts = 5;
        private static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);

        public AuthService(IConfiguration configuration, IInputValidationService validationService)
        {
            _configuration = configuration;
            _validationService = validationService;
            SeedDefaultUsers();
        }

        // ── Registration ─────────────────────────────────────────────────────────
        public Task<AppUser?> RegisterAsync(RegisterRequest request)
        {
            // Reject malicious payloads
            if (_validationService.ContainsMaliciousContent(request.Username) ||
                _validationService.ContainsMaliciousContent(request.Email))
                return Task.FromResult<AppUser?>(null);

            // Uniqueness check (case-insensitive)
            if (_users.Any(u => u.Username.Equals(request.Username, StringComparison.OrdinalIgnoreCase) ||
                                u.Email.Equals(request.Email, StringComparison.OrdinalIgnoreCase)))
                return Task.FromResult<AppUser?>(null);

            var user = new AppUser
            {
                Id = _nextId++,
                Username = _validationService.SanitizeInput(request.Username),
                Email = _validationService.SanitizeInput(request.Email),
                // BCrypt handles its own salt; work-factor 12 is a good production default
                PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.Password, workFactor: 12),
                Role = Roles.User,
                CreatedAt = DateTime.UtcNow
            };

            _users.Add(user);
            return Task.FromResult<AppUser?>(user);
        }

        // ── Credential validation with lockout ────────────────────────────────────
        public Task<AppUser?> ValidateCredentialsAsync(string username, string password)
        {
            var user = _users.FirstOrDefault(u =>
                u.Username.Equals(username, StringComparison.OrdinalIgnoreCase));

            if (user == null || !user.IsActive)
                return Task.FromResult<AppUser?>(null);

            // Enforce lockout
            if (user.LockoutUntil.HasValue && user.LockoutUntil > DateTime.UtcNow)
                return Task.FromResult<AppUser?>(null);

            if (!BCrypt.Net.BCrypt.Verify(password, user.PasswordHash))
            {
                user.FailedLoginAttempts++;
                if (user.FailedLoginAttempts >= MaxFailedAttempts)
                    user.LockoutUntil = DateTime.UtcNow.Add(LockoutDuration);
                return Task.FromResult<AppUser?>(null);
            }

            // Reset on success
            user.FailedLoginAttempts = 0;
            user.LockoutUntil = null;
            user.LastLoginAt = DateTime.UtcNow;
            return Task.FromResult<AppUser?>(user);
        }

        // ── Token generation ──────────────────────────────────────────────────────
        public AuthResponse GenerateTokens(AppUser user)
        {
            var jwtSettings = _configuration.GetSection("JwtSettings");
            var secretKey = jwtSettings["SecretKey"]
                                ?? throw new InvalidOperationException("JWT SecretKey is not configured.");
            var issuer = jwtSettings["Issuer"] ?? "AuthApp";
            var audience = jwtSettings["Audience"] ?? "AuthApp";
            int expiryMinutes = int.TryParse(jwtSettings["ExpiryMinutes"], out var m) ? m : 60;

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub,   user.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.UniqueName, user.Username),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(ClaimTypes.Role,               user.Role),
                new Claim(JwtRegisteredClaimNames.Jti,   Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat,
                    new DateTimeOffset(DateTime.UtcNow).ToUnixTimeSeconds().ToString(),
                    ClaimValueTypes.Integer64)
            };

            var expiry = DateTime.UtcNow.AddMinutes(expiryMinutes);

            var token = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                claims: claims,
                notBefore: DateTime.UtcNow,
                expires: expiry,
                signingCredentials: creds
            );

            // Opaque refresh token (stored server-side)
            var refreshToken = GenerateSecureRefreshToken();
            _refreshTokens.RemoveAll(rt => rt.UserId == user.Id && !rt.IsRevoked); // single active refresh token per user
            _refreshTokens.Add(new RefreshTokenRecord
            {
                Token = refreshToken,
                UserId = user.Id,
                ExpiresAt = DateTime.UtcNow.AddDays(7)
            });

            return new AuthResponse
            {
                Token = new JwtSecurityTokenHandler().WriteToken(token),
                RefreshToken = refreshToken,
                ExpiresAt = expiry,
                Username = user.Username,
                Role = user.Role
            };
        }

        // ── Refresh-token rotation ────────────────────────────────────────────────
        public Task<AuthResponse?> RefreshTokensAsync(string refreshToken)
        {
            var record = _refreshTokens.FirstOrDefault(rt =>
                rt.Token == refreshToken && !rt.IsRevoked && rt.ExpiresAt > DateTime.UtcNow);

            if (record == null) return Task.FromResult<AuthResponse?>(null);

            var user = _users.FirstOrDefault(u => u.Id == record.UserId && u.IsActive);
            if (user == null) return Task.FromResult<AuthResponse?>(null);

            // Rotate: revoke old token, issue new pair
            record.IsRevoked = true;
            return Task.FromResult<AuthResponse?>(GenerateTokens(user));
        }

        // ── Revoke refresh token (logout) ─────────────────────────────────────────
        public Task RevokeRefreshTokenAsync(string refreshToken)
        {
            var record = _refreshTokens.FirstOrDefault(rt => rt.Token == refreshToken);
            if (record != null) record.IsRevoked = true;
            return Task.CompletedTask;
        }

        // ── User queries & role management ───────────────────────────────────────
        public Task<AppUser?> GetUserByUsernameAsync(string username) =>
            Task.FromResult(_users.FirstOrDefault(u =>
                u.Username.Equals(username, StringComparison.OrdinalIgnoreCase)));

        public Task<bool> UpdateUserRoleAsync(string username, string newRole)
        {
            if (!Roles.All.Contains(newRole)) return Task.FromResult(false);

            var user = _users.FirstOrDefault(u =>
                u.Username.Equals(username, StringComparison.OrdinalIgnoreCase));
            if (user == null) return Task.FromResult(false);

            user.Role = newRole;
            return Task.FromResult(true);
        }

        public Task<IEnumerable<AppUser>> GetAllUsersAsync() =>
            Task.FromResult(_users.AsEnumerable());

        // ── Helpers ───────────────────────────────────────────────────────────────
        private static string GenerateSecureRefreshToken()
        {
            var bytes = new byte[64];
            RandomNumberGenerator.Fill(bytes);
            return Convert.ToBase64String(bytes);
        }

        /// <summary>Seed one admin and one manager so the app is usable right away.</summary>
        private static void SeedDefaultUsers()
        {
            if (_users.Count > 0) return;

            _users.Add(new AppUser
            {
                Id = _nextId++,
                Username = "admin",
                Email = "admin@example.com",
                PasswordHash = BCrypt.Net.BCrypt.HashPassword("Admin@123!", 12),
                Role = Roles.Admin,
                CreatedAt = DateTime.UtcNow
            });

            _users.Add(new AppUser
            {
                Id = _nextId++,
                Username = "manager",
                Email = "manager@example.com",
                PasswordHash = BCrypt.Net.BCrypt.HashPassword("Manager@123!", 12),
                Role = Roles.Manager,
                CreatedAt = DateTime.UtcNow
            });

            _users.Add(new AppUser
            {
                Id = _nextId++,
                Username = "regularuser",
                Email = "user@example.com",
                PasswordHash = BCrypt.Net.BCrypt.HashPassword("User@123!", 12),
                Role = Roles.User,
                CreatedAt = DateTime.UtcNow
            });
        }
    }
}