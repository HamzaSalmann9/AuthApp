using AuthApp.Models;

namespace AuthApp.Interfaces
{
    public interface IAuthService
    {
        /// <summary>Register a new user. Returns null on conflict.</summary>
        Task<AppUser?> RegisterAsync(RegisterRequest request);

        /// <summary>Validate credentials and return a populated AppUser, or null on failure.</summary>
        Task<AppUser?> ValidateCredentialsAsync(string username, string password);

        /// <summary>Build a signed JWT + refresh-token pair for the given user.</summary>
        AuthResponse GenerateTokens(AppUser user);

        /// <summary>Exchange a valid refresh token for a new token pair.</summary>
        Task<AuthResponse?> RefreshTokensAsync(string refreshToken);

        /// <summary>Revoke a refresh token (logout).</summary>
        Task RevokeRefreshTokenAsync(string refreshToken);

        /// <summary>Retrieve a user by username.</summary>
        Task<AppUser?> GetUserByUsernameAsync(string username);

        /// <summary>Update the role of an existing user.</summary>
        Task<bool> UpdateUserRoleAsync(string username, string newRole);

        /// <summary>Return all registered users (admin view).</summary>
        Task<IEnumerable<AppUser>> GetAllUsersAsync();
    }
}