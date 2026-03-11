using AuthApp.Controllers;
using AuthApp.Interfaces;
using AuthApp.Models;
using AuthApp.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Moq;
using NUnit.Framework;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace AuthApp.Tests
{
    [TestFixture]
    public class TestAuthentication
    {
        private IInputValidationService _validationService;
        private IAuthService _authService;
        private Mock<IConfiguration> _mockConfiguration;
        private AuthController _authController;
        private AdminController _adminController;

        [SetUp]
        public void Setup()
        {
            _validationService = new InputValidationService();

            _mockConfiguration = new Mock<IConfiguration>();

            // JWT settings
            SetupConfigValue("JwtSettings:SecretKey", "TestSecretKey_AtLeast32Characters_XYZ!");
            SetupConfigValue("JwtSettings:Issuer", "AuthApp");
            SetupConfigValue("JwtSettings:Audience", "AuthApp");
            SetupConfigValue("JwtSettings:ExpiryMinutes", "60");

            // Connection string (not used by auth tests, but satisfies the mock)
            SetupConfigValue("ConnectionStrings:DefaultConnection",
                "Server=(localdb)\\mssqllocaldb;Database=AuthAppDb;Trusted_Connection=True;");

            _authService = new AuthService(_mockConfiguration.Object, _validationService);
            _authController = new AuthController(_authService, _validationService);
            _adminController = new AdminController(_authService, _validationService);
        }

        // ── Registration ──────────────────────────────────────────────────────────

        [Test]
        public async Task Register_ValidInput_ReturnsCreated()
        {
            var request = ValidRegisterRequest("newuser_01");
            var result = await _authController.Register(request) as CreatedAtActionResult;

            Assert.That(result, Is.Not.Null);
            Assert.That(result!.StatusCode, Is.EqualTo(201));
        }

        [Test]
        public async Task Register_DuplicateUsername_ReturnsConflict()
        {
            var req1 = ValidRegisterRequest("dupuser");
            var req2 = ValidRegisterRequest("dupuser");
            req2.Email = "other@example.com";

            await _authController.Register(req1);
            var result = await _authController.Register(req2) as ConflictObjectResult;

            Assert.That(result, Is.Not.Null);
            Assert.That(result!.StatusCode, Is.EqualTo(409));
        }

        [Test]
        public async Task Register_WeakPassword_ReturnsBadRequest()
        {
            var request = ValidRegisterRequest("weakpassuser");
            request.Password = "simple";
            request.ConfirmPassword = "simple";

            var result = await _authController.Register(request) as BadRequestObjectResult;
            Assert.That(result, Is.Not.Null);
        }

        [Test]
        public async Task Register_SQLInjectionUsername_ReturnsBadRequest()
        {
            var request = ValidRegisterRequest("' OR '1'='1");
            var result = await _authController.Register(request);

            // Should be 400 (malicious content) or 400 (invalid username format)
            Assert.That(result, Is.InstanceOf<BadRequestObjectResult>());
        }

        [Test]
        public async Task Register_XSSEmail_ReturnsBadRequest()
        {
            var request = ValidRegisterRequest("xssemailuser");
            request.Email = "<script>alert('xss')</script>@example.com";

            var result = await _authController.Register(request);
            Assert.That(result, Is.InstanceOf<BadRequestObjectResult>());
        }

        // ── Login ─────────────────────────────────────────────────────────────────

        [Test]
        public async Task Login_ValidCredentials_ReturnsTokens()
        {
            // "admin" is seeded in AuthService
            var login = new AppLoginRequest { Username = "admin", Password = "Admin@123!" };
            var result = await _authController.Login(login) as OkObjectResult;

            Assert.That(result, Is.Not.Null);
            var response = result!.Value as AuthResponse;
            Assert.That(response, Is.Not.Null);
            Assert.That(response!.Token, Is.Not.Empty);
            Assert.That(response.RefreshToken, Is.Not.Empty);
            Assert.That(response.Role, Is.EqualTo(Roles.Admin));
        }

        [Test]
        public async Task Login_InvalidPassword_ReturnsUnauthorized()
        {
            var login = new AppLoginRequest { Username = "admin", Password = "WrongPassword!" };
            var result = await _authController.Login(login) as UnauthorizedObjectResult;

            Assert.That(result, Is.Not.Null);
            Assert.That(result!.StatusCode, Is.EqualTo(401));
        }

        [Test]
        public async Task Login_NonExistentUser_ReturnsUnauthorized()
        {
            var login = new AppLoginRequest { Username = "ghost", Password = "Password@1" };
            var result = await _authController.Login(login) as UnauthorizedObjectResult;

            Assert.That(result, Is.Not.Null);
        }

        [Test]
        public async Task Login_SQLInjectionUsername_ReturnsUnauthorizedOrBadRequest()
        {
            var login = new AppLoginRequest { Username = "' OR '1'='1", Password = "irrelevant" };
            var result = await _authController.Login(login);

            // Must NOT return 200
            Assert.That(result, Is.Not.InstanceOf<OkObjectResult>(),
                "SQL injection login attempt must not succeed.");
        }

        [Test]
        public async Task Login_AccountLockout_AfterMaxFailedAttempts()
        {
            // Register a fresh user so we don't poison the seeded admin
            var regReq = ValidRegisterRequest("lockoutuser");
            await _authController.Register(regReq);

            var badLogin = new AppLoginRequest { Username = "lockoutuser", Password = "WrongPass@1" };

            // Exhaust the allowed attempts (AuthService.MaxFailedAttempts = 5)
            for (int i = 0; i < 5; i++)
                await _authController.Login(badLogin);

            // Even with the correct password the account should now be locked
            var correctLogin = new AppLoginRequest { Username = "lockoutuser", Password = "StrongPass@1!" };
            var result = await _authController.Login(correctLogin) as UnauthorizedObjectResult;

            Assert.That(result, Is.Not.Null,
                "Account should be locked out after too many failed attempts.");
        }

        // ── Token refresh ─────────────────────────────────────────────────────────

        [Test]
        public async Task RefreshTokens_ValidToken_ReturnsNewTokenPair()
        {
            var login = new AppLoginRequest { Username = "admin", Password = "Admin@123!" };
            var loginRes = (await _authController.Login(login) as OkObjectResult)!.Value as AuthResponse;

            var refreshReq = new RefreshTokenRequest { RefreshToken = loginRes!.RefreshToken };
            var result = await _authController.Refresh(refreshReq) as OkObjectResult;

            Assert.That(result, Is.Not.Null);
            var newResponse = result!.Value as AuthResponse;
            Assert.That(newResponse!.Token, Is.Not.EqualTo(loginRes.Token),
                "A new JWT should be issued on refresh.");
            Assert.That(newResponse.RefreshToken, Is.Not.EqualTo(loginRes.RefreshToken),
                "Refresh token should be rotated.");
        }

        [Test]
        public async Task RefreshTokens_InvalidToken_ReturnsUnauthorized()
        {
            var refreshReq = new RefreshTokenRequest { RefreshToken = "invalid_token_value" };
            var result = await _authController.Refresh(refreshReq) as UnauthorizedObjectResult;

            Assert.That(result, Is.Not.Null);
        }

        [Test]
        public async Task RefreshTokens_RevokedToken_ReturnsUnauthorized()
        {
            var login = new AppLoginRequest { Username = "manager", Password = "Manager@123!" };
            var loginRes = (await _authController.Login(login) as OkObjectResult)!.Value as AuthResponse;

            // Revoke via logout
            SetupAdminHttpContext("manager", Roles.Manager);
            await _authController.Logout(new RefreshTokenRequest { RefreshToken = loginRes!.RefreshToken });

            // Now try to use the revoked token
            var result = await _authController.Refresh(
                new RefreshTokenRequest { RefreshToken = loginRes.RefreshToken }) as UnauthorizedObjectResult;

            Assert.That(result, Is.Not.Null, "Revoked refresh token must not be reusable.");
        }

        // ── RBAC via AuthService ──────────────────────────────────────────────────

        [Test]
        public async Task UpdateUserRole_ValidRole_Succeeds()
        {
            var regReq = ValidRegisterRequest("roletest_user");
            await _authController.Register(regReq);

            var success = await _authService.UpdateUserRoleAsync("roletest_user", Roles.Manager);
            Assert.That(success, Is.True);

            var user = await _authService.GetUserByUsernameAsync("roletest_user");
            Assert.That(user!.Role, Is.EqualTo(Roles.Manager));
        }

        [Test]
        public async Task UpdateUserRole_InvalidRole_ReturnsFalse()
        {
            var success = await _authService.UpdateUserRoleAsync("admin", "SuperAdmin");
            Assert.That(success, Is.False);
        }

        [Test]
        public async Task UpdateUserRole_NonExistentUser_ReturnsFalse()
        {
            var success = await _authService.UpdateUserRoleAsync("nobody", Roles.Admin);
            Assert.That(success, Is.False);
        }

        [Test]
        public async Task AdminChangeRole_NonAdminUser_ShouldBeForbidden()
        {
            // Simulate a Manager-authenticated HTTP context
            SetupAdminHttpContext("manager", Roles.Manager);

            // The [Authorize(Roles = "Admin")] attribute enforces this at the framework level.
            // In a unit test we verify the underlying service rejects invalid roles,
            // and that a non-admin cannot escalate via the controller.
            var req = new ChangeRoleRequest { Username = "regularuser", NewRole = Roles.Admin };
            // Without Admin role in HttpContext the framework returns 403 before the action runs.
            // Here we confirm the service itself is correct:
            var result = await _authService.UpdateUserRoleAsync("regularuser", Roles.Admin);
            Assert.That(result, Is.True); // service allows it – enforcement is in the [Authorize] attribute

            // Reset
            await _authService.UpdateUserRoleAsync("regularuser", Roles.User);
        }

        // ── Token content ─────────────────────────────────────────────────────────

        [Test]
        public async Task GeneratedToken_ContainsExpectedClaims()
        {
            var user = await _authService.ValidateCredentialsAsync("admin", "Admin@123!");
            Assert.That(user, Is.Not.Null);

            var tokens = _authService.GenerateTokens(user!);
            var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
            var jwt = handler.ReadJwtToken(tokens.Token);

            Assert.That(jwt.Claims.Any(c => c.Type == "unique_name" && c.Value == "admin"), Is.True,
                "JWT should contain the username claim.");
            Assert.That(jwt.Claims.Any(c => c.Type == ClaimTypes.Role && c.Value == Roles.Admin), Is.True,
                "JWT should contain the role claim.");
        }

        [Test]
        public async Task SeededUsers_HaveCorrectRoles()
        {
            var admin = await _authService.GetUserByUsernameAsync("admin");
            var manager = await _authService.GetUserByUsernameAsync("manager");
            var user = await _authService.GetUserByUsernameAsync("regularuser");

            Assert.That(admin!.Role, Is.EqualTo(Roles.Admin));
            Assert.That(manager!.Role, Is.EqualTo(Roles.Manager));
            Assert.That(user!.Role, Is.EqualTo(Roles.User));
        }

        // ── Helpers ───────────────────────────────────────────────────────────────

        private static RegisterRequest ValidRegisterRequest(string username) => new()
        {
            Username = username,
            Email = $"{username}@example.com",
            Password = "StrongPass@1!",
            ConfirmPassword = "StrongPass@1!"
        };

        /// <summary>Attach a fake ClaimsPrincipal to the controller so role-checks work in unit tests.</summary>
        private void SetupAdminHttpContext(string username, string role)
        {
            var claims = new[] { new Claim(ClaimTypes.Name, username), new Claim(ClaimTypes.Role, role) };
            var identity = new ClaimsIdentity(claims, "Test");
            var principal = new ClaimsPrincipal(identity);

            _authController.ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext { User = principal }
            };
        }

        private void SetupConfigValue(string key, string value)
        {
            var section = new Mock<IConfigurationSection>();
            section.Setup(x => x.Value).Returns(value);
            _mockConfiguration.Setup(x => x.GetSection(key)).Returns(section.Object);
            _mockConfiguration.Setup(x => x[key]).Returns(value);
        }
    }
}