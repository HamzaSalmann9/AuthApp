using AuthApp.Interfaces;
using AuthApp.Models;
using AuthApp.Services;
using Microsoft.AspNetCore.Mvc;
using NUnit.Framework;
using AuthApp.Controllers;
using Microsoft.Extensions.Configuration;
using Moq;
using System.Collections.Generic;

namespace AuthApp.Tests
{
    [TestFixture]
    public class TestInputValidation
    {
        private IInputValidationService _validationService;
        private UsersController _controller;
        private Mock<IConfiguration> _mockConfiguration;

        [SetUp]
        public void Setup()
        {
            _validationService = new InputValidationService();

            // Create mock configuration
            _mockConfiguration = new Mock<IConfiguration>();

            // Setup mock connection string (optional for tests that don't use DB)
            var mockConnectionStringSection = new Mock<IConfigurationSection>();
            mockConnectionStringSection.Setup(x => x.Value).Returns("Server=(localdb)\\mssqllocaldb;Database=AuthAppDb;Trusted_Connection=True;");
            _mockConfiguration.Setup(x => x.GetSection("ConnectionStrings:DefaultConnection")).Returns(mockConnectionStringSection.Object);

            // Pass both dependencies to controller
            _controller = new UsersController(_validationService, _mockConfiguration.Object);
        }

        [Test]
        public void TestForSQLInjection()
        {
            // Arrange
            var maliciousInputs = new List<string>
            {
                "' OR '1'='1",
                "'; DROP TABLE Users; --",
                "' UNION SELECT * FROM Users --",
                "admin'--",
                "1; INSERT INTO Users VALUES (999, 'hacker', 'hack@example.com') --",
                "'; EXEC xp_cmdshell('dir') --",
                "' OR 1=1; --",
                "'; DELETE FROM Users WHERE '1' = '1",
                "'; UPDATE Users SET Email = 'hacker@example.com' WHERE Username = 'admin' --"
            };

            foreach (var maliciousInput in maliciousInputs)
            {
                // Act
                var input = new UserInputModel
                {
                    Username = maliciousInput,
                    Email = "test@example.com"
                };

                var result = _controller.CreateUser(input) as BadRequestObjectResult;

                // Assert
                Assert.That(result, Is.Not.Null, $"Input '{maliciousInput}' should be rejected");
                Assert.That(result.StatusCode, Is.EqualTo(400),
                    $"SQL Injection attempt '{maliciousInput}' was not properly blocked");
            }
        }

        [Test]
        public void TestForXSS()
        {
            // Arrange
            var maliciousInputs = new List<string>
            {
                "<script>alert('XSS')</script>",
                "<img src='x' onerror='alert(1)'>",
                "<body onload='alert(\"XSS\")'>",
                "javascript:alert('XSS')",
                "<svg onload='alert(1)'>",
                "'';!--\"<XSS>=&{()}",
                "<SCRIPT>alert('XSS');</SCRIPT>",
                "<IMG SRC=\"javascript:alert('XSS');\">",
                "<IMG SRC=javascript:alert('XSS')>",
                "<<SCRIPT>alert('XSS');//<</SCRIPT>",
                "<IMG \"\"\"><SCRIPT>alert('XSS')</SCRIPT>\"",
                "<IMG SRC=# onmouseover='alert(\"XSS\")'>"
            };

            foreach (var maliciousInput in maliciousInputs)
            {
                // Act
                var input = new UserInputModel
                {
                    Username = "testuser",
                    Email = maliciousInput
                };

                var result = _controller.CreateUser(input) as BadRequestObjectResult;

                // Assert
                Assert.That(result, Is.Not.Null, $"XSS input '{maliciousInput}' should be rejected");
                Assert.That(result.StatusCode, Is.EqualTo(400),
                    $"XSS attempt '{maliciousInput}' was not properly blocked");
            }
        }

        [Test]
        public void TestSanitization_RemovesMaliciousContent()
        {
            // Arrange
            var inputs = new Dictionary<string, string>
            {
                { "<script>alert('test')</script>", "alert('test')" },
                { "Hello <b>World</b>", "Hello World" },
                { "Test &amp; Code", "Test &amp; Code" },
                { "javascript:alert('XSS')", "alert('XSS')" }
            };

            foreach (var input in inputs)
            {
                // Act
                var sanitized = _validationService.SanitizeInput(input.Key);

                // Assert
                Assert.That(sanitized.Contains("<"), Is.False, $"HTML tags not removed from: {input.Key}");
                Assert.That(sanitized.Contains(">"), Is.False, $"HTML tags not removed from: {input.Key}");
            }
        }

        [Test]
        public void TestValidEmailValidation()
        {
            // Arrange
            var validEmails = new List<string>
            {
                "user@example.com",
                "user.name@domain.co.uk",
                "user+label@gmail.com",
                "123@example.com",
                "user@subdomain.example.com"
            };

            var invalidEmails = new List<string>
            {
                "notanemail",
                "user@",
                "@domain.com",
                "user@domain",
                "user@.com",
                "user@domain.",
                "<script>@example.com",
                "'; DROP TABLE --@example.com"
            };

            // Act & Assert - Valid emails
            foreach (var email in validEmails)
            {
                Assert.That(_validationService.IsValidEmail(email), Is.True,
                    $"Valid email '{email}' was rejected");
            }

            // Act & Assert - Invalid emails
            foreach (var email in invalidEmails)
            {
                Assert.That(_validationService.IsValidEmail(email), Is.False,
                    $"Invalid email '{email}' was accepted");
            }
        }

        [Test]
        public void TestValidUsernameValidation()
        {
            // Arrange
            var validUsernames = new List<string>
            {
                "john_doe",
                "jane123",
                "user_name",
                "abc123_def",
                "testuser"
            };

            var invalidUsernames = new List<string>
            {
                "ab", // too short
                "thisusernameiswaytoolongandshouldberejected", // too long
                "user@name", // invalid character
                "user-name", // hyphen not allowed
                "user.name", // dot not allowed
                "<script>", // malicious
                "' OR '1'='1", // SQL injection
                "admin'--" // SQL injection
            };

            // Act & Assert - Valid usernames
            foreach (var username in validUsernames)
            {
                Assert.That(_validationService.IsValidUsername(username), Is.True,
                    $"Valid username '{username}' was rejected");
            }

            // Act & Assert - Invalid usernames
            foreach (var username in invalidUsernames)
            {
                Assert.That(_validationService.IsValidUsername(username), Is.False,
                    $"Invalid username '{username}' was accepted");
            }
        }

        [Test]
        public void TestContainsMaliciousContent_DetectsThreats()
        {
            // Arrange
            var maliciousInputs = new List<string>
            {
                "SELECT * FROM Users",
                "DROP TABLE Users",
                "DELETE FROM Users",
                "UPDATE Users SET",
                "INSERT INTO Users",
                "UNION SELECT",
                "EXEC xp_cmdshell",
                "<script>",
                "javascript:alert",
                "onload=",
                "onerror=",
                "--",
                "/*",
                "*/"
            };

            var safeInputs = new List<string>
            {
                "Hello World",
                "john_doe",
                "user@example.com",
                "This is a normal text",
                "Product description"
            };

            // Act & Assert - Malicious inputs
            foreach (var input in maliciousInputs)
            {
                Assert.That(_validationService.ContainsMaliciousContent(input), Is.True,
                    $"Malicious content not detected in: {input}");
            }

            // Act & Assert - Safe inputs
            foreach (var input in safeInputs)
            {
                Assert.That(_validationService.ContainsMaliciousContent(input), Is.False,
                    $"Safe input flagged as malicious: {input}");
            }
        }

        [Test]
        public void TestSearchEndpoint_SQLInjectionAttempts()
        {
            // Arrange
            var maliciousSearches = new List<string>
            {
                "' OR '1'='1",
                "'; DROP TABLE Users; --",
                "' UNION SELECT * FROM Users --",
                "admin'--",
                "1; DELETE FROM Users --"
            };

            foreach (var search in maliciousSearches)
            {
                // Act
                var result = _controller.SearchUsers(search) as BadRequestObjectResult;

                // Assert
                Assert.That(result, Is.Not.Null, $"Search with '{search}' should be rejected");
                Assert.That(result.StatusCode, Is.EqualTo(400),
                    $"SQL injection in search parameter '{search}' was not blocked");
            }
        }

        [Test]
        public void TestParameterizedQuerySimulation_SafeFromInjection()
        {
            // Arrange
            var input = new UserInputModel
            {
                Username = "' OR '1'='1",
                Email = "test@example.com"
            };

            // Act - The controller's validation should block this
            var result = _controller.CreateUser(input) as BadRequestObjectResult;

            // Assert
            Assert.That(result, Is.Not.Null, "Parameterized query simulation should block SQL injection");
            Assert.That(result.StatusCode, Is.EqualTo(400));

            // Now test with valid data
            input = new UserInputModel
            {
                Username = "valid_user",
                Email = "valid@example.com"
            };

            var validResult = _controller.CreateUser(input) as OkObjectResult;

            Assert.That(validResult, Is.Not.Null, "Valid input should be accepted");
            Assert.That(validResult.StatusCode, Is.EqualTo(200));
        }
    }
}