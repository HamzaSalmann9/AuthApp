using AuthApp.Interfaces;
using AuthApp.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;

namespace AuthApp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UsersController : ControllerBase
    {
        private readonly IInputValidationService _validationService;
        private readonly IConfiguration _configuration;
        private static List<UserModel> _users = new List<UserModel>(); // Mock data store
        private static int _nextId = 1;

        public UsersController(IInputValidationService validationService, IConfiguration configuration)
        {
            _validationService = validationService;
            _configuration = configuration;

            // Add some mock data
            if (!_users.Any())
            {
                _users.Add(new UserModel { Id = _nextId++, Username = "john_doe", Email = "john@example.com" });
                _users.Add(new UserModel { Id = _nextId++, Username = "jane_smith", Email = "jane@example.com" });
            }
        }

        [HttpPost]
        public IActionResult CreateUser([FromBody] UserInputModel input)
        {
            try
            {
                // Validate input
                if (!ModelState.IsValid)
                    return BadRequest(ModelState);

                // Check for malicious content
                if (_validationService.ContainsMaliciousContent(input.Username) ||
                    _validationService.ContainsMaliciousContent(input.Email))
                {
                    return BadRequest("Input contains potentially malicious content");
                }

                // Sanitize inputs (defense in depth)
                string sanitizedUsername = _validationService.SanitizeInput(input.Username);
                string sanitizedEmail = _validationService.SanitizeInput(input.Email);

                // Additional validation
                if (!_validationService.IsValidUsername(sanitizedUsername))
                    return BadRequest("Invalid username format");

                if (!_validationService.IsValidEmail(sanitizedEmail))
                    return BadRequest("Invalid email format");

                // This simulates a parameterized query
                var newUser = new UserModel
                {
                    Id = _nextId++,
                    Username = sanitizedUsername,
                    Email = sanitizedEmail
                };

                _users.Add(newUser);

                return Ok(newUser);
            }
            catch (Exception ex)
            {
                return StatusCode(500, "An error occurred while processing your request");
            }
        }

        [HttpGet("{id}")]
        public IActionResult GetUser(int id)
        {
            // Simulate a parameterized query: SELECT * FROM Users WHERE UserID = @id
            var user = _users.FirstOrDefault(u => u.Id == id);

            if (user == null)
                return NotFound();

            return Ok(user);
        }

        [HttpGet("search")]
        public IActionResult SearchUsers([FromQuery] string username)
        {
            // Validate and sanitize search input
            if (!string.IsNullOrEmpty(username))
            {
                if (_validationService.ContainsMaliciousContent(username))
                    return BadRequest("Invalid search term");

                username = _validationService.SanitizeInput(username);
            }

            // Simulate parameterized search query: SELECT * FROM Users WHERE Username LIKE @username
            var users = _users.Where(u => string.IsNullOrEmpty(username) ||
                                          u.Username.Contains(username, StringComparison.OrdinalIgnoreCase))
                              .ToList();

            return Ok(users);
        }

        [HttpPost("secure-query-example")]
        public IActionResult SecureQueryExample([FromBody] UserInputModel input)
        {
            try
            {
                // First validate and sanitize inputs
                if (!ModelState.IsValid)
                    return BadRequest(ModelState);

                if (_validationService.ContainsMaliciousContent(input.Username) ||
                    _validationService.ContainsMaliciousContent(input.Email))
                {
                    return BadRequest("Input contains potentially malicious content");
                }

                string sanitizedUsername = _validationService.SanitizeInput(input.Username);
                string sanitizedEmail = _validationService.SanitizeInput(input.Email);

                if (!_validationService.IsValidUsername(sanitizedUsername))
                    return BadRequest("Invalid username format");

                if (!_validationService.IsValidEmail(sanitizedEmail))
                    return BadRequest("Invalid email format");

                // Get connection string from configuration
                string connectionString = _configuration.GetConnectionString("DefaultConnection");

                // Use parameterized query to prevent SQL injection
                using (var connection = new SqlConnection(connectionString))
                {
                    var query = "INSERT INTO Users (Username, Email) VALUES (@Username, @Email); SELECT SCOPE_IDENTITY();";

                    using (var command = new SqlCommand(query, connection))
                    {
                        // Add parameters - this is the key to preventing SQL injection
                        command.Parameters.AddWithValue("@Username", sanitizedUsername);
                        command.Parameters.AddWithValue("@Email", sanitizedEmail);

                        connection.Open();

                        // Execute and get the new ID
                        var newId = Convert.ToInt32(command.ExecuteScalar());

                        return Ok(new
                        {
                            Message = "User created successfully with parameterized query",
                            UserId = newId,
                            Username = sanitizedUsername,
                            Email = sanitizedEmail
                        });
                    }
                }
            }
            catch (SqlException ex)
            {
                // Log the exception (use ILogger in production)
                return StatusCode(500, "Database error occurred");
            }
            catch (Exception ex)
            {
                return StatusCode(500, "An error occurred while processing your request");
            }
        }

        [HttpGet("secure-query-example/{id}")]
        public IActionResult GetUserSecure(int id)
        {
            try
            {
                string connectionString = _configuration.GetConnectionString("DefaultConnection");

                using (var connection = new SqlConnection(connectionString))
                {
                    // Parameterized query for SELECT
                    var query = "SELECT UserID, Username, Email FROM Users WHERE UserID = @UserId";

                    using (var command = new SqlCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@UserId", id);

                        connection.Open();

                        using (var reader = command.ExecuteReader())
                        {
                            if (reader.Read())
                            {
                                var user = new
                                {
                                    Id = reader.GetInt32(0),
                                    Username = reader.GetString(1),
                                    Email = reader.GetString(2)
                                };
                                return Ok(user);
                            }
                            else
                            {
                                return NotFound($"User with ID {id} not found");
                            }
                        }
                    }
                }
            }
            catch (SqlException ex)
            {
                return StatusCode(500, "Database error occurred");
            }
        }

        [HttpPut("secure-query-example/{id}")]
        public IActionResult UpdateUserSecure(int id, [FromBody] UserInputModel input)
        {
            try
            {
                // Validate inputs
                if (!ModelState.IsValid)
                    return BadRequest(ModelState);

                if (_validationService.ContainsMaliciousContent(input.Username) ||
                    _validationService.ContainsMaliciousContent(input.Email))
                {
                    return BadRequest("Input contains potentially malicious content");
                }

                string sanitizedUsername = _validationService.SanitizeInput(input.Username);
                string sanitizedEmail = _validationService.SanitizeInput(input.Email);

                string connectionString = _configuration.GetConnectionString("DefaultConnection");

                using (var connection = new SqlConnection(connectionString))
                {
                    // Parameterized query for UPDATE
                    var query = "UPDATE Users SET Username = @Username, Email = @Email WHERE UserID = @UserId";

                    using (var command = new SqlCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@Username", sanitizedUsername);
                        command.Parameters.AddWithValue("@Email", sanitizedEmail);
                        command.Parameters.AddWithValue("@UserId", id);

                        connection.Open();

                        int rowsAffected = command.ExecuteNonQuery();

                        if (rowsAffected > 0)
                        {
                            return Ok(new { Message = "User updated successfully" });
                        }
                        else
                        {
                            return NotFound($"User with ID {id} not found");
                        }
                    }
                }
            }
            catch (SqlException ex)
            {
                return StatusCode(500, "Database error occurred");
            }
        }

        [HttpDelete("secure-query-example/{id}")]
        public IActionResult DeleteUserSecure(int id)
        {
            try
            {
                string connectionString = _configuration.GetConnectionString("DefaultConnection");

                using (var connection = new SqlConnection(connectionString))
                {
                    // Parameterized query for DELETE
                    var query = "DELETE FROM Users WHERE UserID = @UserId";

                    using (var command = new SqlCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@UserId", id);

                        connection.Open();

                        int rowsAffected = command.ExecuteNonQuery();

                        if (rowsAffected > 0)
                        {
                            return Ok(new { Message = "User deleted successfully" });
                        }
                        else
                        {
                            return NotFound($"User with ID {id} not found");
                        }
                    }
                }
            }
            catch (SqlException ex)
            {
                return StatusCode(500, "Database error occurred");
            }
        }

        [HttpGet("demonstrate-sql-injection-prevention")]
        public IActionResult DemonstrateSqlInjectionPrevention()
        {
            var examples = new
            {
                UnsafeApproach = new
                {
                    Description = "DANGEROUS - Never do this! String concatenation is vulnerable to SQL injection",
                    CodeExample = @"string query = ""SELECT * FROM Users WHERE Username = '"" + userInput + ""'"";",
                    Vulnerability = "If userInput = ' OR '1'='1, query becomes: SELECT * FROM Users WHERE Username = '' OR '1'='1' (returns all users)"
                },
                SafeApproach = new
                {
                    Description = "SECURE - Always use parameterized queries",
                    CodeExample = @"string query = ""SELECT * FROM Users WHERE Username = @Username"";
using (var command = new SqlCommand(query, connection))
{
    command.Parameters.AddWithValue(""@Username"", userInput);
}",
                    Benefit = "Parameters are treated as literal values, not executable code, preventing SQL injection"
                }
            };

            return Ok(examples);
        }
    }
}