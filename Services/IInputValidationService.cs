namespace AuthApp.Services
{
    using AuthApp.Interfaces;
    using System.Text.RegularExpressions;
    using System.Web;

    public class InputValidationService : IInputValidationService
    {
        private readonly HashSet<string> _sqlKeywords = new HashSet<string>
    {
        "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "UNION",
        "ALTER", "CREATE", "WHERE", "FROM", "EXEC", "EXECUTE",
        "--", ";", "/*", "*/", "@@", "@", "CHAR", "NCHAR",
        "VARCHAR", "NVARCHAR", "CAST", "CONVERT"
    };

        private readonly Regex _sqlInjectionPattern = new Regex(
            @"('(''|[^'])*')|(;)|(\b(ALTER|CREATE|DELETE|DROP|EXEC(UTE)?|INSERT( +INTO)?|MERGE|SELECT|UPDATE|UNION( +ALL)?)\b)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase
        );

        private readonly Regex _xssPattern = new Regex(
            @"<[^>]*>|(&lt;)|(&gt;)|(javascript:)|(onload)|(onerror)|(onclick)|(onmouse)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase
        );

        private readonly Regex _emailPattern = new Regex(
            @"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
            RegexOptions.Compiled
        );

        private readonly Regex _usernamePattern = new Regex(
            @"^[a-zA-Z0-9_]{3,20}$",
            RegexOptions.Compiled
        );

        public string SanitizeInput(string input)
        {
            if (string.IsNullOrWhiteSpace(input))
                return string.Empty;

            // HTML encode the input to prevent XSS
            string sanitized = HttpUtility.HtmlEncode(input);

            // Remove any remaining potentially dangerous characters
            sanitized = _xssPattern.Replace(sanitized, "");

            // Additional SQL injection prevention
            sanitized = _sqlInjectionPattern.Replace(sanitized, "");

            return sanitized.Trim();
        }

        public bool IsValidEmail(string email)
        {
            if (string.IsNullOrWhiteSpace(email))
                return false;

            return _emailPattern.IsMatch(email);
        }

        public bool IsValidUsername(string username)
        {
            if (string.IsNullOrWhiteSpace(username))
                return false;

            return _usernamePattern.IsMatch(username);
        }

        public bool ContainsMaliciousContent(string input)
        {
            if (string.IsNullOrWhiteSpace(input))
                return false;

            string upperInput = input.ToUpperInvariant();

            // Check for SQL injection keywords
            foreach (var keyword in _sqlKeywords)
            {
                if (upperInput.Contains(keyword.ToUpperInvariant()))
                    return true;
            }

            // Check for XSS patterns
            if (_xssPattern.IsMatch(input))
                return true;

            return false;
        }
    }
}
