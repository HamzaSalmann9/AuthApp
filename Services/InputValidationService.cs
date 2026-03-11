namespace AuthApp.Services
{
    using AuthApp.Interfaces;
    using System.Text.RegularExpressions;
    using System.Web;

    public class InputValidationService : IInputValidationService
    {
        private readonly HashSet<string> _sqlKeywords = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "UNION",
            "ALTER", "CREATE", "WHERE", "FROM", "EXEC", "EXECUTE",
            "--", ";", "/*", "*/", "@@", "@", "CHAR", "NCHAR",
            "VARCHAR", "NVARCHAR", "CAST", "CONVERT",
            // FIX: these were missing — used in ' OR '1'='1 and similar injections
            "OR", "AND", "HAVING", "ORDER BY", "GROUP BY", "LIKE",
            "SLEEP", "WAITFOR", "BENCHMARK", "XP_CMDSHELL"
        };

        private readonly Regex _sqlInjectionPattern = new Regex(
            // FIX: added OR/AND/HAVING/single-quote patterns
            @"('(''|[^'])*')|(;)|(\b(ALTER|CREATE|DELETE|DROP|EXEC(UTE)?|INSERT( +INTO)?|MERGE|SELECT|UPDATE|UNION( +ALL)?|OR|AND|HAVING|SLEEP|WAITFOR)\b)|(--)|(\/\*)",
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

            string sanitized = HttpUtility.HtmlEncode(input);
            sanitized = _xssPattern.Replace(sanitized, "");
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

            // FIX: check for single quote first — it's the entry point for most SQL injection
            if (input.Contains('\''))
                return true;

            // Check SQL injection keywords
            if (_sqlInjectionPattern.IsMatch(input))
                return true;

            // Check for XSS patterns
            if (_xssPattern.IsMatch(input))
                return true;

            // Fallback: keyword loop for anything the regex misses
            string upperInput = input.ToUpperInvariant();
            foreach (var keyword in _sqlKeywords)
            {
                if (upperInput.Contains(keyword.ToUpperInvariant()))
                    return true;
            }

            return false;
        }
    }
}