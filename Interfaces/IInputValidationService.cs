namespace AuthApp.Interfaces
{
    public interface IInputValidationService
    {
        string SanitizeInput(string input);
        bool IsValidEmail(string email);
        bool IsValidUsername(string username);
        bool ContainsMaliciousContent(string input);
    }
}
