using Microsoft.Data.SqlClient;
using MyApp.Helpers;

namespace MyApp.Helpers;

public class LoginHelper
{
    private readonly string _connectionString;

    public LoginHelper(string connectionString)
    {
        _connectionString = connectionString;
    }

    public bool ValidateUserInput(string username, string password)
    {
        string allowedSpecialCharacters = "!@#$%^&*?";
        return ValidationHelpers.IsValidInput(username, allowedSpecialCharacters) && ValidationHelpers.IsValidInput(password, allowedSpecialCharacters);
    }

    public bool AuthenticateUser(string username, string hashedPassword)
    {
        var query = "SELECT COUNT(1) FROM Users WHERE Username = @Username AND Password = @Password";

        try
        {
            using (var connection = new SqlConnection(_connectionString))
            using (var command = new SqlCommand(query, connection))
            {
                command.Parameters.AddWithValue("@Username", username);
                command.Parameters.AddWithValue("@Password", hashedPassword);

                connection.Open();
                return (int)command.ExecuteScalar() > 0;
            }
        }
        catch (Exception ex)
        {
            // Log the exception
            Console.WriteLine($"Error occurred: {ex.Message}");
            return false;
        }
    }
}
