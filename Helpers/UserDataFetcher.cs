using System;
using System.Data;
using Microsoft.Data.SqlClient;

namespace MyApp.Helpers;

public class UserDataFetcher
{
    private readonly string _connectionString;

    public UserDataFetcher(string connectionString)
    {
        _connectionString = connectionString;
    }

    public DataTable GetUserById(int userId)
    {
        var query = "SELECT * FROM Users WHERE UserId = @UserId";

        using (var connection = new SqlConnection(_connectionString))
        using (var command = new SqlCommand(query, connection))
        {
            // Add parameterized query to prevent SQL injection
            command.Parameters.Add(new SqlParameter("@UserId", SqlDbType.Int) { Value = userId });

            // Execute the query securely
            var dataTable = new DataTable();
            using (var adapter = new SqlDataAdapter(command))
            {
                connection.Open();
                adapter.Fill(dataTable);
            }

            return dataTable;
        }
    }
}
