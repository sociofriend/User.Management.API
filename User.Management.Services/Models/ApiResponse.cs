namespace User.Management.Services.Models;

public class ApiResponse<T>
{
    public bool IsSuccess { get; set; }
    public string? Message { get; set; } = null!;
    public int StatusCode { get; set; }
    public T? Response { get; set; } 
}