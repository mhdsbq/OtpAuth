using Microsoft.EntityFrameworkCore;
using OtpAuth.Models;

namespace OtpAuth.Data;

public class DataContext : DbContext
{
    public DataContext(DbContextOptions options) : base(options)
    {
    }

    public DbSet<User> Users => Set<User>();
}