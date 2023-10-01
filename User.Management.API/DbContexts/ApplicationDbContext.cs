using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System.Data;

namespace User.Management.API.DbContexts;

public class ApplicationDbContext : IdentityDbContext<IdentityUser>
{
    
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
    {

    }

    protected override void OnModelCreating(ModelBuilder builder) //manages entities of the DB
    {
        base.OnModelCreating(builder);
        SeedRoles(builder);
    }

    private void SeedRoles(ModelBuilder builder)
    {
        builder.Entity<IdentityRole>().HasData
            (
            new IdentityRole() { Name = "Admin", ConcurrencyStamp = "1", NormalizedName = "Admin" },
            new IdentityRole() { Name = "User", ConcurrencyStamp = "2", NormalizedName = "User" },
            new IdentityRole() { Name = "HR", ConcurrencyStamp = "3", NormalizedName = "Human Resources" }
            );
    }
}
