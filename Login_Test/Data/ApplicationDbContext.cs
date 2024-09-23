using Login_Test.Models;
using Microsoft.EntityFrameworkCore;
using System.Collections.Generic;

namespace Login_Test.Data
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options) { }

        public DbSet<Admin> Admins { get; set; }
    }
}
