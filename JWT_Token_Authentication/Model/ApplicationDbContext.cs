using Microsoft.EntityFrameworkCore;

namespace JWT_Token_Authentication.Model
{
    public class ApplicationDbContext:DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {

        }
        public DbSet<usercred> Authentication_JWT { get; set; }
        public DbSet<DownloadDataModel>DownloadTable { get; set; }
    }
}
