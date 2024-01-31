using JWT_Token_Authentication.Model;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
var connectionString = builder.Configuration.GetConnectionString("Kumaresan");
builder.Services.AddDbContextPool<ApplicationDbContext>(option => option.UseSqlServer(connectionString));

builder.Services.Configure<JWTSetting>(builder.Configuration.GetSection("JWTSetting"));

builder.Services.AddSwaggerGen(
     c =>
     {
         c.SwaggerDoc("v1", new OpenApiInfo { Title = "JWt_Token_Athentication", Version = "v1" });
         c.AddSecurityDefinition(
             "Bearer", new OpenApiSecurityScheme
             {
                 Description = "Jwt Authorization",
                 Name = "Authorization",
                 In = ParameterLocation.Header,
                 Type = SecuritySchemeType.ApiKey,
                 Scheme = "Bearer"
             });
         c.AddSecurityRequirement(new OpenApiSecurityRequirement{
                {
                  new OpenApiSecurityScheme
                {
                  Reference = new OpenApiReference
                  {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                  }
                },
                   new string[]{}
                }
             });
     });

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.RequireHttpsMetadata = false;
        options.SaveToken = true;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(builder.Configuration["JWTSetting:securitykey"])),
            ValidateIssuer = false,
            ValidateAudience = false,
            ClockSkew = TimeSpan.Zero
        };
    });

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseRouting();

app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();

app.Run();