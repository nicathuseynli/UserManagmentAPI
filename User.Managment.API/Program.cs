using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using User.Managment.API.Models;
using User.Managment.Service.Models;
using User.Managment.Service.Services;


var builder = WebApplication.CreateBuilder(args);

//For Entity Framework
var configuration = builder.Configuration;
builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseSqlServer(configuration.GetConnectionString("defaultServer"));
});

//For Identity
builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();
//Adding Authentication
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
});

//Add Email Configuration 
var emailConfig = configuration.GetSection("EmailConfiguration").Get<EmailConfiguration>();
builder.Services.AddSingleton(emailConfig);

builder.Services.AddScoped<IEmailService, EmailService>();
// Add services to the container.

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

app.UseAuthorization();

app.MapControllers();

app.Run();
