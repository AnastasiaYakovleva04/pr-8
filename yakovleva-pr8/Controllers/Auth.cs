using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using yakovleva_pr8.Models;
using yakovleva_pr8.Services;

namespace yakovleva_pr8.Controllers
{
    [ApiController]
    [Route("api/v1/auth")]
    public class Auth : ControllerBase
    {
        private readonly TrpoPr8Context _context;
        private readonly IPasswordHasher<User> _hasher;
        private readonly IConfiguration _configuration;
        private readonly TokenService _service;

        public Auth(TrpoPr8Context context, IPasswordHasher<User> hasher, IConfiguration configuration, TokenService service)
        {
            _context = context;
            _hasher = hasher;
            _configuration = configuration;
            _service = service;
        }

        public record AuthRequest(string Login, string Password);

        [HttpPost("register")]
        public IActionResult Register(AuthRequest request)
        {
            if (_context.Users.Any(u => u.Login == request.Login))
                return Conflict("Такой логин уже занят");

            var user = new User { Login = request.Login, Role = "User" };
            user.PasswordHash = _hasher.HashPassword(user, request.Password);
            _context.Users.Add(user);
            _context.SaveChanges();

            return Ok("Пользователь зарегистрирован");
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(AuthRequest request)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Login == request.Login);
            if (user == null)
                return Unauthorized("Неверная пара логин/пароль");

            var result = _hasher.VerifyHashedPassword(user, user.PasswordHash, request.Password);
            if (result == PasswordVerificationResult.Failed)
                return Unauthorized("Неверная пара логин/пароль");

            var accessToken = GenerateJwtToken(user);
            var refreshToken = _service.GenerateRefreshToken();

            await _service.SaveRefreshTokenAsync(user.Id, refreshToken);
            return Ok(new
            {
                access_token = accessToken,
                refresh_token = refreshToken
            });
        }
        private string GenerateJwtToken(User user)
        {
            var claims = new[]
            {
                new Claim(ClaimTypes.Name, user.Login),
                new Claim(ClaimTypes.Role, user.Role ?? "User"),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!));

            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: "ExampleApi",
                audience: "ExampleApiClient",
                claims: claims,
                expires: DateTime.UtcNow.AddSeconds(60),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public record RefreshRequest(string Refresh_token);

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh(RefreshRequest request)
        {
            var existingToken = await _service.GetRefreshTokenAsync(request.Refresh_token);
            if (existingToken == null || existingToken.ExpiresAt < DateTime.UtcNow)
                return Unauthorized();

            await _service.RemoveRefreshTokenAsync(existingToken);

            var user = existingToken.User;
            var newAccessToken = GenerateJwtToken(user);
            var newRefreshToken = _service.GenerateRefreshToken();

            await _service.SaveRefreshTokenAsync(user.Id, newRefreshToken);

            return Ok(new
            {
                access_token = newAccessToken,
                refresh_token = newRefreshToken
            });
        }

        [HttpPost("logout")]
        [Authorize]
        public async Task<IActionResult> Logout(RefreshRequest request)
        {
            var currentUser = User.Identity?.Name;
            var jti = User.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;
            if (string.IsNullOrEmpty(currentUser) || string.IsNullOrEmpty(jti))
                return Unauthorized();

            var existingToken = await _service.GetRefreshTokenAsync(request.Refresh_token);
            if (existingToken == null || existingToken.ExpiresAt < DateTime.UtcNow)
                return Unauthorized();

            if (existingToken.User.Login != currentUser)
                return Forbid();

            _context.RefreshTokens.Remove(existingToken);
            _context.RevokedTokens.Add(new RevokedToken
            {
                Jti = jti,
                ExpiresAt = DateTime.UtcNow.AddMinutes(1)
            });
            await _context.SaveChangesAsync();
            return NoContent();
        }
    }
}
