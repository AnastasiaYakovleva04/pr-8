using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text;
using yakovleva_pr8.Models;
using Task = System.Threading.Tasks.Task;

namespace yakovleva_pr8.Services
{
    public class TokenService
    {
        private readonly TrpoPr8Context _context;
        public TokenService(TrpoPr8Context context)
        {
            _context = context;
        }

        public string GenerateRefreshToken()
        {
            var rand = new byte[32];
            RandomNumberGenerator.Create().GetBytes(rand);
            return Convert.ToBase64String(rand);
        }

        public string GetHash(string input)
        {
            var hash = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(input));
            return Convert.ToHexString(hash).ToLower();
        }

        public async System.Threading.Tasks.Task SaveRefreshTokenAsync(int userId, string token)
        {
            var refreshToken = new RefreshToken
            {
                UserId = userId,
                TokenHash = GetHash(token),
                ExpiresAt = DateTime.UtcNow.AddDays(7)
            };
            _context.RefreshTokens.Add(refreshToken);
            await _context.SaveChangesAsync();
        }

        public async Task<RefreshToken?> GetRefreshTokenAsync(string token)
        {
            var hash = GetHash(token);
            return await _context.RefreshTokens.Include(r => r.User).FirstOrDefaultAsync(r => r.TokenHash == hash);
        }

        public async System.Threading.Tasks.Task RemoveRefreshTokenAsync(RefreshToken token)
        {
            _context.RefreshTokens.Remove(token);
            await _context.SaveChangesAsync();
        }

        public async Task RevokeJwtAsync(string jti, DateTime expiresAt)
        {
            var revokedToken = new RevokedToken
            {
                Jti = jti,
                ExpiresAt = expiresAt
            };
            _context.RevokedTokens.Add(revokedToken);
            await _context.SaveChangesAsync();
        }
    }
}
