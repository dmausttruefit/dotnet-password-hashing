using System.Security.Cryptography;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.WebUtilities;

namespace PasswordHashing;

public static class PasswordHasher
{
    private const byte CurrentHashVersion = 0x01;

    // ReSharper disable ArgumentsStyleOther
    private static readonly IReadOnlyDictionary<byte, HashSettings> HashSettingsByVersion =
        new Dictionary<byte, HashSettings>
        {
            {
                0x01,
                new HashSettings(
                    KeyDerivationPrf.HMACSHA256,
                    saltSize: 128 / 8,
                    iterationCount: 10000,
                    numberOfBytesRequested: 256 / 8)
            }
        };
    // ReSharper restore ArgumentsStyleOther

    public static string HashPassword(string password)
    {
        if (string.IsNullOrEmpty(password))
            throw new ArgumentNullException(nameof(password));

        var currentHashSettings = HashSettingsByVersion[CurrentHashVersion];

        using var rng = RandomNumberGenerator.Create();
        var salt = new byte[currentHashSettings.SaltSize];
        rng.GetBytes(salt);

        var key = GenerateKey(password, salt, currentHashSettings);
        var hashBytes = new[] { CurrentHashVersion }.Concat(salt.Concat(key)).ToArray();

        return WebEncoders.Base64UrlEncode(hashBytes);
    }

    public static bool VerifyPassword(string password, string hash)
    {
        if (string.IsNullOrEmpty(password))
            throw new ArgumentNullException(nameof(password));

        if (string.IsNullOrEmpty(hash))
            throw new ArgumentNullException(nameof(hash));

        var hashBytes = WebEncoders.Base64UrlDecode(hash);
        var hashVersion = hashBytes[0];
        var hashSettings = HashSettingsByVersion[hashVersion];

        var salt = hashBytes.Skip(1).Take(hashSettings.SaltSize).ToArray();
        var originalKey = hashBytes.Skip(1 + hashSettings.SaltSize).ToArray();

        var passwordKey = GenerateKey(password, salt, hashSettings);

        return CryptographicOperations.FixedTimeEquals(originalKey, passwordKey);
    }

    private static byte[] GenerateKey(string password, byte[] salt, HashSettings hashSettings) =>
        KeyDerivation.Pbkdf2(
            password,
            salt,
            hashSettings.KeyDerivationPrf,
            hashSettings.IterationCount,
            hashSettings.NumberOfBytesRequested);

    private class HashSettings
    {
        public HashSettings(
            KeyDerivationPrf keyDerivationPrf,
            int saltSize,
            int iterationCount,
            int numberOfBytesRequested)
        {
            KeyDerivationPrf = keyDerivationPrf;
            SaltSize = saltSize;
            IterationCount = iterationCount;
            NumberOfBytesRequested = numberOfBytesRequested;
        }

        public KeyDerivationPrf KeyDerivationPrf { get; }
        public int SaltSize { get; }
        public int IterationCount { get; }
        public int NumberOfBytesRequested { get; }
    }
}