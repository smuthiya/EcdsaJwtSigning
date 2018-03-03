using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;

namespace ConsoleApp1
{
    class Program
    {
        static void Main(string[] args)
        {
            //Create Private-Public Key pair
            var key = CngKey.Create(CngAlgorithm.ECDsaP256, "MYKey",
                new CngKeyCreationParameters
                {
                    KeyCreationOptions = CngKeyCreationOptions.OverwriteExistingKey,
                    KeyUsage =  CngKeyUsages.AllUsages,
                    ExportPolicy = CngExportPolicies.AllowPlaintextExport
                });
            var privateKey = Convert.ToBase64String(key.Export(CngKeyBlobFormat.EccPrivateBlob));
            var publicKey = Convert.ToBase64String(key.Export(CngKeyBlobFormat.EccPublicBlob));

            //Use the private key to create ECDsa object
            var privateECDsa = LoadPrivateKey(privateKey);

            //Use the public key to create ECDsa object
            var publicECDsa = LoadPublicKey(publicKey);

            //Create JWT token and sign it using ECDsa
            var jwt = CreateSignedJwt(privateECDsa);

            //Verify JWT token and sign it using ECDsa
            var isValid = VerifySignedJwt(publicECDsa, jwt);

            Console.WriteLine(isValid ? "Valid!" : "Not Valid...");
        }

        private static string CreateSignedJwt(ECDsa eCDsa)
        {
            var now = DateTime.UtcNow;
            var tokenHandler = new JwtSecurityTokenHandler();

            var jwtToken = tokenHandler.CreateJwtSecurityToken(
                issuer: "me",
                audience: "you",
                subject: null,
                notBefore: now,
                expires: now.AddMinutes(30),
                issuedAt: now,
                signingCredentials: new SigningCredentials(
                    new ECDsaSecurityKey(eCDsa), SecurityAlgorithms.EcdsaSha256));

            return tokenHandler.WriteToken(jwtToken);
        }

        private static bool VerifySignedJwt(ECDsa eCDsa, string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            var claimsPrincipal = tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidIssuer = "me",
                ValidAudience = "you",
                IssuerSigningKey = new ECDsaSecurityKey(eCDsa)
            }, out var parsedToken);

            return claimsPrincipal.Identity.IsAuthenticated;
        }

        private static ECDsa LoadPrivateKey(string privateKey)
        {
            var ecDsaCng = new ECDsaCng(CngKey.Import(Convert.FromBase64String(privateKey), CngKeyBlobFormat.EccPrivateBlob));
            ecDsaCng.HashAlgorithm = CngAlgorithm.ECDsaP256;
            return ecDsaCng;
        }

        private static ECDsa LoadPublicKey(string publicKey)
        {
            var ecDsaCng = new ECDsaCng(CngKey.Import(Convert.FromBase64String(publicKey), CngKeyBlobFormat.EccPublicBlob));
            ecDsaCng.HashAlgorithm = CngAlgorithm.ECDsaP256;
            return ecDsaCng;
        }
    }
}
