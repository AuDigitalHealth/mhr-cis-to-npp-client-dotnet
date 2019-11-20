using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;

namespace Digitalhealth.MhrProviderPortalAccess
{


    /// <summary>
    /// Class to generate the Json Web Token based on the data passed in
    /// Signed using the NASH organisation Certificate
    /// Useful Info for Testing Token if having an issue: https://jwt.io/
    /// </summary>
    public class JsonWebTokenUtility
    {
        // HS256 uses a shared secret
        // RS256 uses a public/private key pair
        public enum JwtHashAlgorithm
        {
            RS256, HS256, HS384, HS512
        }

        private static Dictionary<JwtHashAlgorithm, Func<RSA, byte[], byte[]>> HashAlgorithmsSigning;

        /// <summary>
        ///  Sign data
        /// </summary>
        static JsonWebTokenUtility()
        {
            HashAlgorithmsSigning = new Dictionary<JwtHashAlgorithm, Func<RSA, byte[], byte[]>>
            { { JwtHashAlgorithm.RS256, (key, value) => { return key.SignData(value, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1); } },
              { JwtHashAlgorithm.HS256, (key, value) => { return key.SignData(value, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1); } },
              { JwtHashAlgorithm.HS384, (key, value) => { return key.SignData(value, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1); } },
              { JwtHashAlgorithm.HS512, (key, value) => { return key.SignData(value, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1); } }
            };
        }

        /// <summary>
        /// Create Json Web Token
        /// </summary>
        /// <param name="clientId"></param>
        /// <param name="privateKey"></param>
        /// <param name="hpio"></param>
        /// <param name="userId"></param>
        /// <param name="dateOfBirth"></param>
        /// <param name="gender"></param>
        /// <param name="family"></param>
        /// <param name="ihiNum"></param>
        /// <param name="mcaNum"></param>
        /// <param name="dvaNum"></param>
        /// <returns></returns>
        public static string GetNppAssertion(string clientId, RSA privateKey, string hpio, string userId,
                                             string dateOfBirth, string gender, string family, 
                                             string ihiNum, string mcaNum, string dvaNum)
        {
            // Allow for a -60 to +60 interval gap to allow for server to be within 1 minute of computer
            TimeSpan t = DateTime.UtcNow - new DateTime(1970, 1, 1);
            int epoch = (int) t.TotalSeconds;
            var uuid = "uuid:" + Guid.NewGuid();
            var token = "";

            //See which search we are doing
            if (!String.IsNullOrEmpty(ihiNum))
            {
                var payload = new
                {
                    iss = clientId, jti = uuid, iat = (epoch - 60), exp = (epoch + 60), organisationID = hpio, userID = userId,
                    dob = dateOfBirth, sex = gender, family_name = family, ihi = ihiNum
                };
                token = EncodeUsingCertificate(payload, privateKey, JwtHashAlgorithm.RS256);
            }
            else if (!String.IsNullOrEmpty(mcaNum))
            {
                var payload = new
                {
                    iss = clientId, jti = uuid, iat = (epoch - 60), exp = (epoch + 60), organisationID = hpio, userID = userId,
                    dob = dateOfBirth, sex = gender, family_name = family, mcn = mcaNum
                };
                token = EncodeUsingCertificate(payload, privateKey, JwtHashAlgorithm.RS256);
            }
            else if (!String.IsNullOrEmpty(dvaNum))
            {
                var payload = new
                {
                    iss = clientId, jti = uuid, iat = (epoch - 60), exp = (epoch + 60), organisationID = hpio, userID = userId,
                    dob = dateOfBirth, sex = gender, family_name = family, dva = dvaNum
                };
                token = EncodeUsingCertificate(payload, privateKey, JwtHashAlgorithm.RS256);
            }

            return (token);
        }

        /// <summary>
        /// Encode Data and sign with Certificate
        /// </summary>
        /// <param name="payload"></param>
        /// <param name="keyBytes"></param>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public static string EncodeUsingCertificate(object payload, RSA keyBytes, JwtHashAlgorithm algorithm)
        {
            var segments = new List<string>();
            var header = new {alg = algorithm.ToString(), typ = "JWT"};

            byte[] headerBytes = Encoding.UTF8.GetBytes(new JavaScriptSerializer().Serialize(header));
            byte[] payloadBytes = Encoding.UTF8.GetBytes(new JavaScriptSerializer().Serialize(payload));

            segments.Add(Base64UrlEncode(headerBytes));
            segments.Add(Base64UrlEncode(payloadBytes));

            var stringToSign = string.Join(".", segments.ToArray());

            var bytesToSign = Encoding.UTF8.GetBytes(stringToSign);

            byte[] signature = HashAlgorithmsSigning[algorithm](keyBytes, bytesToSign);
            segments.Add(Base64UrlEncode(signature));

            return string.Join(".", segments.ToArray());
        }

        /// <summary>
        /// Encode data
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        private static string Base64UrlEncode(byte[] input)
        {
            var output = Convert.ToBase64String(input);
            output = output.Split('=')[0]; // Remove any trailing '='s
            output = output.Replace('+', '-'); // 62nd char of encoding
            output = output.Replace('/', '_'); // 63rd char of encoding
            return output;
        }

        /// <summary>
        /// Decode data
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        private static byte[] Base64UrlDecode(string input)
        {
            var output = input;
            output = output.Replace('-', '+'); // 62nd char of encoding
            output = output.Replace('_', '/'); // 63rd char of encoding
            switch (output.Length % 4) // Pad with trailing '='s
            {
                case 0: break; // No pad chars in this case
                case 2:
                    output += "==";
                    break; // Two pad chars
                case 3:
                    output += "=";
                    break; // One pad char
                default: throw new System.Exception("Illegal base64url string!");
            }
            var converted = Convert.FromBase64String(output); // Standard base64 decoder
            return converted;
        }

    }
}
