namespace EnterpriseWebhooks
{
    using System;
    using System.Linq;
    using Nancy;
    using Nancy.IO;
    using Org.BouncyCastle.Asn1.Pkcs;
    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.Security;

    public class HomeModule : NancyModule
    {
        public HomeModule()
        {
            InitialiseRoutes();
        }

        internal void InitialiseRoutes()
        {
            Post("/", async _ =>
            {
                string signature = Request.Headers["X-MessageMedia-Signature"].FirstOrDefault();
                if (string.IsNullOrEmpty(signature))
                {
                    return new Response {StatusCode = HttpStatusCode.Unauthorized};
                }

                byte[] signatureBytes = Convert.FromBase64String(signature);
                byte[] dataBytes = new byte[Request.Body.Length];

                RequestStream.FromStream(Request.Body).Read(dataBytes, 0, (int) Request.Body.Length);

                if (!VerifySignature(signatureBytes, dataBytes, Environment.GetEnvironmentVariable("PUBLIC_CERT_PATH")))
                {
                    return new Response {StatusCode = HttpStatusCode.Unauthorized};
                }

                return await HandleCallbackData(dataBytes);
            });
        }

        internal Response HandleCallbackData(byte[] payload)
        {
            // Custom logic here

            return new Response { StatusCode = HttpStatusCode.OK };
        }

        public static bool VerifySignature(byte[] signature, byte[] data, string publicKeyPath)
        {
            var publicKey = ReadRsaKeyPair(publicKeyPath);
            ISigner verifier = SignerUtilities.GetSigner(PkcsObjectIdentifiers.Sha256WithRsaEncryption.Id);
            verifier.Init(false, publicKey);
            verifier.BlockUpdate(data, 0, data.Length);

            return verifier.VerifySignature(signature);
        }

        internal static RsaKeyParameters ReadRsaKeyPair(string pemFileName)
        {
            var fileStream = System.IO.File.OpenText(pemFileName);
            var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(fileStream);
            return (RsaKeyParameters)pemReader.ReadObject();
        }
    }
}
