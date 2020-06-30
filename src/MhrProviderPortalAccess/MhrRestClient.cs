using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using RestSharp;

namespace Digitalhealth.MhrProviderPortalAccess
{
    public class MhrRestClient
    {
        // Expose rest response to look at the HTTP Response code if required
        public IRestResponse restResponse;
        
        private RestClient _restClient = null;
        private readonly string _endpoint;
        private readonly string _client_id;
        private readonly X509Certificate2 _cert;
        private readonly string _productName;
        private readonly string _productVersion;

        /// <summary>
        /// Initiate client with values needed to connect to the B2B Interface
        /// </summary>
        /// <param name="endpoint">URL of the endpoint to pass data in to</param>
        /// <param name="client_id">Unique Vendor client ID</param>
        /// <param name="cert">The NASH organisation certificate to be used to connect to the B2B channel</param>
        /// <param name="productName">Name of the product.</param>
        /// <param name="productVersion">The product version.</param>
        public MhrRestClient(string endpoint, string client_id, X509Certificate2 cert, string productName, string productVersion)
        {
            _endpoint = endpoint;
            _client_id = client_id;
            _productName = productName;
            _productVersion = productVersion;
            _cert = cert;

            //Set up rest client
            _restClient = new RestClient(_endpoint);
            restResponse = null;

            //Require Cert to authenticate?
            if (_cert != null)
            {
                _restClient.ClientCertificates = new X509CertificateCollection(new[] {_cert});
            }

            //Set Call back to ignore certificate validation
            ServicePointManager.ServerCertificateValidationCallback = delegate (Object obj, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors) { return (true); };
        }

        /// <summary>
        /// Pass in the data required in order to create the Json Web Token and Consumer Search details.
        /// </summary>
        /// <param name="hpio">hpio of organisation and matches NASH certificate (mandatory)</param>
        /// <param name="userId">hpii of user (mandatory)</param>
        /// <param name="dateOfBith">(mandatory)</param>
        /// <param name="gender">(mandatory)</param>
        /// <param name="family">(mandatory)</param>
        /// <param name="ihi">One of 3 identifiers that can be used (conditional)</param>
        /// <param name="mcn">One of 3 identifiers that can be used (conditional)</param>
        /// <param name="dva">One of 3 identifiers that can be used (conditional)</param>
        /// <returns>Returns the HTML to go in a WebBrowser window. An Error will return nothing</returns>
        public string GetAccessToNpp(string hpio, string userId, string dateOfBith, string gender, string family, string ihi, string mcn, string dva)
        {
            // Certificates
            RSA _privateKey = _cert.GetRSAPrivateKey();
            var jwt = JsonWebTokenUtility.GetNppAssertion(_client_id, _privateKey, hpio, userId, dateOfBith, gender, family, ihi, mcn, dva);

            var request = new RestRequest("", Method.POST);
            request.AddHeader("Content-Type", "application/x-www-form-urlencoded");
            request.AddHeader("productName", _productName);
            request.AddHeader("productVersion", _productVersion);
            request.AddParameter("JWT", jwt);

            restResponse = _restClient.Execute(request);
            if (restResponse.StatusCode == HttpStatusCode.OK)
            {
                return (restResponse.Content);
            }
            return null;
        }

    }
}