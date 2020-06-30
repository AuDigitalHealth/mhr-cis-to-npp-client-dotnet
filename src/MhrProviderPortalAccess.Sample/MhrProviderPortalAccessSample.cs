using System;
using System.Security.Cryptography.X509Certificates;
using System.Windows.Forms;
using Digitalhealth.MhrProviderPortalAccess;
using RestSharp;

namespace MhrProviderPortalAccess.Sample
{
    public class MhrProviderPortalAccessSample
    {
        public void Sample()
        {
            // ------------------------------------------------------------------------------
            // Set up
            // ------------------------------------------------------------------------------

            // Set the URL for the CIStoNPP endpoint- uses B2B endpoint + CIStoNPP
            string b2bEndpoint = "https://b2b.ehealthvendortest.health.gov.au/";
            string url = b2bEndpoint + "CIStoNPP";

            // Provide Client id allocated by the NIO when registering for this interface
            string clientId = "<Client id>";

            // Provide the product name and version registered
            string productName = "<Product Name>";
            string productVersion = "<Product Version>";

            // Obtain the certificate by serial number
            // Obtain the certificate by thumbprint
            X509Certificate2 clientCert = GetCertificate("Thumbprint", X509FindType.FindByThumbprint, StoreName.My, StoreLocation.CurrentUser, true);

            // Read the HPIO out of the certificate
            string hpio = (clientCert != null ? clientCert.Subject.Split('.')[1] : "");

            // Create client
            MhrRestClient client = new MhrRestClient(url, clientId, clientCert, productName, productVersion);

            // Add HPII of provider accessing portal
            string hpii = "<HPI-I number";

            // Populate data from patient details
            // Get patient identifier - ONLY one of these
            string ihi = "<Either: ihi number";
            string mcn = "<or: medicare number";
            string dva = "<or: dva number";
            // Patient demographics
            string dob = Convert.ToDateTime("DOB").ToString("dd-MM-yyyy"); ;
            string gender = "M, F, U or I";
            string family = "Surname only";


            // Set up the request
            try
            {
                //HTTP Response
                string response = client.GetAccessToNpp(hpio, hpii, dob, gender, family, ihi, mcn, dva);

                if (response != null)
                {
                    // Display the response in a webbrowser that has internet access
                    WebBrowser webBrowser = new WebBrowser() {DocumentText = response};
                }

            }
            catch (Exception)
            {
                // If an error is encountered, look at client.restResponse
                // for detailed description of the error.
                IRestResponse lookAtStatusCode = client.restResponse;
            }
        }


        /// <summary>
        /// Gets a certificate from the Windows certificate repository.
        /// </summary>
        /// <param name="findValue">Find value.</param>
        /// <param name="findType">Find type.</param>
        /// <param name="storeName">Store name.</param>
        /// <param name="storeLocation">Store location.</param>
        /// <param name="valid">Valid certificate flag.</param>
        /// <returns>Matching certificate.</returns>
        private static X509Certificate2 GetCertificate(String findValue, X509FindType findType, StoreName storeName, StoreLocation storeLocation, bool valid)
        {
            X509Store certStore = new X509Store(storeName, storeLocation);
            certStore.Open(OpenFlags.ReadOnly);

            X509Certificate2Collection foundCerts =
                certStore.Certificates.Find(findType, findValue, valid);
            certStore.Close();

            // Check if any certificates were found with the criteria
            if (foundCerts.Count == 0)
                throw new ArgumentException("Certificate was not found with criteria '" + findValue + "'");

            // Check if more than one certificate was found with the criteria
            if (foundCerts.Count > 1)
                throw new ArgumentException("More than one certificate found with criteria '" + findValue + "'");

            return foundCerts[0];
        }

    }
}
