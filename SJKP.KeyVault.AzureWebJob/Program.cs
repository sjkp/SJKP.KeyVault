using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Azure.WebJobs;
using SampleKeyVaultClientWebRole;
using System.Configuration;

namespace SJKP.KeyVault.AzureWebJob
{
    // Learn to gain access to certificates: http://azure.microsoft.com/blog/2014/10/27/using-certificates-in-azure-websites-applications/

    // To learn more about Microsoft Azure WebJobs SDK, please see http://go.microsoft.com/fwlink/?LinkID=320976
    class Program
    {
        // Please set the following connection strings in app.config for this WebJob to run:
        // AzureWebJobsDashboard and AzureWebJobsStorage
        static void Main()
        {
            Console.WriteLine("Hello from job");
            var certThumbprint = ConfigurationManager.AppSettings[Constants.KeyVaultAuthCertThumbprintSetting];

            Console.WriteLine("Cert thumbprint: " + certThumbprint);

            var cert = CertificateHelper.FindCertificateByThumbprint(certThumbprint);
            if (cert != null)
                Console.WriteLine("Cert found");

            //TODO the secret URL should go into appsettings too.
            Console.WriteLine("Secret was: " + KeyVaultAccessor.GetSecret("https://sjkpvault.vault.azure.net/secrets/MyPassword/94fd5e8fe2eb447abc6be515e1e9d08c"));
        }
    }
}
