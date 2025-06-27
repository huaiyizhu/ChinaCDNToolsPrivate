using System;
using System.Collections.Generic;
using System.Runtime.ConstrainedExecution;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Cloud.MooncakeService.Common;

namespace Mooncake.Cdn.CredentialManagementTool
{
    /// <summary>
    /// KeyVaultAccessV3 provides access to Azure Key Vault using SNI certificate (by SNI name) from local store, using Azure SDK and MSAL.
    /// </summary>
    public class KeyVaultAccessV3 : IDisposable
    {
        private SecretClient secretClient;
        private CertificateClient certificateClient;
        private string keyvaultUrl;
        private bool disposed = false;

        public KeyVaultAccessV3(KeyVaultSettingInfo settingInfo)
            : this(settingInfo.Url, settingInfo.AADInfo.ClientId, settingInfo.AADInfo.CertificateThumbprintOrName, "common")
        {
        }

        public KeyVaultAccessV3(string keyvaultUrl, string clientId, string sniCertName, string tenantId)
        {
            this.keyvaultUrl = keyvaultUrl;
            var cert = FindCertificateByName(sniCertName);
            var credentialOptions = new ClientCertificateCredentialOptions
            {
                AuthorityHost = GetKeyVaultAuthorityHost(new Uri(keyvaultUrl)),
                SendCertificateChain = true,
                AdditionallyAllowedTenants = { "*" } // Allow all tenants
            };
            var credential = new ClientCertificateCredential(tenantId, clientId, cert, credentialOptions);
            this.secretClient = new SecretClient(new Uri(keyvaultUrl), credential);
            this.certificateClient = new CertificateClient(new Uri(keyvaultUrl), credential);
        }

        private X509Certificate2 FindCertificateByName(string certName)
        {
            var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);
            try
            {
                var certs = store.Certificates.Find(X509FindType.FindBySubjectName, certName, false);
                if (certs.Count == 0)
                    throw new ArgumentException($"Cannot find certificate by SNI name '{certName}' in LocalMachine store.");
                return certs[0];
            }
            finally
            {
                store.Close();
            }
        }

        public async Task<KeyVaultSecret> GetSecretAsync(string name)
        {
            return await secretClient.GetSecretAsync(name);
        }

        public async Task SetSecretAsync(string name, string value)
        {
            await secretClient.SetSecretAsync(name, value);
        }

        public async Task<List<SecretInfo>> GetAllSecretsAsync(bool includeCertificates)
        {
            List<SecretInfo> results = new List<SecretInfo>();
            await foreach (var secretProperties in secretClient.GetPropertiesOfSecretsAsync())
            {
                if (secretProperties.Enabled.HasValue && !secretProperties.Enabled.Value)
                {
                    continue; // Skip disabled secrets if not requested
                }

                if (!includeCertificates && secretProperties.ContentType?.StartsWith("application/x-pkcs12") == true)
                {
                    continue; // Skip certificates if not requested
                }

                KeyVaultSecret secret = await secretClient.GetSecretAsync(secretProperties.Name);
                results.Add(secret.ToSecretInfo());
            }

            return results;
        }

        public async Task<List<CertificateInfo>> GetAllCertificatesAsync()
        {
            List<CertificateInfo> results = new List<CertificateInfo>();
            await foreach (var certProperties in certificateClient.GetPropertiesOfCertificatesAsync())
            {
                if (certProperties.Enabled.HasValue && !certProperties.Enabled.Value)
                {
                    continue; // Skip disabled certificates
                }
                KeyVaultCertificateWithPolicy certWithPolicy = await certificateClient.GetCertificateAsync(certProperties.Name);
                results.Add(certWithPolicy.ToCertificateInfo());
            }
            return results;
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposed) return;
            if (disposing)
            {
                // No unmanaged resources
            }
            disposed = true;
        }

        public Uri GetKeyVaultAuthorityHost(Uri vaultAddress)
        {
            Requires.Argument(nameof(vaultAddress), vaultAddress).NotNull();

            if (vaultAddress.Host.EndsWith("vault.azure.cn"))
            {
                return AzureAuthorityHosts.AzureChina;

            }
            else if (vaultAddress.Host.EndsWith("vault.azure.net"))
            {
                return AzureAuthorityHosts.AzurePublicCloud;
            }
            else
            {
                throw new ArgumentException($"Unable to detect key vault authority host for {vaultAddress}");
            }
        }

    }

    public static class CredentialUtilitiesV3
    {
        public static SecretInfo ToSecretInfo(this KeyVaultSecret secret)
        {
            return new SecretInfo
            {
                Name = secret.Name,
                Value = secret.Value,
                ContentType = secret.Properties.ContentType,
                Enabled = secret.Properties.Enabled,
                Expires = secret.Properties.ExpiresOn?.DateTime,
                NotBefore = secret.Properties.NotBefore?.DateTime,
                Tags = secret.Properties.Tags,
                Version = secret.Properties.Version,
                Id = secret.Id.ToString(),
            };
        }

        public static CertificateInfo ToCertificateInfo(this KeyVaultCertificateWithPolicy cert)
        {
            var certInfo = new CertificateInfo
            {
                Name = cert.Name,
                Version = cert.Properties.Version,
                Id = cert.Id.ToString(),
                Enabled = cert.Properties.Enabled,
                Expires = cert.Properties.ExpiresOn?.DateTime,
                NotBefore = cert.Properties.NotBefore?.DateTime,
                Tags = cert.Properties.Tags,
                ContentType = cert.Policy?.ContentType?.ToString(), // Convert enum to string
                Thumbprint = cert.Properties.X509Thumbprint != null ? BitConverter.ToString(cert.Properties.X509Thumbprint).Replace("-", string.Empty) : null,
                Certificate = cert.Cer != null ? new X509Certificate2(cert.Cer) : null,
                Value = cert.Cer != null ? Convert.ToBase64String(cert.Cer) : null // Store base64 string of certificate
            };

            return certInfo;
        }
    }

}
