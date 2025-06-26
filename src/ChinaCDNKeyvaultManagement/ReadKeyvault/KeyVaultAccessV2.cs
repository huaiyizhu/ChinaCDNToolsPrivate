using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.Rest.Azure;

namespace Mooncake.Cdn.CredentialManagementTool
{
    /// <summary>
    /// KeyVaultAccessV2 provides access to Azure Key Vault using SNI certificate (by SNI name) from local store.
    /// </summary>
    public class KeyVaultAccessV2 : IDisposable
    {
        private KeyVaultClient keyVaultClient;
        private string keyvaultUrl;
        private bool disposed = false;

        public KeyVaultAccessV2(KeyVaultSettingInfo settingInfo)
            : this(settingInfo.Url, settingInfo.AADInfo.ClientId, settingInfo.AADInfo.CertificateThumbprintOrName)
        {
        }

        public KeyVaultAccessV2(string keyvaultUrl, string clientId, string sniCertName)
        {
            this.keyvaultUrl = keyvaultUrl;
            this.keyVaultClient = InitWithSniCert(keyvaultUrl, clientId, sniCertName);
        }

        private KeyVaultClient InitWithSniCert(string vaultaddr, string clientId, string sniCertName)
        {
            X509Certificate2[] certs = CertUtils.GetValidCertificatesByName(sniCertName, StoreName.My, StoreLocation.LocalMachine);
            if (certs == null || certs.Length == 0)
                throw new ArgumentException($"Cannot find certificate by SNI name '{sniCertName}' in LocalMachine store.");
            var assertionCert = new ClientAssertionCertificate(clientId, certs[0]);
            // Use reflection to set _sendX5C to true for SNI scenario (for ADAL 3.x)
            var field = typeof(ClientAssertionCertificate).GetField("_sendX5C", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            if (field != null)
            {
                field.SetValue(assertionCert, true);
            }
            return new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(
                (authority, resource, scope) => GetAccessTokenWithCertAsync(authority, resource, scope, assertionCert)));
        }

        private static async Task<string> GetAccessTokenWithCertAsync(string authority, string resource, string scope, ClientAssertionCertificate assertionCert)
        {
            var context = new AuthenticationContext(authority, TokenCache.DefaultShared);
            var result = await context.AcquireTokenAsync(resource, assertionCert).ConfigureAwait(false);
            return result.AccessToken;
        }

        public async Task<SecretInfo> GetSecretAsync(string name, string version = null)
        {
            var bundle = string.IsNullOrEmpty(version)
                ? await keyVaultClient.GetSecretAsync(keyvaultUrl, name).ConfigureAwait(false)
                : await keyVaultClient.GetSecretAsync(keyvaultUrl, name, version).ConfigureAwait(false);
            return bundle.ToSecretInfo();
        }

        public async Task SetSecretAsync(string name, string value, DateTimeOffset? expires = null, IDictionary<string, string> tags = null, string contentType = null)
        {
            var attributes = new SecretAttributes(true, null, expires?.UtcDateTime);
            await keyVaultClient.SetSecretAsync(keyvaultUrl, name, value, tags, contentType, attributes).ConfigureAwait(false);
        }

        public async Task<CertificateInfo> GetCertificateAsync(string name, string version = null)
        {
            var certBundle = string.IsNullOrEmpty(version)
                ? await keyVaultClient.GetCertificateAsync(keyvaultUrl, name).ConfigureAwait(false)
                : await keyVaultClient.GetCertificateAsync(keyvaultUrl, name, version).ConfigureAwait(false);
            if (certBundle == null) return null;
            return certBundle.ToCertificateInfo();
        }

        public async Task ImportCertificateAsync(string name, string base64Pfx, string password = null, IDictionary<string, string> tags = null, CertificatePolicy policy = null, DateTimeOffset? expires = null)
        {
            var attributes = new CertificateAttributes(true, null, expires?.UtcDateTime);
            await keyVaultClient.ImportCertificateAsync(keyvaultUrl, name, base64Pfx, password, policy, attributes, tags).ConfigureAwait(false);
        }

        public async Task<List<SecretInfo>> ListSecretsAsync(bool includeCertificates = false)
        {
            var results = new List<SecretInfo>();
            IPage<SecretItem> secrets = await keyVaultClient.GetSecretsAsync(keyvaultUrl).ConfigureAwait(false);
            string nextPageLink = secrets.NextPageLink;
            while (true)
            {
                results.AddRange(secrets.Select(x => x.ToSecretInfo()));
                if (string.IsNullOrEmpty(nextPageLink))
                    break;
                secrets = await keyVaultClient.GetSecretsNextAsync(nextPageLink).ConfigureAwait(false);
                nextPageLink = secrets.NextPageLink;
            }
            if (!includeCertificates)
                results = results.Where(x => x.ContentType != CertificateContentType.Pfx && x.ContentType != CertificateContentType.Pem).ToList();
            return results;
        }

        public async Task<List<CertificateInfo>> ListCertificatesAsync()
        {
            var results = new List<CertificateInfo>();
            IPage<CertificateItem> certs = await keyVaultClient.GetCertificatesAsync(keyvaultUrl).ConfigureAwait(false);
            string nextPageLink = certs.NextPageLink;
            while (true)
            {
                results.AddRange(certs.Select(x => x.ToCertificateInfo()));
                if (string.IsNullOrEmpty(nextPageLink))
                    break;
                certs = await keyVaultClient.GetCertificatesNextAsync(nextPageLink).ConfigureAwait(false);
                nextPageLink = certs.NextPageLink;
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
                keyVaultClient?.Dispose();
            }
            disposed = true;
        }
    }
}
