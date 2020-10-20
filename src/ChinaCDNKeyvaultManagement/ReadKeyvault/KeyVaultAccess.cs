using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.Rest.Azure;

namespace ReadKeyvault
{
    public class SecretInfo
    {
        public string Name { get; set; }

        public string Value { get; set; }

        public IDictionary<string, string> Tags { get; set; }

        public string ContentType { get; set; }

        public DateTime? NotBefore { get; set; }

        public DateTime? Expires { get; set; }
    }

    public class KeyVaultAccess : IDisposable
    {
        private KeyVaultClient keyVaultClient = null;
        private bool disposed = false;

        private string keyvaultUrl;

        public KeyVaultAccess(
        string keyvaultUrl,
        string clientId,
        string certThumbprint,
        bool useSecret,
        Func<string> secret)
        {
            this.Init(keyvaultUrl, clientId, certThumbprint, useSecret, secret);
        }

        public KeyVaultAccess(
            string keyvaultUrl,
            AADSettingInfo aadInfo)
        {
            this.Init(keyvaultUrl, aadInfo.ClientId, aadInfo.CertificateThumbprint, aadInfo.UseSecret, aadInfo.SecretRetriever);
        }

        public KeyVaultAccess(KeyVaultSettingInfo kvInfo)
            : this(kvInfo.Url, kvInfo.AADInfo)
        {
        }

        /// <summary>
        /// Gets the source.
        /// </summary>
        /// <value>
        /// The source.
        /// </value>
        public string Source
        {
            get { return string.Format("KeyVault: {0}", this.keyvaultUrl); }
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            this.Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Reads the secret.
        /// </summary>
        /// <param name="name">The name.</param>
        /// <returns>
        /// Secret value
        /// </returns>
        public string GetSecret(string name)
        {
            try
            {
                var bundle = this.keyVaultClient.GetSecretAsync(this.keyvaultUrl, name)
                                 .ConfigureAwait(false)
                                 .GetAwaiter().GetResult();
                return bundle.Value;
            }
            catch (AdalServiceException)
            {
                // authentication cert is not valid
                throw;
            }
            catch (KeyVaultErrorException ex)
            {
                if (ex.Body != null &&
                    ex.Body.Error != null &&
                    ex.Body.Error.Code == "SecretNotFound")
                {
                    return null;
                }

                throw;
            }
        }

        internal async Task DeleteAllSecrets(Predicate<SecretItem> isMathced)
        {
            List<SecretItem> allSecrets = await this.GetAllSecrets().ConfigureAwait(false);
            List<SecretItem> secrets = allSecrets.Where(x => isMathced(x)).ToList();

            Console.WriteLine("Total Secrets: {0}", allSecrets.Count);
            Console.WriteLine("Secrets to be deleted: {0}", secrets.Count);

            foreach (var secret in secrets)
            {
                Console.WriteLine("Deleting Secret {0} in key vault...", secret.Id);
                await this.keyVaultClient.DeleteSecretAsync(this.keyvaultUrl, secret.Identifier.Name).ConfigureAwait(false);
            }
        }

        internal async Task DisableAllCertificates(Predicate<CertificateItem> isMatched)
        {
            List<CertificateItem> allCertificates = await this.GetAllCertificates().ConfigureAwait(false);
            List<CertificateItem> certificates = allCertificates.Where(x => isMatched(x)).ToList();

            Console.WriteLine("Total Certificates: {0}", allCertificates.Count);
            Console.WriteLine("Certificates to be disabled: {0}", certificates.Count);

            foreach (var cert in certificates)
            {
                Console.WriteLine("Disabling Certificate {0} in key vault...", cert.Id);
               // await this.keyVaultClient.DeleteCertificateAsync(this.keyvaultUrl, cert.Identifier.Name).ConfigureAwait(false);
            }
        }

        internal async Task DeleteAllCertificates(Predicate<CertificateItem> isMathced)
        {
            List<CertificateItem> allCertificates = await this.GetAllCertificates().ConfigureAwait(false);
            List<CertificateItem> certificates = allCertificates.Where(x => isMathced(x)).ToList();

            Console.WriteLine("Total Certificates: {0}", allCertificates.Count);
            Console.WriteLine("Certificates to be deleted: {0}", certificates.Count);

            foreach (var cert in certificates)
            {
                Console.WriteLine("Deleting Certificate {0} in key vault...", cert.Id);
                Console.WriteLine("Press any key to continue...");
                Console.ReadLine();
                await this.keyVaultClient.DeleteCertificateAsync(this.keyvaultUrl, cert.Identifier.Name).ConfigureAwait(false);
            }
        }

        public async Task ImportSecretsAndCerts(List<SecretInfo> secretsAndCerts, bool overwriteExisting = false)
        {
            foreach (var info in secretsAndCerts)
            {
                bool isCertificate = info.ContentType == CertificateContentType.Pem;

                try
                {
                    if (isCertificate)
                    {
                        var cert = await this.keyVaultClient.GetCertificateAsync(this.keyvaultUrl, info.Name).ConfigureAwait(false);
                        Console.WriteLine("[====Warning===] Certificate {0} already in keyvault", info.Name);
                    }
                    else
                    {
                        var secret = await this.keyVaultClient.GetSecretAsync(this.keyvaultUrl, info.Name).ConfigureAwait(false);
                        Console.WriteLine("[====Warning===] Secret {0} already in keyvault. Value: {1}", info.Name, secret.Value);

                        if (overwriteExisting)
                        {
                            if (secret.Value != info.Value ||
                                info.Expires != secret.Attributes.Expires ||
                                info.NotBefore != secret.Attributes.NotBefore)
                            {
                                Console.WriteLine("Importing Secret {0} to keyvault with new value: {1}", info.Name, info.Value);
                                SecretAttributes attribute = new SecretAttributes(true, info.NotBefore, info.Expires);
                                await this.keyVaultClient.SetSecretAsync(this.keyvaultUrl, info.Name, info.Value, info.Tags, info.ContentType, attribute).ConfigureAwait(false);
                            }
                            else
                            {
                                Console.WriteLine($"Same secret value for secret {info.Name}, skip import");
                            }
                        }
                    }
                }
                catch (KeyVaultErrorException ex)
                {
                    if (ex.Response != null &&
                        ex.Response.StatusCode == System.Net.HttpStatusCode.NotFound)
                    {
                        if (isCertificate)
                        {
                            Console.WriteLine("Importing Certificate {0} to keyvault", info.Name);
                            CertificatePolicy policy = new CertificatePolicy
                            {
                                KeyProperties = new KeyProperties
                                {
                                    Exportable = true,
                                    KeyType = "RSA",
                                },
                                SecretProperties = new SecretProperties
                                {
                                    ContentType = CertificateContentType.Pem,
                                }
                            };
                            try
                            {
                                CertificateAttributes attribute = new CertificateAttributes(true, info.NotBefore, info.Expires);
                                await this.keyVaultClient.ImportCertificateAsync(this.keyvaultUrl, info.Name, info.Value, null, policy, attribute).ConfigureAwait(false);
                            }
                            catch (Exception newex)
                            {
                                Console.WriteLine(string.Format("[================== Skip error certificate {0} for message: {1} ====================]", info.Name, newex.Message));
                            }
                        }
                        else
                        {
                            Console.WriteLine("Importing Secret {0} to keyvault", info.Name);
                            SecretAttributes attribute = new SecretAttributes(true, info.NotBefore, info.Expires);
                            await this.keyVaultClient.SetSecretAsync(this.keyvaultUrl, info.Name, info.Value, info.Tags, info.ContentType, attribute).ConfigureAwait(false);
                        }
                    }
                }
            }
        }

        private async Task<X509Certificate2> GetExistingCertificate(string certName)
        {
            try
            {
                var cert = await this.keyVaultClient.GetCertificateAsync(this.keyvaultUrl, certName).ConfigureAwait(false);

                if (cert != null)
                {
                    return new X509Certificate2(cert.Cer);
                }
                else
                {
                    return null;
                }
            }
            catch (KeyVaultErrorException ex)
            {
                if (ex.Response != null &&
                    ex.Response.StatusCode == System.Net.HttpStatusCode.NotFound)
                {
                    return null;
                }
                else
                {
                    throw;
                }
            }
        }

        public async Task WriteSecret(string name, string value, bool overwriteExisting)
        {
            try
            {
                var secret = await this.keyVaultClient.GetSecretAsync(this.keyvaultUrl, name).ConfigureAwait(false);
                Console.WriteLine("[====Warning===] Secret {0} already in keyvault", name);

                if(overwriteExisting)
                {
                    Console.WriteLine("Importing Secret {0} to keyvault", name);
                    await this.keyVaultClient.SetSecretAsync(this.keyvaultUrl, name, value).ConfigureAwait(false);
                }
            }
            catch (KeyVaultErrorException ex)
            {
                if (ex.Response != null &&
                    ex.Response.StatusCode == System.Net.HttpStatusCode.NotFound)
                {
                    Console.WriteLine("Importing Secret {0} to keyvault", name);
                    await this.keyVaultClient.SetSecretAsync(this.keyvaultUrl, name, value).ConfigureAwait(false);
                }
            }
        }

        public async Task<CertificatePolicy> GetCertificatePolicy(string certificateName)
        {
            CertificatePolicy policy = await this.keyVaultClient.GetCertificatePolicyAsync(this.keyvaultUrl, certificateName).ConfigureAwait(false);
            return policy;
        }

        public async Task ImportCertificates(List<Tuple<string, string, string>> certificates, bool overwriteExisting = false)
        {
            foreach (var info in certificates)
            {
                string name = info.Item1;
                string thumbprint = info.Item2;
                string content = info.Item3;

                X509Certificate2 existingCert = await this.GetExistingCertificate(name).ConfigureAwait(false);
                bool doImport = false;

                if (existingCert != null)
                {
                    Console.WriteLine($"[====Warning===] Certificate {name}: Overwrite Existing: {overwriteExisting}.\n\tExisting: {existingCert.Thumbprint}\n\tNew:      {thumbprint}");
                    doImport = overwriteExisting && existingCert.Thumbprint != thumbprint;
                }
                else
                {
                    doImport = true;
                }

                if (doImport)
                {
                    Console.WriteLine($"Importing Certificate {name} {thumbprint} to keyvault");
                    await this.keyVaultClient.ImportCertificateAsync(this.keyvaultUrl, info.Item1, content).ConfigureAwait(false);
                }
            }
        }

        public async Task<IEnumerable<Tuple<string, string, string>>> DownloadCertificates(Predicate<CertificateItem> isMatch)
        {
            //List<Tuple<string, X509Certificate2>> results = new List<Tuple<string, X509Certificate2>>();
            List<Tuple<string, string, string>> results = new List<Tuple<string, string, string>>();

            List<CertificateItem> allCertificates = await this.GetAllCertificates().ConfigureAwait(false);
            List<CertificateItem> certificates = allCertificates.Where(x => isMatch(x)).ToList();

            Console.WriteLine("Total Certificates: {0}", allCertificates.Count);
            Console.WriteLine("Certificates to be downloaded: {0}", certificates.Count);

            foreach (var certificate in certificates)
            {
                var secretBundle = await this.keyVaultClient.GetSecretAsync(this.keyvaultUrl, certificate.Identifier.Name).ConfigureAwait(false);

                //string thumbprint = Convert.ToBase64String(certificate.X509Thumbprint);
                byte[] raw =  Convert.FromBase64String(secretBundle.Value);
                X509Certificate2 cert = new X509Certificate2(raw);
                string thumbprint = cert.Thumbprint;

                results.Add(new Tuple<string, string, string>(certificate.Identifier.Name, thumbprint, secretBundle.Value));
            }

            return results;
        }

        public async Task<IEnumerable<SecretInfo>> DownloadSecretsAndCerts(Predicate<SecretItem> isMatch)
        {
            //List<Tuple<string, X509Certificate2>> results = new List<Tuple<string, X509Certificate2>>();
            List<SecretInfo> results = new List<SecretInfo>();

            List<SecretItem> allSecrets = await this.GetAllSecrets().ConfigureAwait(false);
            List<SecretItem> secrets = allSecrets.Where(x => isMatch(x)).ToList();

            Console.WriteLine("Total Secrets: {0}", allSecrets.Count);
            Console.WriteLine("Secrets to be downloaded: {0}", secrets.Count);

            foreach (var secret in secrets)
            {
                var secretBundle = await this.keyVaultClient.GetSecretAsync(this.keyvaultUrl, secret.Identifier.Name).ConfigureAwait(false);
                SecretInfo info = new SecretInfo
                {
                    Name = secret.Identifier.Name,
                    Value = secretBundle.Value,
                    Tags = secretBundle.Tags,
                    ContentType = secretBundle.ContentType,
                    NotBefore = secretBundle.Attributes.NotBefore,
                    Expires = secretBundle.Attributes.Expires,
                };
                results.Add(info);
            }

            return results;
        }

        private async Task<List<SecretItem>> GetAllSecrets()
        {
            List<SecretItem> results = new List<SecretItem>();

            IPage<SecretItem> secrets = await this.keyVaultClient.GetSecretsAsync(this.keyvaultUrl).ConfigureAwait(false);

            string nextPageLink = secrets.NextPageLink;
            while (true)
            {
                results.AddRange(secrets);

                if (string.IsNullOrEmpty(nextPageLink))
                {
                    break;
                }
                else
                {
                    secrets = await this.keyVaultClient.GetSecretsNextAsync(nextPageLink).ConfigureAwait(false);
                    nextPageLink = secrets.NextPageLink;
                }
            };

            return results;
        }

        public async Task<List<CertificateItem>> GetAllCertificates()
        {
            List<CertificateItem> results = new List<CertificateItem>();

            IPage<CertificateItem> certificates = await this.keyVaultClient.GetCertificatesAsync(this.keyvaultUrl).ConfigureAwait(false);

            string nextPageLink = certificates.NextPageLink;
            while (true)
            {
                results.AddRange(certificates);

                if (string.IsNullOrEmpty(nextPageLink))
                {
                    break;
                }
                else
                {
                    certificates = await this.keyVaultClient.GetCertificatesNextAsync(nextPageLink).ConfigureAwait(false);
                    nextPageLink = certificates.NextPageLink;
                }
            };

            return results;
        }

        /// <summary>
        /// Releases unmanaged and - optionally - managed resources.
        /// </summary>
        /// <param name="disposing"><c>true</c> to release both managed and unmanaged resources; <c>false</c> to release only unmanaged resources.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (this.disposed)
            {
                return;
            }

            if (disposing)
            {
                //// Free any other managed objects here
                this.keyVaultClient.Dispose();
            }

            //// free any unmanaged objects here

            this.disposed = true;
        }

        private static async Task<string> GetAccessTokenWithCert(string authority, string resource, string scope, ClientAssertionCertificate assertionCert)
        {
            AuthenticationContext context = new AuthenticationContext(authority, TokenCache.DefaultShared);
            AuthenticationResult result = await context.AcquireTokenAsync(resource, assertionCert).ConfigureAwait(false);
            return result.AccessToken;
        }

        private static async Task<string> GetAccessTokenWithSecret(string authority, string resource, string scope, string clientId, string secret)
        {
            AuthenticationContext context = new AuthenticationContext(authority, TokenCache.DefaultShared);
            AuthenticationResult result = await context.AcquireTokenAsync(resource, new ClientCredential(clientId, secret)).ConfigureAwait(false);
            return result.AccessToken;
        }

        private KeyVaultClient InitWithSecret(string valutaddr, string authClientId, string secret)
        {
            KeyVaultClient client = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(
                (authority, resource, scope)
                    => GetAccessTokenWithSecret(authority, resource, scope, authClientId, secret)));

            return client;
        }

        private KeyVaultClient InitWithCert(string vaultaddr, string authClientId, string authThumbprint)
        {
            X509Certificate2 cert = this.FindCertificateByThumbprint(authThumbprint);

            if (cert == null)
            {
                throw new ArgumentException(string.Format("Cannot find Certificate by thumbprint \"{0}\" to Access KeyVault \"{1}\"", authThumbprint, vaultaddr));
            }

            ClientAssertionCertificate assertionCert = new ClientAssertionCertificate(authClientId, cert);

            KeyVaultClient client = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(
                                       (authority, resource, scope)
                                           => GetAccessTokenWithCert(authority, resource, scope, assertionCert)));
            return client;
        }

        private X509Certificate2 FindCertificateByThumbprint(string thumbprint)
        {
            if (string.IsNullOrEmpty(thumbprint))
            {
                throw new ArgumentNullException("Certificate Thumbprint for Accessing KeyVault should not be null");
            }

            return CertUtils.GetCertificateByThumbprint(thumbprint, StoreName.My, StoreLocation.LocalMachine);
        }

        private void Init(string keyvaultUrl, string aadClientId, string aadAccessCertThumbprint, bool useSecret, Func<string> secretRetriever)
        {
            this.keyvaultUrl = keyvaultUrl;

            if (useSecret)
            {
                this.keyVaultClient = this.InitWithSecret(
                                            this.keyvaultUrl,
                                            aadClientId,
                                            secretRetriever());
            }
            else
            {
                this.keyVaultClient = this.InitWithCert(
                                            this.keyvaultUrl,
                                            aadClientId,
                                            aadAccessCertThumbprint);
            }
        }
    }

    /// <summary>
    /// Common class for certificate usage
    /// </summary>
    public static class CertUtils
    {
        /// <summary>
        /// Gets the certificate by thumbprint.
        /// </summary>
        /// <param name="thumbprint">The thumbprint.</param>
        /// <param name="allowNotFound">if set to <c>true</c> [allow not found].</param>
        /// <returns>X509Certificate2 instance</returns>
        /// <exception cref="X509CertificateNotFoundException">Certificate not found</exception>
        public static X509Certificate2 GetCertificateByThumbprint(string thumbprint, bool allowNotFound = false)
        {
            X509Certificate2 certificate;
            foreach (var name in new[] { StoreName.My, StoreName.Root })
            {
                foreach (var location in new[] { StoreLocation.CurrentUser, StoreLocation.LocalMachine })
                {
                    certificate = GetCertificateByThumbprint(thumbprint, name, location, true);
                    if (certificate != null)
                    {
                        return certificate;
                    }
                }
            }

            if (allowNotFound)
            {
                return null;
            }
            else
            {
                throw new X509CertificateNotFoundException(thumbprint);
            }
        }

        /// <summary>
        /// Gets the certificate by thumbprint.
        /// </summary>
        /// <param name="thumbprint">The thumbprint.</param>
        /// <param name="name">The name.</param>
        /// <param name="location">The location.</param>
        /// <param name="allowNotFound">if set to <c>true</c> [allow not found].</param>
        /// <returns>The X509Certificate2</returns>
        /// <exception cref="X509CertificateNotFoundException">Certificate not found</exception>
        public static X509Certificate2 GetCertificateByThumbprint(string thumbprint, StoreName name, StoreLocation location, bool allowNotFound = false)
        {
            var certStore = new X509Store(name, location);
            try
            {
                certStore.Open(OpenFlags.ReadOnly);
                var certCllection = certStore.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);

                if (certCllection.Count > 0)
                {
                    return certCllection[0];
                }

                if (allowNotFound)
                {
                    return null;
                }
                else
                {
                    throw new X509CertificateNotFoundException(thumbprint);
                }
            }
            finally
            {
                certStore.Close();
            }
        }
    }

    public class X509CertificateNotFoundException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="X509CertificateNotFoundException"/> class.
        /// </summary>
        /// <param name="thumbprint">The thumbprint.</param>
        public X509CertificateNotFoundException(string thumbprint)
            : base(string.Format("Cannot find specified X509certificate with thumbprint \"{0}\"! Please verify if the certificate is installed.", thumbprint))
        {
        }
    }
}
