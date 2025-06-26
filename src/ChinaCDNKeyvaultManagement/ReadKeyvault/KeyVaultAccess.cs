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

namespace Mooncake.Cdn.CredentialManagementTool
{
    public class SecretInfo
    {
        public string Id { get; set; }

        public string Name { get; set; }

        public string Version { get; set; }

        public string Value { get; set; }

        public bool? Enabled { get; set; }

        public IDictionary<string, string> Tags { get; set; }

        public string ContentType { get; set; }

        public DateTime? NotBefore { get; set; }

        public DateTime? Expires { get; set; }

        public override string ToString()
        {
            return $"Name: {Name}, Version: {Version}, ContentType: {ContentType}, NotBefore: {NotBefore}, Expires: {Expires}, Enabled: {Enabled}, Tags: {string.Join(";", Tags.Select(x => $"{x.Key}:{x.Value}"))}";
        }

        public string ToStringWithSecretValue()
        {
            return $"Name: {Name}, Version: {Version}, Value: {Value}, ContentType: {ContentType}, NotBefore: {NotBefore}, Expires: {Expires}, Enabled: {Enabled}, Tags: {string.Join(";", Tags.Select(x => $"{x.Key}:{x.Value}"))}";
        }
    }
    public class CertificateInfo : SecretInfo
    {
        public string Thumbprint { get; set; }

        public X509Certificate2 Certificate { get; set; }

        public override string ToString()
        {
            return $"Name: {Name}, Version: {Version}, Thumbprint: {Thumbprint}, ContentType: {ContentType}, NotBefore: {NotBefore}, Expires: {Expires}, Enabled: {Enabled}, Tags: {string.Join(";", Tags.Select(x => $"{x.Key}:{x.Value}"))}";
        }
    }

    public static class CredentialUtilities
    {
        public static bool IsCertificate(this SecretInfo secret, bool pemAsCert = false)
        {
            if (secret == null)
            {
                return false;
            }

            if (secret.ContentType == CertificateContentType.Pfx)
            {
                return true;
            }

            return pemAsCert ? secret.ContentType == CertificateContentType.Pem : false;
        }

        public static SecretInfo ToSecretInfo(this SecretBundle secret)
        {
            if (secret == null)
            {
                return null;
            }

            SecretInfo info = new SecretInfo
            {
                Id = secret.Id,
                ContentType = secret.ContentType,
                Name = secret.SecretIdentifier.Name,
                Enabled = secret.Attributes.Enabled,
                Expires = secret.Attributes.Expires,
                NotBefore = secret.Attributes.NotBefore,
                Value = secret.Value,
                Version = secret.SecretIdentifier.Version,
                Tags = secret.Tags != null ? new Dictionary<string, string>(secret.Tags) : new Dictionary<string, string>(),
            };

            return info;
        }

        public static SecretInfo ToSecretInfo(this SecretItem secret)
        {
            if (secret == null)
            {
                return null;
            }

            SecretInfo info = new SecretInfo
            {
                Id = secret.Id,
                ContentType = secret.ContentType,
                Name = secret.Identifier.Name,
                Enabled = secret.Attributes.Enabled,
                Expires = secret.Attributes.Expires,
                NotBefore = secret.Attributes.NotBefore,
                Version = secret.Identifier.Version,
                Value = null,
                Tags = secret.Tags != null ? new Dictionary<string, string>(secret.Tags) : new Dictionary<string, string>(),
            };

            return info;
        }

        public static CertificateInfo ToCertificateInfo(this SecretBundle secret)
        {
            if (secret == null)
            {
                return null;
            }

            X509Certificate2 x509cert = new X509Certificate2(Convert.FromBase64String(secret.Value));
            CertificateInfo info = new CertificateInfo
            {
                Id = secret.Id,
                ContentType = secret.ContentType,
                Name = secret.SecretIdentifier.Name,
                Version = secret.SecretIdentifier.Version,
                Enabled = secret.Attributes.Enabled,
                Expires = secret.Attributes.Expires,
                NotBefore = secret.Attributes.NotBefore,
                Value = secret.Value,
                Certificate = x509cert,
                Thumbprint = x509cert.Thumbprint,
                Tags = secret.Tags != null ? new Dictionary<string, string>(secret.Tags) : new Dictionary<string, string>(),
            };

            return info;
        }

        public static CertificateInfo ToCertificateInfo(this SecretInfo secret)
        {
            if (secret == null)
            {
                return null;
            }

            X509Certificate2 x509cert = new X509Certificate2(Convert.FromBase64String(secret.Value));
            CertificateInfo info = new CertificateInfo
            {
                Id = secret.Id,
                ContentType = secret.ContentType,
                Name = secret.Name,
                Version = secret.Version,
                Enabled = secret.Enabled,
                Expires = secret.Expires,
                NotBefore = secret.NotBefore,
                Value = secret.Value,
                Certificate = x509cert,
                Thumbprint = x509cert.Thumbprint,
                Tags = secret.Tags != null ? new Dictionary<string, string>(secret.Tags) : new Dictionary<string, string>(),
            };

            return info;
        }

        public static CertificateInfo ToCertificateInfo(this CertificateBundle cert)
        {
            if (cert == null)
            {
                return null;
            }

            return new CertificateInfo
            {
                Id = cert.Id,
                Name = cert.KeyIdentifier.Name,
                Version = cert.SecretIdentifier.Version,
                Enabled = cert.Attributes.Enabled,
                Certificate = new X509Certificate2(cert.Cer),
                ContentType = cert.ContentType,
                Value = Convert.ToBase64String(cert.Cer),
                Expires = cert.Attributes.Expires,
                NotBefore = cert.Attributes.NotBefore,
                Thumbprint = BitConverter.ToString(cert.X509Thumbprint).Replace("-", ""),
                Tags = cert.Tags == null ? new Dictionary<string, string>() : new Dictionary<string, string>(cert.Tags),
            };
        }

        public static CertificateInfo ToCertificateInfo(this CertificateItem cert)
        {
            if (cert == null)
            {
                return null;
            }

            return new CertificateInfo
            {
                Id = cert.Id,
                Name = cert.Identifier.Name,
                Version = cert.Identifier.Version,
                Enabled = cert.Attributes.Enabled,
                Certificate = null,
                //ContentType = ,
                Expires = cert.Attributes.Expires,
                NotBefore = cert.Attributes.NotBefore,
                Thumbprint = BitConverter.ToString(cert.X509Thumbprint).Replace("-", ""),
                Tags = cert.Tags == null ? new Dictionary<string, string>() : new Dictionary<string, string>(cert.Tags),
            };
        }
    }

    public class KeyVaultAccess : IDisposable
    {
        private KeyVaultClient keyVaultClient = null;
        private bool disposed = false;

        private string keyvaultUrl;

        public KeyVaultAccess(
        string keyvaultUrl,
        string clientId,
        AADAuthType authType,
        string certThumbprintOrName,
        Func<string> secret)
        {
            this.Init(keyvaultUrl, clientId, authType, certThumbprintOrName, secret);
        }

        public KeyVaultAccess(
            string keyvaultUrl,
            AADSettingInfo aadInfo)
        {
            this.Init(keyvaultUrl, aadInfo.ClientId, aadInfo.AuthType, aadInfo.CertificateThumbprintOrName, aadInfo.SecretRetriever);
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

        public async Task<SecretInfo> GetSecretItemAsync(string name, string version)
        {
            try
            {
                var bundle = string.IsNullOrEmpty(version) ?
                    await this.keyVaultClient.GetSecretAsync(this.keyvaultUrl, name).ConfigureAwait(false) :
                    await this.keyVaultClient.GetSecretAsync(this.keyvaultUrl, name, version).ConfigureAwait(false);

                var info = bundle.ToSecretInfo();
                return info;
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

        public async Task<List<SecretInfo>> GetSecretItemWithAllVersionsAsync(string name)
        {
            try
            {
                var secrets = await this.keyVaultClient.GetSecretVersionsAsync(this.keyvaultUrl, name).ConfigureAwait(false);

                List<SecretInfo> results = new List<SecretInfo>();
                foreach (var secret in secrets)
                {
                    var bundle = await this.keyVaultClient.GetSecretAsync(this.keyvaultUrl, name, secret.Identifier.Version)
                                     .ConfigureAwait(false);

                    var info = bundle.ToSecretInfo();
                    results.Add(info);
                }

                return results.OrderByDescending(x => x.Expires).ToList();
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
                    return new List<SecretInfo>();
                }

                throw;
            }
        }

        /// <summary>
        /// Reads the secret.
        /// </summary>
        /// <param name="name">The name.</param>
        /// <returns>
        /// Secret value
        /// </returns>
        public async Task<string> GetSecretAsync(string name, string version)
        {
            var item = await GetSecretItemAsync(name, version).ConfigureAwait(false);
            return item.Value;
        }

        internal async Task DeleteAllSecretsAsync(Predicate<SecretInfo> isMathced)
        {
            List<SecretInfo> allSecrets = await this.GetAllSecretsAsync(includeCertificates: false, showSecretValue: false).ConfigureAwait(false);
            List<SecretInfo> secrets = allSecrets.Where(x => isMathced(x)).ToList();

            Console.WriteLine("Total Secrets: {0}", allSecrets.Count);
            Console.WriteLine("Secrets to be deleted: {0}", secrets.Count);

            foreach (var secret in secrets)
            {
                Console.WriteLine("Deleting Secret {0} in key vault...", secret.Id);
                await this.keyVaultClient.DeleteSecretAsync(this.keyvaultUrl, secret.Name).ConfigureAwait(false);
            }
        }

        internal async Task DisableAllCertificatesAsync(Predicate<CertificateInfo> isMatched)
        {
            List<CertificateInfo> allCertificates = await this.GetAllCertificatesAsync().ConfigureAwait(false);
            List<CertificateInfo> certificates = allCertificates.Where(x => isMatched(x)).ToList();

            Console.WriteLine("Total Certificates: {0}", allCertificates.Count);
            Console.WriteLine("Certificates to be disabled: {0}", certificates.Count);

            foreach (var cert in certificates)
            {
                Console.WriteLine("Disabling Certificate {0} in key vault...", cert.Name);
               // await this.keyVaultClient.DeleteCertificateAsync(this.keyvaultUrl, cert.Identifier.Name).ConfigureAwait(false);
            }
        }

        internal async Task DeleteCertificateAsync(string certName)
        {
            Console.Write("Deleting certificate {0} ...", certName);
            await this.keyVaultClient.DeleteCertificateAsync(this.keyvaultUrl, certName).ConfigureAwait(false);
            Console.WriteLine("Completed");
        }

        internal async Task UpdateSecretExpirationDateAsync(string secretName, string secretVersion, DateTimeOffset expireDate)
        {
            Console.Write($"Updating secret {secretName} expire date {expireDate} with version '{secretVersion}'...");
            var secret = string.IsNullOrWhiteSpace(secretVersion) ?
                                await this.keyVaultClient.GetSecretAsync(this.keyvaultUrl, secretName).ConfigureAwait(false) :
                                await this.keyVaultClient.GetSecretAsync(this.keyvaultUrl, secretName, secretVersion).ConfigureAwait(false);
            SecretAttributes attr = new SecretAttributes()
            {
                Expires = expireDate.UtcDateTime,
            };

            await this.keyVaultClient.UpdateSecretAsync(secret.Id, null, attr).ConfigureAwait(false);
            Console.WriteLine("Completed");
        }

        internal async Task DeleteSecretAsync(string secretName)
        {
            Console.Write("Deleting secret {0} ...", secretName);
            await this.keyVaultClient.DeleteSecretAsync(this.keyvaultUrl, secretName).ConfigureAwait(false);
            Console.WriteLine("Completed");
        }

        internal async Task DeleteAllCertificatesAsync(Predicate<CertificateInfo> isMathced)
        {
            List<CertificateInfo> allCertificates = await this.GetAllCertificatesAsync().ConfigureAwait(false);
            List<CertificateInfo> certificates = allCertificates.Where(x => isMathced(x)).ToList();

            Console.WriteLine("Total Certificates: {0}", allCertificates.Count);
            Console.WriteLine("Certificates to be deleted: {0}", certificates.Count);

            foreach (var cert in certificates)
            {
                Console.WriteLine("Deleting Certificate {0} in key vault...", cert.Id);
                Console.WriteLine("Press any key to continue...");
                Console.ReadLine();
                await this.keyVaultClient.DeleteCertificateAsync(this.keyvaultUrl, cert.Name).ConfigureAwait(false);
            }
        }

        public async Task ImportSecretsAndCertsAsync(List<SecretInfo> secretsAndCerts, bool overwriteExisting = false, bool pemAsCert = false)
        {
            foreach (var info in secretsAndCerts)
            {
                bool isCertificate = pemAsCert ? info.ContentType == CertificateContentType.Pem : false;

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
                                Console.WriteLine($"Importing Secret {info.Name} with new value '{info.Value}' to keyvault {this.keyvaultUrl}");
                                SecretAttributes attribute = new SecretAttributes(true, info.NotBefore, info.Expires);
                                await this.keyVaultClient.SetSecretAsync(this.keyvaultUrl, info.Name, info.Value, info.Tags, info.ContentType, attribute).ConfigureAwait(false);
                            }
                            else
                            {
                                Console.WriteLine($"Same secret value for secret {info.Name}, skip import");
                            }
                        }
                        else
                        {
                            Console.WriteLine($"Skip import, please use '--force' to force sync new secret value for secret {info.Name}");
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
                            Console.WriteLine($"Importing Certificate {info.Name} to keyvault {this.keyvaultUrl}");
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
                            Console.WriteLine($"Importing Secret {info.Name} to keyvault {this.keyvaultUrl}");
                            SecretAttributes attribute = new SecretAttributes(true, info.NotBefore, info.Expires);
                            await this.keyVaultClient.SetSecretAsync(this.keyvaultUrl, info.Name, info.Value, info.Tags, info.ContentType, attribute).ConfigureAwait(false);
                        }
                    }
                }
            }
        }

        public async Task<CertificateInfo> GetExistingCertificateAsync(string certName, string version)
        {
            try
            {
                var cert = string.IsNullOrEmpty(version) ?
                    await this.keyVaultClient.GetCertificateAsync(this.keyvaultUrl, certName).ConfigureAwait(false) :
                    await this.keyVaultClient.GetCertificateAsync(this.keyvaultUrl, certName, version).ConfigureAwait(false);
                if (cert != null)
                {
                    return string.IsNullOrEmpty(version) ?
                    (await this.keyVaultClient.GetSecretAsync(this.keyvaultUrl, certName).ConfigureAwait(false)).ToCertificateInfo() :
                    (await this.keyVaultClient.GetSecretAsync(this.keyvaultUrl, certName, version).ConfigureAwait(false)).ToCertificateInfo();
                }

                return null;
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

        public async Task<List<CertificateInfo>> GetExistingCertificateWithAllVersionsAsync(string certName)
        {
            try
            {
                var certVersions = await this.keyVaultClient.GetCertificateVersionsAsync(this.keyvaultUrl, certName).ConfigureAwait(false);

                List<CertificateInfo> certs = new List<CertificateInfo>();
                foreach (var certVersion in certVersions)
                {

                    string secretVersion = certVersion.Identifier.Version;
                    var cert = (await this.keyVaultClient.GetSecretAsync(this.keyvaultUrl, certName, secretVersion).ConfigureAwait(false)).ToCertificateInfo();
                    certs.Add(cert);
                }

                return certs.OrderByDescending(x => x.Expires).ToList();
            }
            catch (KeyVaultErrorException ex)
            {
                if (ex.Response != null &&
                    ex.Response.StatusCode == System.Net.HttpStatusCode.NotFound)
                {
                    return new List<CertificateInfo>();
                }
                else
                {
                    throw;
                }
            }
        }

        public async Task WriteSecretAsync(string name, string value, DateTimeOffset expiredDate, bool overwriteExisting)
        {
            try
            {
                var secret = await this.keyVaultClient.GetSecretAsync(this.keyvaultUrl, name).ConfigureAwait(false);
                Console.WriteLine($"[====Warning===] Secret {name} already in keyvault {this.keyvaultUrl}");

                if(overwriteExisting)
                {
                    Console.WriteLine($"Importing Secret {name} to keyvault {this.keyvaultUrl}, expired date {expiredDate}");
                    SecretAttributes attributes = new SecretAttributes(true, null, expiredDate.UtcDateTime);
                    await this.keyVaultClient.SetSecretAsync(this.keyvaultUrl, name, value, null, null, attributes).ConfigureAwait(false);
                }
            }
            catch (KeyVaultErrorException ex)
            {
                if (ex.Response != null &&
                    ex.Response.StatusCode == System.Net.HttpStatusCode.NotFound)
                {
                    Console.WriteLine($"Importing Secret {name} to keyvault {this.keyvaultUrl}");
                    SecretAttributes attributes = new SecretAttributes(true, null, expiredDate.UtcDateTime);
                    await this.keyVaultClient.SetSecretAsync(this.keyvaultUrl, name, value, null, null, attributes).ConfigureAwait(false);
                }
            }
        }

        public async Task<CertificatePolicy> GetCertificatePolicyAsync(string certificateName)
        {
            CertificatePolicy policy = await this.keyVaultClient.GetCertificatePolicyAsync(this.keyvaultUrl, certificateName).ConfigureAwait(false);
            return policy;
        }

        public async Task ImportCertificateAsync(CertificateInfo cert, bool overwriteExisting = false)
        {
            var existingCert = (await this.GetSecretItemAsync(cert.Name, null).ConfigureAwait(false)).ToCertificateInfo();
            bool doImport = false;

            if (existingCert != null)
            {
                Console.WriteLine($"[====Warning===] Certificate {cert.Name}: Overwrite Existing: {overwriteExisting}.\n\tExisting: {existingCert.Thumbprint}\n\tNew:      {cert.Thumbprint}");
                doImport = overwriteExisting && existingCert.Thumbprint != cert.Thumbprint;
            }
            else
            {
                doImport = true;
            }

            if (doImport)
            {
                Console.WriteLine($"Importing Certificate {cert.Name} {cert.Thumbprint} to keyvault {this.keyvaultUrl}");
                await this.keyVaultClient.ImportCertificateAsync(this.keyvaultUrl, cert.Name, cert.Value).ConfigureAwait(false);
            }
            else
            {
                Console.WriteLine($"Skip import, please use '--force' to force sync new certificate {cert.Name}");
            }
        }

        public async Task ImportCertificatesAsync(List<CertificateInfo> certificates, bool overwriteExisting = false)
        {
            foreach (var cert in certificates)
            {
                CertificateInfo existingCert = await this.GetExistingCertificateAsync(cert.Name, null).ConfigureAwait(false);
                bool doImport = false;

                if (existingCert != null)
                {
                    Console.WriteLine($"[====Warning===] Certificate {cert.Name}: Overwrite Existing: {overwriteExisting}.\n\tExisting: {existingCert.Thumbprint}\n\tNew:      {cert.Thumbprint}");
                    doImport = overwriteExisting && existingCert.Thumbprint != cert.Thumbprint;
                }
                else
                {
                    doImport = true;
                }

                if (doImport)
                {
                    Console.WriteLine($"Importing Certificate {cert.Name} {cert.Thumbprint} to keyvault");
                    await this.keyVaultClient.ImportCertificateAsync(this.keyvaultUrl, cert.Name, cert.Value).ConfigureAwait(false);
                }
            }
        }

        public async Task<IEnumerable<Tuple<string, string, string>>> DownloadCertificatesAsync(Predicate<CertificateInfo> isMatch)
        {
            //List<Tuple<string, X509Certificate2>> results = new List<Tuple<string, X509Certificate2>>();
            List<Tuple<string, string, string>> results = new List<Tuple<string, string, string>>();

            List<CertificateInfo> allCertificates = await this.GetAllCertificatesAsync().ConfigureAwait(false);
            List<CertificateInfo> certificates = allCertificates.Where(x => isMatch(x)).ToList();

            Console.WriteLine("Total Certificates: {0}", allCertificates.Count);
            Console.WriteLine("Certificates to be downloaded: {0}", certificates.Count);

            foreach (var certificate in certificates)
            {
                var secretBundle = await this.keyVaultClient.GetSecretAsync(this.keyvaultUrl, certificate.Name).ConfigureAwait(false);

                //string thumbprint = Convert.ToBase64String(certificate.X509Thumbprint);
                byte[] raw =  Convert.FromBase64String(secretBundle.Value);
                X509Certificate2 cert = new X509Certificate2(raw);
                string thumbprint = cert.Thumbprint;

                results.Add(new Tuple<string, string, string>(certificate.Name, thumbprint, secretBundle.Value));
            }

            return results;
        }

        public async Task<IEnumerable<SecretInfo>> DownloadSecretsAndCertsAsync(Predicate<SecretInfo> isMatch)
        {
            //List<Tuple<string, X509Certificate2>> results = new List<Tuple<string, X509Certificate2>>();
            List<SecretInfo> results = new List<SecretInfo>();

            List<SecretInfo> allSecrets = await this.GetAllSecretsAsync(includeCertificates: true, showSecretValue: true).ConfigureAwait(false);
            List<SecretInfo> secrets = allSecrets.Where(x => isMatch(x)).ToList();

            Console.WriteLine("Total Secrets: {0}", allSecrets.Count);
            Console.WriteLine("Secrets to be downloaded: {0}", secrets.Count);

            foreach (var secret in secrets)
            {
                var secretBundle = await this.keyVaultClient.GetSecretAsync(this.keyvaultUrl, secret.Name).ConfigureAwait(false);
                SecretInfo info = secretBundle.ToSecretInfo();
                results.Add(info);
            }

            return results;
        }

        public async Task<List<SecretInfo>> GetAllSecretsAsync(bool includeCertificates, bool showSecretValue)
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

            var allSecrets = results.Select(x => x.ToSecretInfo()).ToList();
            if (!includeCertificates)
            {
                allSecrets = allSecrets.Where(x => !x.IsCertificate()).ToList();
            }

            if (showSecretValue)
            {
                List<SecretInfo> allSecretsWithValues = new List<SecretInfo>();
                foreach (var secret in allSecrets)
                {
                    var item = await this.GetSecretItemAsync(secret.Name, null).ConfigureAwait(false);
                    allSecretsWithValues.Add(item);
                }

                allSecrets = allSecretsWithValues;
            }

            return allSecrets;
        }

        public async Task<List<CertificateInfo>> GetAllCertificatesAsync()
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

            return results.Select(x => x.ToCertificateInfo()).ToList();
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

        private static async Task<string> GetAccessTokenWithCertAsync(string authority, string resource, string scope, ClientAssertionCertificate assertionCert)
        {
            AuthenticationContext context = new AuthenticationContext(authority, TokenCache.DefaultShared);
            AuthenticationResult result = await context.AcquireTokenAsync(resource, assertionCert).ConfigureAwait(false);
            return result.AccessToken;
        }

        private static async Task<string> GetAccessTokenWithSecretAsync(string authority, string resource, string scope, string clientId, string secret)
        {
            AuthenticationContext context = new AuthenticationContext(authority, TokenCache.DefaultShared);
            AuthenticationResult result = await context.AcquireTokenAsync(resource, new ClientCredential(clientId, secret)).ConfigureAwait(false);
            return result.AccessToken;
        }

        private KeyVaultClient InitWithSecret(string valutaddr, string authClientId, string secret)
        {
            KeyVaultClient client = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(
                (authority, resource, scope)
                    => GetAccessTokenWithSecretAsync(authority, resource, scope, authClientId, secret)));

            return client;
        }

        private KeyVaultClient InitWithCertThrumbprint(string vaultaddr, string authClientId, string authThumbprint)
        {
            X509Certificate2 cert = this.FindCertificateByThumbprint(authThumbprint);

            if (cert == null)
            {
                throw new ArgumentException(string.Format("Cannot find Certificate by thumbprint \"{0}\" to Access KeyVault \"{1}\" with AAD app ID {2}", authThumbprint, vaultaddr, authClientId));
            }

            ClientAssertionCertificate assertionCert = new ClientAssertionCertificate(authClientId, cert);

            KeyVaultClient client = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(
                                       (authority, resource, scope)
                                           => GetAccessTokenWithCertAsync(authority, resource, scope, assertionCert)));
            return client;
        }

        private KeyVaultClient InitWithCertName(string vaultaddr, string authClientId, string certName)
        {
            X509Certificate2[] certs = this.FindValidCertificatesByName(certName);

            if (certs == null || certs.Length == 0)
            {
                throw new ArgumentException(string.Format("Cannot find Certificate by certificate name \"{0}\" to Access KeyVault \"{1}\" with AAD App ID {2}", certName, vaultaddr, authClientId));
            }

            foreach (X509Certificate2 cert in certs)
            {
                ClientAssertionCertificate assertionCert = new ClientAssertionCertificate(authClientId, cert);

                KeyVaultClient client = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(
                                           (authority, resource, scope)
                                               => GetAccessTokenWithCertAsync(authority, resource, scope, assertionCert)));
                return client;
            }

            return null;
        }

        private X509Certificate2[] FindValidCertificatesByName(string certName)
        {
            if (string.IsNullOrEmpty(certName))
            {
                throw new ArgumentNullException("Certificate Name for Accessing KeyVault should not be null");
            }

            return CertUtils.GetValidCertificatesByName(certName, StoreName.My, StoreLocation.LocalMachine);
        }

        private X509Certificate2 FindCertificateByThumbprint(string thumbprint)
        {
            if (string.IsNullOrEmpty(thumbprint))
            {
                throw new ArgumentNullException("Certificate Thumbprint for Accessing KeyVault should not be null");
            }

            return CertUtils.GetCertificateByThumbprint(thumbprint, StoreName.My, StoreLocation.LocalMachine);
        }

        private void Init(string keyvaultUrl, string aadClientId, AADAuthType authType, string aadAccessCertThumbprintOrName, Func<string> secretRetriever)
        {
            this.keyvaultUrl = keyvaultUrl;

            if (authType == AADAuthType.Secret && secretRetriever != null)
            {
                this.keyVaultClient = this.InitWithSecret(
                                            this.keyvaultUrl,
                                            aadClientId,
                                            secretRetriever());
            }
            else if (authType == AADAuthType.CertificateThumbprint && !string.IsNullOrEmpty(aadAccessCertThumbprintOrName))
            {
                this.keyVaultClient = this.InitWithCertThrumbprint(
                                            this.keyvaultUrl,
                                            aadClientId,
                                            aadAccessCertThumbprintOrName);
            }
            else if (authType == AADAuthType.SNICertificate && !string.IsNullOrEmpty(aadAccessCertThumbprintOrName))
            {
                this.keyVaultClient = this.InitWithCertName(
                                            this.keyvaultUrl,
                                            aadClientId,
                                            aadAccessCertThumbprintOrName);
            }
            else
            {
                throw new InvalidOperationException($"Missing certificate name, thumbprint or secret retriever to access key vault {this.keyvaultUrl} for AAD {aadClientId}");
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

        public static X509Certificate2[] GetValidCertificatesByName(string certName, StoreName name, StoreLocation location)
        {
            var certStore = new X509Store(name, location);
            try
            {
                certStore.Open(OpenFlags.ReadOnly);
                var certCollection = certStore.Certificates.Find(X509FindType.FindBySubjectName, certName, false);
                List<X509Certificate2> certList = new List<X509Certificate2>(certCollection.Cast<X509Certificate2>());
                return certList.ToArray();
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
