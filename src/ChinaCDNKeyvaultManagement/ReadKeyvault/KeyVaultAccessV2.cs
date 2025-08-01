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
    public class KeyVaultAccessV2 : IDisposable
    {
        private SecretClient secretClient;
        private CertificateClient certificateClient;
        private string keyvaultUrl;
        private bool disposed = false;

        public KeyVaultAccessV2(KeyVaultSettingInfo settingInfo)
            : this(settingInfo.Url, settingInfo.AADInfo.ClientId, settingInfo.AADInfo.CertificateThumbprintOrName, "common")
        {
        }

        public KeyVaultAccessV2(string keyvaultUrl, string clientId, string sniCertName, string tenantId)
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

        public async Task<CertificateInfo> GetExistingCertificateAsync(string targetName, string credentialVersion)
        {
            try
            {
                KeyVaultSecret secret;
                if (string.IsNullOrEmpty(credentialVersion))
                {
                    secret = await secretClient.GetSecretAsync(targetName).ConfigureAwait(false);
                }
                else
                {
                    secret = await secretClient.GetSecretAsync(targetName, credentialVersion).ConfigureAwait(false);
                }
                // Convert the secret (PFX) to CertificateInfo, which includes the private key
                return secret.ToCertificateInfo();
            }
            catch (Azure.RequestFailedException ex) when (ex.Status == 404)
            {
                return null;
            }
        }

        public async Task<SecretInfo> GetSecretItemAsync(string targetName, string credentialVersion)
        {
            try
            {
                KeyVaultSecret secret;
                if (string.IsNullOrEmpty(credentialVersion))
                {
                    secret = await secretClient.GetSecretAsync(targetName).ConfigureAwait(false);
                }
                else
                {
                    secret = await secretClient.GetSecretAsync(targetName, credentialVersion).ConfigureAwait(false);
                }
                return secret.ToSecretInfo();
            }
            catch (Azure.RequestFailedException ex) when (ex.Status == 404)
            {
                return null;
            }
        }

        private Uri GetKeyVaultAuthorityHost(Uri vaultAddress)
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

        public async Task<List<CertificateInfo>> GetExistingCertificateWithAllVersionsAsync(string targetName)
        {
            var certs = new List<CertificateInfo>();
            await foreach (var certProperties in certificateClient.GetPropertiesOfCertificateVersionsAsync(targetName))
            {
                KeyVaultCertificate cert = await certificateClient.GetCertificateVersionAsync(targetName, certProperties.Version).ConfigureAwait(false);
                certs.Add(cert.ToCertificateInfo());
            }
            return certs;
        }

        public async Task<List<SecretInfo>> GetSecretItemWithAllVersionsAsync(string targetName)
        {
            var secrets = new List<SecretInfo>();
            await foreach (var secretProperties in secretClient.GetPropertiesOfSecretVersionsAsync(targetName))
            {
                KeyVaultSecret secret = await secretClient.GetSecretAsync(secretProperties.Name, secretProperties.Version).ConfigureAwait(false);
                secrets.Add(secret.ToSecretInfo());
            }
            return secrets;
        }

        public async Task WriteSecretAsync(string secretName, string value, DateTimeOffset expiredDate, bool overrideIfExist)
        {
            try
            {
                var secretResponse = await secretClient.GetSecretAsync(secretName).ConfigureAwait(false);
                var secret = secretResponse.Value;
                Console.WriteLine($"[====Warning===] Secret {secretName} already in keyvault {this.keyvaultUrl}");
                if (overrideIfExist)
                {
                    Console.Write($"Importing Secret {secretName} to keyvault {this.keyvaultUrl}, expired date {expiredDate}...");
                    var newSecret = new KeyVaultSecret(secretName, value) { Properties = { ExpiresOn = expiredDate } };
                    await secretClient.SetSecretAsync(newSecret).ConfigureAwait(false);
                    Console.WriteLine("Completed");
                }
                else
                {
                    Console.WriteLine($"Skipping import of Secret {secretName} to keyvault {this.keyvaultUrl} as it already exists.");
                }
            }
            catch (Azure.RequestFailedException ex) when (ex.Status == 404)
            {
                Console.WriteLine($"Importing Secret {secretName} to keyvault {this.keyvaultUrl}");
                var secret = new KeyVaultSecret(secretName, value) { Properties = { ExpiresOn = expiredDate } };
                await secretClient.SetSecretAsync(secret).ConfigureAwait(false);
            }
        }

        public async Task UpdateSecretExpirationDateAsync(string secretName, string secretVersion, DateTimeOffset expireDate)
        {
            Console.Write($"Updating secret {secretName} expire date {expireDate} with version '{secretVersion}'...");

            // Fetch the secret (with or without version)
            KeyVaultSecret secret;
            if (string.IsNullOrEmpty(secretVersion))
            {
                secret = await secretClient.GetSecretAsync(secretName).ConfigureAwait(false);
            }
            else
            {
                secret = await secretClient.GetSecretAsync(secretName, secretVersion).ConfigureAwait(false);
            }

            // Update the expiration date
            secret.Properties.ExpiresOn = expireDate;
            await secretClient.UpdateSecretPropertiesAsync(secret.Properties).ConfigureAwait(false);
            Console.WriteLine("Completed");
        }

        public async Task ImportSecretsAndCertsAsync(List<SecretInfo> secretInfos, bool overwriteExisting)
        {
            foreach (var info in secretInfos)
            {
                bool isCertificate = info is CertificateInfo || (info.ContentType != null && info.ContentType.StartsWith("application/x-pkcs12"));
                try
                {
                    if (isCertificate)
                    {
                        var cert = await certificateClient.GetCertificateAsync(info.Name).ConfigureAwait(false);
                        Console.WriteLine($"[====Warning===] Certificate {info.Name} already in keyvault");
                    }
                    else
                    {
                        var secretResponse = await secretClient.GetSecretAsync(info.Name).ConfigureAwait(false);
                        var secret = secretResponse.Value;
                        Console.WriteLine($"[====Warning===] Secret {info.Name} already in keyvault. Value: {secret.Value}");
                        if (overwriteExisting)
                        {
                            if (secret.Value != info.Value ||
                                info.Expires != secret.Properties.ExpiresOn?.DateTime ||
                                info.NotBefore != secret.Properties.NotBefore?.DateTime)
                            {
                                Console.WriteLine($"Importing Secret {info.Name} with new value '{info.Value}' to keyvault {this.keyvaultUrl}...");
                                var newSecret = new KeyVaultSecret(info.Name, info.Value)
                                {
                                    Properties =
                                    {
                                        ExpiresOn = info.Expires,
                                        NotBefore = info.NotBefore,
                                        ContentType = info.ContentType
                                    }
                                };
                                if (info.Tags != null)
                                {
                                    foreach (var tag in info.Tags)
                                        newSecret.Properties.Tags[tag.Key] = tag.Value;
                                }
                                await secretClient.SetSecretAsync(newSecret).ConfigureAwait(false);
                                Console.WriteLine("Completed");
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
                catch (Azure.RequestFailedException ex) when (ex.Status == 404)
                {
                    if (isCertificate)
                    {
                        Console.WriteLine($"Importing Certificate {info.Name} to keyvault {this.keyvaultUrl}...");
                        try
                        {
                            var importOptions = new ImportCertificateOptions(info.Name, Convert.FromBase64String(info.Value))
                            {
                                Enabled = info.Enabled
                            };
                            if (info.Tags != null)
                            {
                                foreach (var tag in info.Tags)
                                    importOptions.Tags.Add(tag.Key, tag.Value);
                            }
                            await certificateClient.ImportCertificateAsync(importOptions).ConfigureAwait(false);
                            Console.WriteLine("Completed");
                        }
                        catch (Exception newex)
                        {
                            Console.WriteLine($"[================== Skip error certificate {info.Name} for message: {newex.Message} ====================]");
                        }
                    }
                    else
                    {
                        Console.WriteLine($"Importing Secret {info.Name} to keyvault {this.keyvaultUrl}...");
                        var newSecret = new KeyVaultSecret(info.Name, info.Value)
                        {
                            Properties =
                            {
                                ExpiresOn = info.Expires,
                                NotBefore = info.NotBefore,
                                ContentType = info.ContentType
                            }
                        };
                        if (info.Tags != null)
                        {
                            foreach (var tag in info.Tags)
                                newSecret.Properties.Tags[tag.Key] = tag.Value;
                        }
                        await secretClient.SetSecretAsync(newSecret).ConfigureAwait(false);
                        Console.WriteLine("Completed");
                    }
                }
            }
        }

        public async Task ImportCertificateAsync(CertificateInfo cert, bool overwriteExisting)
        {
            var existingCert = await GetExistingCertificateAsync(cert.Name, null).ConfigureAwait(false);
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
                Console.WriteLine($"Importing Certificate {cert.Name} {cert.Thumbprint} to keyvault {this.keyvaultUrl}...");

                // Validate that the PFX contains a private key
                var pfxBytes = Convert.FromBase64String(cert.Value);
                var x509 = new X509Certificate2(pfxBytes, (string)null, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
                if (!x509.HasPrivateKey)
                {
                    throw new InvalidOperationException("The certificate being imported does not contain a private key. Please ensure the PFX includes the private key.");
                }

                var importOptions = new ImportCertificateOptions(cert.Name, pfxBytes)
                {
                    Enabled = cert.Enabled
                };
                if (cert.Tags != null)
                {
                    foreach (var tag in cert.Tags)
                        importOptions.Tags.Add(tag.Key, tag.Value);
                }
                await certificateClient.ImportCertificateAsync(importOptions).ConfigureAwait(false);
                Console.WriteLine("Completed");
            }
            else
            {
                Console.WriteLine($"Skip import, please use '--force' to force sync new certificate {cert.Name}");
            }
        }

        public async Task DeleteCertificateAsync(string certName)
        {
            Console.Write("Deleting certificate {0} ...", certName);
            // Deletes a certificate from the Key Vault
            await certificateClient.StartDeleteCertificateAsync(certName).ConfigureAwait(false);
            Console.WriteLine("Completed");
        }

        public async Task DeleteSecretAsync(string secretName)
        {
            Console.Write("Deleting secret {0} ...", secretName);
            // Deletes a secret from the Key Vault
            await secretClient.StartDeleteSecretAsync(secretName).ConfigureAwait(false);
            Console.WriteLine("Completed");
        }
    }

    public static class CredentialUtilitiesV3
    {
        public static SecretInfo ToSecretInfo(this KeyVaultSecret secret)
        {
            if (secret == null)
            {
                return null;
            }

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

        public static CertificateInfo ToCertificateInfo(this KeyVaultCertificate cert)
        {
            if (cert == null)
            {
                return null;
            }

            var thumbprint = cert.Properties.X509Thumbprint != null
                ? BitConverter.ToString(cert.Properties.X509Thumbprint).Replace("-", string.Empty)
                : string.Empty;
            var base64Value = cert.Cer != null ? Convert.ToBase64String(cert.Cer) : string.Empty;
            var x509Cert = cert.Cer != null ? new X509Certificate2(cert.Cer) : null;

            var certInfo = new CertificateInfo
            {
                Name = cert.Name,
                Version = cert.Properties.Version,
                Id = cert.Id.ToString(),
                Enabled = cert.Properties.Enabled,
                Expires = cert.Properties.ExpiresOn?.DateTime,
                NotBefore = cert.Properties.NotBefore?.DateTime,
                Tags = cert.Properties.Tags,
                Thumbprint = thumbprint,
                Certificate = x509Cert,
                Value = base64Value
            };

            return certInfo;
        }

        public static CertificateInfo ToCertificateInfo(this KeyVaultCertificateWithPolicy cert)
        {
            CertificateInfo info = (cert as KeyVaultCertificate).ToCertificateInfo();
            var contentType = cert.Policy?.ContentType != null ? cert.Policy.ContentType.ToString() : string.Empty;
            info.ContentType = contentType;
            return info;
        }

        public static CertificateInfo ToCertificateInfo(this KeyVaultSecret secret)
        {
            if (secret == null)
            {
                return null;
            }

            // The secret value is a base64-encoded PFX/PKCS#12 containing the private key
            X509Certificate2 x509cert = null;
            string thumbprint = string.Empty;
            try
            {
                var raw = Convert.FromBase64String(secret.Value);
                x509cert = new X509Certificate2(raw, (string)null, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
                thumbprint = x509cert.Thumbprint;
            }
            catch
            {
                // If not a valid PFX, leave x509cert and thumbprint as null/empty
            }

            return new CertificateInfo
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
                Certificate = x509cert,
                Thumbprint = thumbprint
            };
        }
    }
}
