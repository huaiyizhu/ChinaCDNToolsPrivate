using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using CommandLine;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.Cloud.MooncakeService.Common;

namespace ReadKeyvault
{
    public class AADSettingInfo
    {
        public string Name { get; set; }
        public string ClientId { get; set; }
        public string CertificateThumbprint { get; set; }

        public string CertificateName { get; set; }

        public bool UseSecret { get; set; }

        public Func<string> SecretRetriever { get; set; }
    }

    public class KeyVaultSettingInfo
    {
        public string Url { get; set; }
        //public string ClientId { get; set; }
        //public string CertificateThumbprint { get; set; }

        public AADSettingInfo AADInfo { get; set; }

        public override string ToString()
        {
            return this.Url;
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

                CommandLine.Parser.Default.ParseArguments<CommandOptions>(args)
                           .WithParsed(ProcessCommandLines);

                //DeleteCertificatesFromFile(@"D:\Work\CCIC\CDN\DeleteUnusedCertificates\cert-delete-list1.csv");
                //DeleteCertificatesFromFile(@"D:\Work\CCIC\CDN\DeleteUnusedCertificates\cert-delete-list2.txt");
                //DeleteCertificatesFromFile(@"D:\Work\CCIC\CDN\DeleteUnusedCertificates\cert-delete-list3.txt");

                //DeleteSecretsFromFile(@"D:\Work\CCIC\CDN\DeleteUnusedCertificates\secret-delete-list1.txt");
                //DeleteSecretsFromFile(@"D:\Work\CCIC\CDN\DeleteUnusedCertificates\secret-delete-list2.txt");
                //DeleteSecretsFromFile(@"D:\Work\CCIC\CDN\DeleteUnusedCertificates\secret-delete-list3.txt");
                //DeleteSecretsFromFile(@"D:\Work\CCIC\CDN\DeleteUnusedCertificates\secret-delete-list4.txt");

                //UpdateSecretsExpiredDateFromFile(@"D:\Work\CCIC\CDN\DeleteUnusedCertificates\secret-update-expire-date-test-code1.csv");
                //UpdateSecretsExpiredDateFromFile(@"D:\Work\CCIC\CDN\DeleteUnusedCertificates\secret-update-expire-date-list1.csv");
                //UpdateSecretsExpiredDateFromFile(@"D:\Work\CCIC\CDN\DeleteUnusedCertificates\secret-update-expire-date-list2.csv");
                //UpdateSecretsExpiredDateFromFile(@"D:\Work\CCIC\CDN\DeleteUnusedCertificates\secret-update-expire-date-list3.csv");
                //UpdateSecretsExpiredDateFromFile(@"D:\Work\CCIC\CDN\DeleteUnusedCertificates\secret-update-expire-date-list4.csv");
                //UpdateSecretsExpiredDateFromFile(@"D:\Work\CCIC\CDN\DeleteUnusedCertificates\secret-update-expire-date-list5.csv");
                //UpdateSecretsExpiredDateFromFile(@"D:\Work\CCIC\CDN\DeleteUnusedCertificates\secret-update-expire-date-list6.csv");
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
        }

        private static void ProcessCommandLines(CommandOptions command)
        {
            try
            {
                switch (command.Operation)
                {
                    case OperationType.list:
                        ProcessListAction(command);
                        break;
                    case OperationType.sync:
                        ProcessSyncAction(command);
                        break;
                    case OperationType.get:
                        ProcessGetAction(command);
                        break;
                    case OperationType.add:
                        ProcessAddAction(command);
                        break;
                    case OperationType.delete:
                        ProcessDeleteAction(command);
                        break;
                    case OperationType.update:
                        ProcessUpdateAction(command);
                        break;
                    default:
                        throw new ArgumentException($"Unknown operation {command.Operation}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
        }

        private static void ProcessAddAction(CommandOptions command)
        {
            Requires.Argument("name", command.TargetName).NotNullOrEmpty();
            Requires.Argument("value", command.Value).NotNullOrEmpty();
            Requires.Argument("expired", command.ExpiredDate).NotNull();
            Requires.Argument("target", command.Target).PassPredication(x => x == OperationTarget.secret, "only secret type is supported");

            Console.WriteLine($"Begin to add {command.Target} '{command.TargetName}' for source key vault '{command.SrcKeyVault}', value: {command.Value}, expired date {command.ExpiredDate}, overwrite existing: {command.OverrideIfExist}...");

            KeyVaultSettingInfo srcKVInfo = GetPredefinedKeyVaults(command.SrcKeyVault);
            KeyVaultAccess kv = new KeyVaultAccess(srcKVInfo);

            kv.WriteSecret(command.TargetName, command.Value, command.ExpiredDate.Value, command.OverrideIfExist).Wait();

        }

        private static void ProcessUpdateAction(CommandOptions command)
        {
            Requires.Argument("name", command.TargetName).NotNullOrEmpty();
            Requires.Argument("expired", command.ExpiredDate).NotNull();
            Requires.Argument("target", command.Target).PassPredication(x => x == OperationTarget.secret, "only secret type is supported");

            Console.WriteLine($"Begin to update for {command.Target} '{command.TargetName}' from source key vault '{command.SrcKeyVault}', new expired date {command.ExpiredDate}...");

            KeyVaultSettingInfo srcKVInfo = GetPredefinedKeyVaults(command.SrcKeyVault);
            KeyVaultAccess kv = new KeyVaultAccess(srcKVInfo);

            kv.UpdateSecretExpirationDate(command.TargetName, command.ExpiredDate.Value).Wait();
        }

        private static void ProcessDeleteAction(CommandOptions command)
        {
            Requires.Argument("name", command.TargetName).NotNullOrEmpty();

            Console.WriteLine($"Begin to delete {command.Target} '{command.TargetName}' from source key vault '{command.SrcKeyVault}'...");
            Console.WriteLine("Type 'yes' with enter to confim delete action...");

            string confirmYes = Console.ReadLine();
            if (!string.Equals(confirmYes, "yes", StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine("Delete action not performed");
                return;
            }

            Console.WriteLine($"Comfirmed to delete {command.Target} {command.TargetName} from source key vault {command.SrcKeyVault}");

            KeyVaultSettingInfo srcKVInfo = GetPredefinedKeyVaults(command.SrcKeyVault);
            KeyVaultAccess kv = new KeyVaultAccess(srcKVInfo);
            if (command.Target == OperationTarget.certificate)
            {
                kv.DeleteCertificate(command.TargetName).Wait();
            }
            else
            {
                kv.DeleteSecret(command.TargetName).Wait();
            }
        }

        private static void ProcessListAction(CommandOptions command)
        {
            Console.WriteLine($"Begin to list {command.Target} '{command.TargetName}' from source key vault '{command.SrcKeyVault}'...");
            KeyVaultSettingInfo srcKVInfo = GetPredefinedKeyVaults(command.SrcKeyVault);
            KeyVaultAccess kv = new KeyVaultAccess(srcKVInfo);
            if (command.Target == OperationTarget.certificate)
            {
                var certificates = kv.GetAllCertificates().Result;
                Console.WriteLine($"Total certificates: {certificates.Count}");
                foreach (var cert in certificates)
                {
                    Console.WriteLine($"  {cert}");
                }
            }
            else
            {
                var secrets = kv.GetAllSecrets(includeCertificates: false).Result;
                Console.WriteLine($"Total secrets: {secrets.Count}");
                foreach (var secret in secrets)
                {
                    Console.WriteLine($"  {secret}");
                }
            }
        }

        private static void ProcessSyncAction(CommandOptions command)
        {
            Requires.Argument("dstkv", command.DstKeyVault).NotNullOrEmpty();
            Requires.Argument("name", command.TargetName).NotNullOrEmpty();

            Console.WriteLine($"Begin to sync {command.Target} '{command.TargetName}' from source key vault '{command.SrcKeyVault}' to dest key vaule '{command.DstKeyVault}'. Override if exist: {command.OverrideIfExist}");

            KeyVaultSettingInfo srcKVInfo = GetPredefinedKeyVaults(command.SrcKeyVault);
            KeyVaultSettingInfo dstKVInfo = GetPredefinedKeyVaults(command.DstKeyVault);

            if (command.Target == OperationTarget.certificate)
            {
                CopyCertificate(
                    srcKVInfo,
                    dstKVInfo,
                    command.TargetName,
                    command.OverrideIfExist).Wait();
            }
            else
            {
                CopySecretAsync(
                    srcKVInfo,
                    dstKVInfo,
                    command.TargetName,
                    command.OverrideIfExist).Wait();
            }
        }

        private static void ProcessGetAction(CommandOptions command)
        {
            Requires.Argument("name", command.TargetName).NotNullOrEmpty();

            Console.WriteLine($"Begin to find {command.Target} '{command.TargetName}' under key vault '{command.SrcKeyVault}'");
            KeyVaultSettingInfo srcKV = GetPredefinedKeyVaults(command.SrcKeyVault);
            KeyVaultAccess kv = new KeyVaultAccess(srcKV);
            if (command.Target == OperationTarget.certificate)
            {
                var cert = kv.GetExistingCertificate(command.TargetName).Result;
                if (cert == null)
                {
                    Console.WriteLine($"Cannot find certificate '{command.TargetName}' under key vault '{command.SrcKeyVault}'");
                }
                else
                {
                    Console.WriteLine($"Certificate is {cert}");
                }
            }
            else
            {
                var secret = kv.GetSecretItem(command.TargetName);
                if (secret == null)
                {
                    Console.WriteLine($"Cannot find secret '{command.TargetName}' under key vault '{command.SrcKeyVault}'");
                }
                else
                {
                    Console.WriteLine($"Secret is {secret}");
                }
            }
        }

        private static void UpdateSecretsExpiredDateFromFile(string file)
        {
            string[] lines = File.ReadAllLines(file);
            var secretToUpdate = lines.Select(x =>
            {
                var items = x.Split(new char[] { '\t' }, StringSplitOptions.RemoveEmptyEntries);
                string item = items[0].Trim();
                string date = items[1].Trim();
                DateTime expiredDate = DateTime.Parse(date);
                return new
                {
                    ItemName = item.Substring(item.LastIndexOf('/') + 1),
                    KeyVaultPath = item,
                    KeyVault = item.Substring("https://".Length, item.IndexOf(".vault.azure.cn/") - "https://".Length),
                    ExpiredDate = expiredDate,
                };
            }).ToList();

            var groupedByKeyVault = secretToUpdate.GroupBy(x => x.KeyVault).ToList();

            foreach (var keyvault in groupedByKeyVault)
            {
                Console.WriteLine("[Begin] Updating secrets' expiration date in keyvault {0}, total secrets {1}...", keyvault.Key, keyvault.Count());
                KeyVaultSettingInfo kvInfo = GetPredefinedKeyVaults(keyvault.Key);
                KeyVaultAccess kvAccess = new KeyVaultAccess(kvInfo);
                foreach (var secret in keyvault)
                {
                    kvAccess.UpdateSecretExpirationDate(secret.ItemName, secret.ExpiredDate).Wait();
                }

                Console.WriteLine("[End] Completed update secrets' expiration date in keyvault {0}, total secrets {1}...", keyvault.Key, keyvault.Count());
                Console.WriteLine();
            }
        }

        private static void DeleteSecretsFromFile(string file)
        {
            string[] lines = File.ReadAllLines(file);
            var certsToDelete = lines.Select(item =>
            {
                item = item.Trim();
                return new
                {
                    ItemName = item.Substring(item.LastIndexOf('/') + 1),
                    KeyVaultPath = item,
                    KeyVault = item.Substring("https://".Length, item.IndexOf(".vault.azure.cn/") - "https://".Length),
                };
            }).ToList();

            var groupedByKeyVault = certsToDelete.GroupBy(x => x.KeyVault).ToList();

            foreach (var keyvault in groupedByKeyVault)
            {
                Console.WriteLine("[Begin] Deleting secrets in keyvault {0}, total secrets {1}...", keyvault.Key, keyvault.Count());
                KeyVaultSettingInfo kvInfo = GetPredefinedKeyVaults(keyvault.Key);
                KeyVaultAccess kvAccess = new KeyVaultAccess(kvInfo);
                foreach (var secretToDelete in keyvault)
                {
                    kvAccess.DeleteSecret(secretToDelete.ItemName).Wait();
                }

                Console.WriteLine("[End] Completed delete secret in keyvault {0}, total secrets {1}...", keyvault.Key, keyvault.Count());
                Console.WriteLine();
            }
        }

        private static void DeleteCertificatesFromFile(string file)
        {
            string[] lines = File.ReadAllLines(file);
            var certsToDelete = lines.Select(item =>
            {
                item = item.Trim();
                return new
                {
                    ItemName = item.Substring(item.LastIndexOf('/') + 1),
                    KeyVaultPath = item,
                    KeyVault = item.Substring("https://".Length, item.IndexOf(".vault.azure.cn/") - "https://".Length),
                };
            }).ToList();

            var groupedByKeyVault = certsToDelete.GroupBy(x => x.KeyVault).ToList();

            foreach (var keyvault in groupedByKeyVault)
            {
                Console.WriteLine("[Begin] Deleting certificate in keyvault {0}, total certificates {1}...", keyvault.Key, keyvault.Count());
                KeyVaultSettingInfo kvInfo = GetPredefinedKeyVaults(keyvault.Key);
                KeyVaultAccess kvAccess = new KeyVaultAccess(kvInfo);
                foreach (var certToDelete in keyvault)
                {
                    kvAccess.DeleteCertificate(certToDelete.ItemName).Wait();
                }

                Console.WriteLine("[End] Completed delete certificate in keyvault {0}, total certificates {1}...", keyvault.Key, keyvault.Count());
                Console.WriteLine();
            }
        }

        private static void BackupCustomerCertificates()
        {

            KeyVaultSettingInfo srcKvInfo = GetPredefinedKeyVaults("mccdnprod");

            KeyVaultSettingInfo dstKvInfo = new KeyVaultSettingInfo
            {
                Url = "https://mccdn-prod-savecustomer.vault.azure.cn/",
                AADInfo = new AADSettingInfo
                {
                    Name = "temp",
                    ClientId = "e5853e7a-fb1d-439d-ac66-ca22b1054fc4",
                    CertificateThumbprint = "0ed3c86cda68e9f087a93ec25b95b7c71cb86ae6",
                }
            };

            CopyCustomerCertificates(srcKvInfo, dstKvInfo);
        }

        private static bool IsGuidSecret(SecretInfo cert)
        {
            return !IsNotGuidName(cert.Name);
        }

        private static bool IsGuidCertificate(CertificateItem cert)
        {
            return !IsNotGuidName(cert.Identifier.Name);
        }

        private static bool IsNotGuidCertificate(CertificateItem cert)
        {
            return IsNotGuidName(cert.Identifier.Name);
        }

        private static bool IsNotGuidName(string name)
        {
            Guid guid;
            return !Guid.TryParse(name, out guid);
        }

        private static async Task CopySecretAsync(KeyVaultSettingInfo srcKvInfo, KeyVaultSettingInfo dstKvInfo, string secretName, bool overwriteExisting = false)
        {
            KeyVaultAccess srckv = new KeyVaultAccess(srcKvInfo);
            var secretItem = srckv.GetSecretItem(secretName);
            if (secretItem == null)
            {
                throw new ArgumentException($"Cannot get secret '{secretName}' in source key vault '{srcKvInfo.Url}'");
            }

            KeyVaultAccess dstkv = new KeyVaultAccess(dstKvInfo);
            await dstkv.ImportSecretsAndCerts(new SecretInfo[] { secretItem }.ToList(), overwriteExisting).ConfigureAwait(false);
        }

        private static void CopySecrets(KeyVaultSettingInfo srcKvInfo, KeyVaultSettingInfo dstKvInfo, Predicate<SecretInfo> isMatched, bool overwriteExisting = false)
        {
            Console.WriteLine("CopySecrets from key vault {0} to {1}, overwrite existing: {2}, press any key to continue...", srcKvInfo, dstKvInfo, overwriteExisting);
            Console.ReadKey();

            KeyVaultAccess srckv = new KeyVaultAccess(srcKvInfo);

            var certs = srckv.DownloadSecretsAndCerts(isMatched).Result.ToList();

            string secretsName = string.Join(Environment.NewLine, certs.Select(x => x.Name));
            Console.WriteLine($"Secrets to download Names: {secretsName}");

            Console.WriteLine("Press any key to continue...");
            Console.ReadKey();

            KeyVaultAccess dstkv = new KeyVaultAccess(dstKvInfo);
            dstkv.ImportSecretsAndCerts(certs, overwriteExisting).Wait();
        }

        private static void DisableCertificate(KeyVaultSettingInfo disableKvInfo, Predicate<CertificateInfo> predict)
        {
            Console.WriteLine("DisableCertificates for givin key vault {0}, press any key to continue...", disableKvInfo);
            Console.ReadKey();

            KeyVaultAccess kv = new KeyVaultAccess(disableKvInfo);
            kv.DisableAllCertificates(predict).Wait();
        }

        private static async Task CopyCertificate(KeyVaultSettingInfo srcKvInfo, KeyVaultSettingInfo dstKvInfo, string name, bool overwriteExisting = false)
        {
            KeyVaultAccess srckv = new KeyVaultAccess(srcKvInfo);
            var cert = await srckv.GetExistingCertificate(name).ConfigureAwait(false);

            if (cert == null)
            {
                throw new KeyNotFoundException($"Cannot find certificate {name} from source key vault {srcKvInfo.Url}");
            }

            KeyVaultAccess dstkv = new KeyVaultAccess(dstKvInfo);
            await dstkv.ImportCertificate(cert, overwriteExisting).ConfigureAwait(false);
        }

        private static void CopyCustomerCertificates(KeyVaultSettingInfo srcKvInfo, KeyVaultSettingInfo dstKvInfo)
        {
            Console.WriteLine("CopyCustomerCertificates from key vault {0} to {1}, press any key to continue...", srcKvInfo, dstKvInfo);
            Console.ReadKey();

            Console.WriteLine("Beginig copy customer certificates...");

            KeyVaultAccess srckv = new KeyVaultAccess(srcKvInfo);
            KeyVaultAccess dstkv = new KeyVaultAccess(dstKvInfo);

            var secrets = srckv.DownloadSecretsAndCerts(IsGuidSecret).Result.ToList();
            //var secrets = srckv.DownloadSecretsAndCerts(x => x.Identifier.Name == "15a11949-5a3e-11e8-be87-0017fa000909").Result.ToList();
            dstkv.ImportSecretsAndCerts(secrets).Wait();

            //var certificates = srckv.DownloadCertificates(IsGuidCertificate).Result.ToList();
            //dstkv.ImportCertificates(certificates).Wait();
        }

        private static string KeyvaultReaderSecretRetriever()
        {
            var kvInfo = GetPredefinedKeyVaults("mccdn-prodsecrets-holder");

            KeyVaultAccess kv = new KeyVaultAccess(kvInfo);
            var secret = kv.GetSecret("CertificateRepositoryKeyVaultClientSecret");
            return secret;
        }

        private static readonly Dictionary<string, AADSettingInfo> PredefinedAADInfo = new Dictionary<string, AADSettingInfo>()
            .AddAADSettingInfo("KeyVaultMcCdnDeployProdCMEByCertApp3", "acd70671-bc7d-450d-8cc3-02c1f98d0561", "E72D40CC10B7B3560B61D33C32E19D38E5E9ECED", "config.keyvault.access.cdn.azure.cn")
            .AddAADSettingInfo("KeyVaultMcCdnDeployTestByCertApp", "e5853e7a-fb1d-439d-ac66-ca22b1054fc4", "0ed3c86cda68e9f087a93ec25b95b7c71cb86ae6")
            .AddAADSettingInfo("KeyVaultMcCdnDeployProdCMEByCertApp2", "5c83117e-eb3b-40c2-9afc-545893059b36", "E72D40CC10B7B3560B61D33C32E19D38E5E9ECED", "config.keyvault.access.cdn.azure.cn")
            .AddAADSettingInfo("KeyVaultMcCdnDeployProdByCertApp2", "000be46d-6e2e-4ab9-b6f4-996e4d1e834d", "E72D40CC10B7B3560B61D33C32E19D38E5E9ECED", "config.keyvault.access.cdn.azure.cn")
            .AddAADSettingInfo("KeyVaultMcCCSDeployProdCMEByCertApp3", "9a1a38f5-a221-4d21-9f3b-7655665f33fa", "FE7A56C1DC4F91E7A2BA216C8464AB50AF29FB25")
            .AddAADSettingInfo("mccdn-keyvault-reader", "d144f18e-c146-4d94-b9de-8f942bd30ccf", null, null, true, KeyvaultReaderSecretRetriever);

        private static readonly Dictionary<string, KeyVaultSettingInfo> predefinedKeyVaults = new Dictionary<string, KeyVaultSettingInfo>()
            .AddKeyVault("mccdnintkvn2", PredefinedAADInfo["KeyVaultMcCdnDeployTestByCertApp"])
            .AddKeyVault("test001", PredefinedAADInfo["KeyVaultMcCdnDeployTestByCertApp"])
            .AddKeyVault("cdnbillingkvprod", PredefinedAADInfo["KeyVaultMcCdnDeployProdCMEByCertApp2"])
            .AddKeyVault("mccdnsecretsholdertest", PredefinedAADInfo["KeyVaultMcCdnDeployTestByCertApp"])
            .AddKeyVault("ccskvtest", PredefinedAADInfo["KeyVaultMcCdnDeployProdCMEByCertApp2"])
            .AddKeyVault("ccskvprod", PredefinedAADInfo["KeyVaultMcCCSDeployProdCMEByCertApp3"])
            .AddKeyVault("mccdnkeyvault", PredefinedAADInfo["KeyVaultMcCdnDeployProdByCertApp2"])
            .AddKeyVault("mccdnprod", PredefinedAADInfo["KeyVaultMcCdnDeployProdByCertApp2"])
            .AddKeyVault("sfmccdnprodkv", PredefinedAADInfo["KeyVaultMcCdnDeployProdByCertApp2"])
            //            .AddKeyVault("mccdndeployprod-cme", PredefinedAADInfo["KeyVaultMcCdnDeployProdCMEByCertApp3"])
            .AddKeyVault("mccdndeployprod-cme", PredefinedAADInfo["mccdn-keyvault-reader"])
            .AddKeyVault("mccdndeploytest", PredefinedAADInfo["KeyVaultMcCdnDeployTestByCertApp"])
            .AddKeyVault("mccdn-prodsecrets-holder", PredefinedAADInfo["KeyVaultMcCdnDeployTestByCertApp"])
            .AddKeyVault("cert-holder-del-2020-07", PredefinedAADInfo["KeyVaultMcCdnDeployTestByCertApp"])
            .AddKeyVault("mccdnarm-provider-prod01", PredefinedAADInfo["KeyVaultMcCdnDeployProdCMEByCertApp3"])
            .AddKeyVault("mccdnintkveast2", PredefinedAADInfo["KeyVaultMcCdnDeployTestByCertApp"])
            .AddKeyVault("mccdn-prodv2-holder", PredefinedAADInfo["KeyVaultMcCdnDeployTestByCertApp"])
            //            .AddKeyVault("mccdndeployprodv2-cme", PredefinedAADInfo["KeyVaultMcCdnDeployProdCMEByCertApp3"])
            .AddKeyVault("mccdndeployprodv2-cme", PredefinedAADInfo["mccdn-keyvault-reader"])
            .AddKeyVault("mccdncoreconfig", PredefinedAADInfo["KeyVaultMcCdnDeployProdCMEByCertApp3"])
            .AddKeyVault("mccdn-vscode", PredefinedAADInfo["KeyVaultMcCdnDeployTestByCertApp"])
            .AddKeyVault("mccdn-nuget", PredefinedAADInfo["KeyVaultMcCdnDeployTestByCertApp"])
            .AddKeyVault("mccdn-gallery", PredefinedAADInfo["KeyVaultMcCdnDeployTestByCertApp"])
            .AddKeyVault("mccdndeployprod", PredefinedAADInfo["KeyVaultMcCdnDeployProdByCertApp2"]);

        private static KeyVaultSettingInfo GetPredefinedKeyVaults(string kvName)
        {
            if (predefinedKeyVaults.ContainsKey(kvName))
            {
                return predefinedKeyVaults[kvName];
            }

            throw new KeyNotFoundException($"KeyVaultSettingInfo not found with key vault name {kvName}");
        }
    }

    public static class MyExtension
    {
        public static Dictionary<string, AADSettingInfo> AddAADSettingInfo(
            this Dictionary<string, AADSettingInfo> dict,
            string aadName,
            string clientId,
            string certThumbrpint,
            string certName = null,
            bool useSecret = false,
            Func<string> secretRetriever = null)
        {
            var info = GenerateAADSettingInfo(aadName, clientId, certThumbrpint, certName, useSecret, secretRetriever);
            dict.Add(info.Key, info.Value);
            return dict;
        }

        public static Dictionary<string, KeyVaultSettingInfo> AddKeyVault(this Dictionary<string, KeyVaultSettingInfo> dict, string keyvaultName, AADSettingInfo aadInfo)
        {
            var info = GenerateKeyVaultSettingInfo(keyvaultName, aadInfo);
            dict.Add(info.Key, info.Value);
            return dict;
        }

        private static KeyValuePair<string, KeyVaultSettingInfo> GenerateKeyVaultSettingInfo(string keyvaultName, AADSettingInfo aadInfo)
        {
            return new KeyValuePair<string, KeyVaultSettingInfo>(
                keyvaultName,
                new KeyVaultSettingInfo
                {
                    Url = $"https://{keyvaultName}.vault.azure.cn/",
                    AADInfo = aadInfo,
                });
        }

        private static KeyValuePair<string, AADSettingInfo> GenerateAADSettingInfo(
            string aadName,
            string clientId,
            string certThumbprint,
            string certName,
            bool useSecret, Func<string> secretRetriever)
        {
            return new KeyValuePair<string, AADSettingInfo>(
                aadName,
                new AADSettingInfo
                {
                    Name = aadName,
                    ClientId = clientId,
                    CertificateThumbprint = certThumbprint,
                    CertificateName = certName,
                    UseSecret = useSecret,
                    SecretRetriever = secretRetriever,
                });
        }

    }
}
