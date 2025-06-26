using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using CommandLine;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.Cloud.MooncakeService.Common;

namespace Mooncake.Cdn.CredentialManagementTool
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

                CommandLine.Parser.Default.ParseArguments<CommandOptions>(args)
                                          .WithParsedAsync(ProcessCommandLines)
                                          .Wait();

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

        private static async Task ProcessCommandLines(CommandOptions command)
        {
            try
            {
                Program program = new Program();
                switch (command.Operation)
                {
                    case OperationType.list:
                        await program.ProcessListAction(command).ConfigureAwait(false);
                        break;
                    case OperationType.sync:
                        await program.ProcessSyncAction(command).ConfigureAwait(false);
                        break;
                    case OperationType.get:
                        await program.ProcessGetAction(command).ConfigureAwait(false);
                        break;
                    case OperationType.getallversions:
                        await program.ProcessGetAllVersionsAction(command).ConfigureAwait(false);
                        break;                            
                    case OperationType.add:
                        await program.ProcessAddAction(command).ConfigureAwait(false);
                        break;
                    case OperationType.delete:
                        await program.ProcessDeleteAction(command).ConfigureAwait(false);
                        break;
                    case OperationType.update:
                        await program.ProcessUpdateAction(command).ConfigureAwait(false);
                        break;
                    case OperationType.download:
                        await program.ProcessDownloadAction(command).ConfigureAwait(false);
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

        private async Task ProcessAddAction(CommandOptions command)
        {
            Requires.Argument("name", command.TargetName).NotNullOrEmpty();
//            Requires.Argument("value", command.Value).NotNullOrEmpty();
            Requires.Argument("expired", command.ExpiredDate).NotNull();
            Requires.Argument("target", command.Target).PassPredication(x => x == OperationTarget.secret, "only secret type is supported");

            Console.WriteLine($"Begin to add {command.Target} '{command.TargetName}' for source key vault '{command.SrcKeyVault}', value: {command.Value}, value from file: {command.ValueFile}, expired date {command.ExpiredDate}, overwrite existing: {command.OverrideIfExist}...");

            if (string.IsNullOrEmpty(command.Value) && string.IsNullOrEmpty(command.ValueFile))
            {
                throw new ArgumentException("Secret value or file for secret value should be provided for adding secret");
            }

            string finalValue = command.Value;
            if (string.IsNullOrEmpty(finalValue))
            {
                finalValue = File.ReadAllText(command.ValueFile, System.Text.Encoding.UTF8);
            }

            if (string.IsNullOrEmpty(finalValue))
            {
                throw new ArgumentException("Non empty secret value must be provided or read from a file.");
            }

            KeyVaultSettingInfo srcKVInfo = GetPredefinedKeyVaults(command.SrcKeyVault);
            KeyVaultAccess kv = new KeyVaultAccess(srcKVInfo);

            await kv.WriteSecretAsync(command.TargetName, finalValue, command.ExpiredDate.Value, command.OverrideIfExist).ConfigureAwait(false);

        }

        private async Task ProcessUpdateAction(CommandOptions command)
        {
            Requires.Argument("name", command.TargetName).NotNullOrEmpty();
            Requires.Argument("expired", command.ExpiredDate).NotNull();
            Requires.Argument("target", command.Target).PassPredication(x => x == OperationTarget.secret, "only secret type is supported");

            Console.WriteLine($"Begin to update for {command.Target} '{command.TargetName}' with version '{command.CredentialVersion}' from source key vault '{command.SrcKeyVault}', new expired date {command.ExpiredDate}...");

            KeyVaultSettingInfo srcKVInfo = GetPredefinedKeyVaults(command.SrcKeyVault);
            KeyVaultAccess kv = new KeyVaultAccess(srcKVInfo);

            await kv.UpdateSecretExpirationDateAsync(command.TargetName, command.CredentialVersion, command.ExpiredDate.Value).ConfigureAwait(false);
        }

        private async Task ProcessDeleteAction(CommandOptions command)
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
                await kv.DeleteCertificateAsync(command.TargetName).ConfigureAwait(false);
            }
            else
            {
                await kv.DeleteSecretAsync(command.TargetName).ConfigureAwait(false);
            }
        }

        private async Task ProcessListAction(CommandOptions command)
        {
            Console.WriteLine($"Begin to list all {command.Target} of source key vault '{command.SrcKeyVault}', show secret value {command.GetSecretValue}...");
            KeyVaultSettingInfo srcKVInfo = GetPredefinedKeyVaults(command.SrcKeyVault);
            KeyVaultAccess kv = new KeyVaultAccess(srcKVInfo);
            if (command.Target == OperationTarget.certificate)
            {
                var certificates = await kv.GetAllCertificatesAsync().ConfigureAwait(false);
                Console.WriteLine($"Total certificates: {certificates.Count}");
                foreach (var cert in certificates)
                {
                    Console.WriteLine($"  {cert}");
                }
            }
            else
            {
                var secrets = await kv.GetAllSecretsAsync(includeCertificates: false, showSecretValue: command.GetSecretValue).ConfigureAwait(false);
                Console.WriteLine($"Total secrets: {secrets.Count}");
                foreach (var secret in secrets)
                {
                    string result = command.GetSecretValue ? secret.ToStringWithSecretValue() : secret.ToString();
                    Console.WriteLine($"  {result}");
                }
            }
        }

        private async Task ProcessSyncAction(CommandOptions command)
        {
            Requires.Argument("dstkv", command.DstKeyVault).NotNullOrEmpty();
            Requires.Argument("name", command.TargetName).NotNullOrEmpty();

            Console.WriteLine($"Begin to sync {command.Target} '{command.TargetName}' with version '{command.CredentialVersion}' from source key vault '{command.SrcKeyVault}' to dest key vaule '{command.DstKeyVault}'. Override if exist: {command.OverrideIfExist}");

            KeyVaultSettingInfo srcKVInfo = GetPredefinedKeyVaults(command.SrcKeyVault);
            KeyVaultSettingInfo dstKVInfo = GetPredefinedKeyVaults(command.DstKeyVault);

            if (command.Target == OperationTarget.certificate)
            {
                await CopyCertificate(
                    srcKVInfo,
                    dstKVInfo,
                    command.TargetName,
                    command.CredentialVersion,
                    command.OverrideIfExist).ConfigureAwait(false);
            }
            else
            {
                await CopySecretAsync(
                    srcKVInfo,
                    dstKVInfo,
                    command.TargetName,
                    command.CredentialVersion,
                    command.OverrideIfExist).ConfigureAwait(false);
            }
        }

        private async Task ProcessDownloadAction(CommandOptions command)
        {
            if (command.Target == OperationTarget.secret)
            {
                Console.WriteLine($"Download secret to file is not supported. Please get the secret value by using '--showsecret' parameter");
                return;
            }

            Requires.Argument("name", command.TargetName).NotNullOrEmpty();

            Console.WriteLine($"Begin to download {command.Target} '{command.TargetName}' with version '{command.CredentialVersion}' from source key vault '{command.SrcKeyVault}'.");

            KeyVaultSettingInfo srcKVInfo = GetPredefinedKeyVaults(command.SrcKeyVault);

            await DownloadCertificate(
                srcKVInfo,
                command.TargetName,
                command.CredentialVersion,
                command.OverrideIfExist).ConfigureAwait(false);
        }

        private async Task ProcessGetAction(CommandOptions command)
        {
            Requires.Argument("name", command.TargetName).NotNullOrEmpty();

            Console.WriteLine($"Begin to find {command.Target} '{command.TargetName}' with version '{command.CredentialVersion}' under key vault '{command.SrcKeyVault}', show secret value: {command.GetSecretValue}");
            KeyVaultSettingInfo srcKV = GetPredefinedKeyVaults(command.SrcKeyVault);
            KeyVaultAccess kv = new KeyVaultAccess(srcKV);
            if (command.Target == OperationTarget.certificate)
            {
                var cert = await kv.GetExistingCertificateAsync(command.TargetName, command.CredentialVersion).ConfigureAwait(false);
                if (cert == null)
                {
                    Console.WriteLine($"Cannot find certificate '{command.TargetName}' with version '{command.CredentialVersion}' under key vault '{command.SrcKeyVault}'");
                }
                else
                {
                    Console.WriteLine($"Certificate is {cert}");
                }
            }
            else
            {
                var secret = await kv.GetSecretItemAsync(command.TargetName, command.CredentialVersion).ConfigureAwait(false);
                if (secret == null)
                {
                    Console.WriteLine($"Cannot find secret '{command.TargetName}' with version '{command.CredentialVersion}' under key vault '{command.SrcKeyVault}'");
                }
                else
                {
                    string result = command.GetSecretValue ? secret.ToStringWithSecretValue() : secret.ToString();
                    Console.WriteLine($"Secret is {result}");
                }
            }
        }

        private async Task ProcessGetAllVersionsAction(CommandOptions command)
        {
            Requires.Argument("name", command.TargetName).NotNullOrEmpty();

            Console.WriteLine($"Begin to find {command.Target} '{command.TargetName}' with all versions under key vault '{command.SrcKeyVault}', show secret value: {command.GetSecretValue}");
            KeyVaultSettingInfo srcKV = GetPredefinedKeyVaults(command.SrcKeyVault);
            KeyVaultAccess kv = new KeyVaultAccess(srcKV);
            if (command.Target == OperationTarget.certificate)
            {
                var certs = await kv.GetExistingCertificateWithAllVersionsAsync(command.TargetName).ConfigureAwait(false);
                if (!certs.Any())
                {
                    Console.WriteLine($"Cannot find certificate '{command.TargetName}' under key vault '{command.SrcKeyVault}'");
                }
                else
                {
                    Console.WriteLine($"Certificate with {certs.Count()} versions:");
                    foreach (var cert in certs)
                    {
                        Console.WriteLine($"{cert}");
                    }   
                }
            }
            else
            {
                var secrets = await kv.GetSecretItemWithAllVersionsAsync(command.TargetName).ConfigureAwait(false);
                if (!secrets.Any())
                {
                    Console.WriteLine($"Cannot find secret '{command.TargetName}' under key vault '{command.SrcKeyVault}'");
                }
                else
                {
                    Console.WriteLine($"Secret with {secrets.Count()} versions:");
                    foreach (var secret in secrets)
                    {
                        string result = command.GetSecretValue ? secret.ToStringWithSecretValue() : secret.ToString();
                        Console.WriteLine($"{result}");
                    }
                }
            }
        }

        private static async Task UpdateSecretsExpiredDateFromFile(string file)
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
                    await kvAccess.UpdateSecretExpirationDateAsync(secret.ItemName, null, secret.ExpiredDate).ConfigureAwait(false);
                }

                Console.WriteLine("[End] Completed update secrets' expiration date in keyvault {0}, total secrets {1}...", keyvault.Key, keyvault.Count());
                Console.WriteLine();
            }
        }

        private static async Task DeleteSecretsFromFile(string file)
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
                    await kvAccess.DeleteSecretAsync(secretToDelete.ItemName).ConfigureAwait(false);
                }

                Console.WriteLine("[End] Completed delete secret in keyvault {0}, total secrets {1}...", keyvault.Key, keyvault.Count());
                Console.WriteLine();
            }
        }

        private static async Task DeleteCertificatesFromFile(string file)
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
                    await kvAccess.DeleteCertificateAsync(certToDelete.ItemName).ConfigureAwait(false);
                }

                Console.WriteLine("[End] Completed delete certificate in keyvault {0}, total certificates {1}...", keyvault.Key, keyvault.Count());
                Console.WriteLine();
            }
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

        private static async Task CopySecretAsync(KeyVaultSettingInfo srcKvInfo, KeyVaultSettingInfo dstKvInfo, string secretName, string srcVersion, bool overwriteExisting = false)
        {
            KeyVaultAccess srckv = new KeyVaultAccess(srcKvInfo);
            var secretItem = await srckv.GetSecretItemAsync(secretName, srcVersion).ConfigureAwait(false);
            if (secretItem == null)
            {
                throw new ArgumentException($"Cannot get secret '{secretName}' with version '{srcVersion}' in source key vault '{srcKvInfo.Url}'");
            }

            KeyVaultAccess dstkv = new KeyVaultAccess(dstKvInfo);
            await dstkv.ImportSecretsAndCertsAsync(new SecretInfo[] { secretItem }.ToList(), overwriteExisting).ConfigureAwait(false);
        }

        private static async Task DisableCertificate(KeyVaultSettingInfo disableKvInfo, Predicate<CertificateInfo> predict)
        {
            Console.WriteLine("DisableCertificates for givin key vault {0}, press any key to continue...", disableKvInfo);
            Console.ReadKey();

            KeyVaultAccess kv = new KeyVaultAccess(disableKvInfo);
            await kv.DisableAllCertificatesAsync(predict).ConfigureAwait(false);
        }

        private static async Task CopyCertificate(KeyVaultSettingInfo srcKvInfo, KeyVaultSettingInfo dstKvInfo, string name, string srcVersion, bool overwriteExisting = false)
        {
            KeyVaultAccess srckv = new KeyVaultAccess(srcKvInfo);
            var cert = await srckv.GetExistingCertificateAsync(name, srcVersion).ConfigureAwait(false);

            if (cert == null)
            {
                throw new KeyNotFoundException($"Cannot find certificate {name} with version '{srcVersion}' from source key vault {srcKvInfo.Url}");
            }

            KeyVaultAccess dstkv = new KeyVaultAccess(dstKvInfo);
            await dstkv.ImportCertificateAsync(cert, overwriteExisting).ConfigureAwait(false);
        }

        private static async Task DownloadCertificate(KeyVaultSettingInfo srcKvInfo, string name, string srcVersion, bool overwriteExisting = false)
        {
            KeyVaultAccess srckv = new KeyVaultAccess(srcKvInfo);
            var cert = await srckv.GetExistingCertificateAsync(name, srcVersion).ConfigureAwait(false);

            if (cert == null)
            {
                throw new KeyNotFoundException($"Cannot find certificate {name} with version '{srcVersion}' from source key vault {srcKvInfo.Url}");
            }

            WriteCertificateFile(cert, name, overwriteExisting);
        }

        private static void WriteCertificateFile(CertificateInfo cert, string name, bool overwriteExisting = false)
        {
            string filePathName = string.Concat(name, ".pfx");
            Console.WriteLine("Downloading Certificate to local file {0} with overwrite {1}...", filePathName, overwriteExisting);
            if (File.Exists(filePathName))
            {
                if (overwriteExisting)
                {
                    Console.WriteLine("File {0} exist, overwrite the file...", filePathName);
                }
                else
                {
                    Console.WriteLine("File {0} already exist, stop download.", filePathName);
                    return;
                }
            }

            byte[] rawSecret = Convert.FromBase64String(cert.Value);
            File.WriteAllBytes(filePathName, rawSecret);

            Console.WriteLine("Downloaded Certificate to local file {0}", filePathName);
        }

        private static string KeyvaultReaderSecretRetriever()
        {
            var kvInfo = GetPredefinedKeyVaults("mccdn-prodsecrets-holder");

            KeyVaultAccess kv = new KeyVaultAccess(kvInfo);
            var secret = kv.GetSecretAsync("CertificateRepositoryKeyVaultClientSecret", null).GetAwaiter().GetResult();
            return secret;
        }

        private static readonly Dictionary<string, AADSettingInfo> PredefinedAADInfo = new Dictionary<string, AADSettingInfo>()
            .AddAADSettingInfo(KeyVaultEnvironment.China, "ChinaCDNCredentialKeyVaultAccess.Prod", "3344f555-f11c-4ac8-ba24-426edf324904", AADAuthType.SNICertificate, "keyvault.prod.access.chinacdn.azclient.ms")
            .AddAADSettingInfo(KeyVaultEnvironment.China, "ChinaCDNCredentialKeyVaultAccess.Int", "5230d07e-253b-47f4-82b7-9ccc750f7de3", AADAuthType.SNICertificate, "keyvault.int.access.chinacdn.azclient-int.ms")
            .AddAADSettingInfo(KeyVaultEnvironment.China, "KeyVaultMcCdnDeployTestByCertApp", "e5853e7a-fb1d-439d-ac66-ca22b1054fc4", AADAuthType.CertificateThumbprint, "0ed3c86cda68e9f087a93ec25b95b7c71cb86ae6")
            .AddAADSettingInfo(KeyVaultEnvironment.China, "KeyVaultMcCdnDeployProdCMEByCertApp2", "5c83117e-eb3b-40c2-9afc-545893059b36", AADAuthType.SNICertificate, "config.keyvault.access.cdn.azure.cn")
            .AddAADSettingInfo(KeyVaultEnvironment.China, "KeyVaultMcCdnDeployProdByCertApp2", "000be46d-6e2e-4ab9-b6f4-996e4d1e834d", AADAuthType.SNICertificate, "config.keyvault.access.cdn.azure.cn")
            .AddAADSettingInfo(KeyVaultEnvironment.China, "KeyVaultMcCCSDeployProdCMEByCertApp3", "9a1a38f5-a221-4d21-9f3b-7655665f33fa", AADAuthType.CertificateThumbprint, "FE7A56C1DC4F91E7A2BA216C8464AB50AF29FB25")
            .AddAADSettingInfo(KeyVaultEnvironment.China, "KeyVaultMcCdnDeployTestCMEByCertApp", "d4837427-d2f6-45b7-a7b7-6402387e46b8", AADAuthType.CertificateThumbprint, "0ed3c86cda68e9f087a93ec25b95b7c71cb86ae6")
            .AddAADSettingInfo(KeyVaultEnvironment.Global, "AFDCloudTestApp", "4af5dd89-61cc-483a-b93d-9c25ce954818", AADAuthType.SNICertificate, "config.keyvault.access.cdn.azure.cn");
            //.AddAADSettingInfo(KeyVaultEnvironment.China, "mccdn-keyvault-reader", "d144f18e-c146-4d94-b9de-8f942bd30ccf", null, "config.keyvault.access.cdn.azure.cn");

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
            .AddKeyVault("mccdndeployprod-cme", PredefinedAADInfo["ChinaCDNCredentialKeyVaultAccess.Prod"])
            .AddKeyVault("mccdndeploytest-cme", PredefinedAADInfo["KeyVaultMcCdnDeployTestCMEByCertApp"])
            .AddKeyVault("mccdndeploytest", PredefinedAADInfo["KeyVaultMcCdnDeployTestByCertApp"])
            .AddKeyVault("mccdn-prodsecrets-holder", PredefinedAADInfo["KeyVaultMcCdnDeployTestByCertApp"])
            .AddKeyVault("cert-holder-del-2020-07", PredefinedAADInfo["KeyVaultMcCdnDeployTestByCertApp"])
            .AddKeyVault("mccdnarm-provider-prod01", PredefinedAADInfo["ChinaCDNCredentialKeyVaultAccess.Prod"])
            .AddKeyVault("mccdnintkveast2", PredefinedAADInfo["KeyVaultMcCdnDeployTestByCertApp"])
            .AddKeyVault("mccdn-prodv2-holder", PredefinedAADInfo["KeyVaultMcCdnDeployTestByCertApp"])
            .AddKeyVault("mccdndeployprodv2-cme", PredefinedAADInfo["ChinaCDNCredentialKeyVaultAccess.Prod"])
            .AddKeyVault("mccdnafdoutbox", PredefinedAADInfo["ChinaCDNCredentialKeyVaultAccess.Prod"])
            .AddKeyVault("mccdncoreconfig", PredefinedAADInfo["ChinaCDNCredentialKeyVaultAccess.Prod"])
            .AddKeyVault("mccdn-vscode", PredefinedAADInfo["KeyVaultMcCdnDeployTestByCertApp"])
            .AddKeyVault("mccdn-nuget", PredefinedAADInfo["KeyVaultMcCdnDeployTestByCertApp"])
            .AddKeyVault("mccdn-gallery", PredefinedAADInfo["KeyVaultMcCdnDeployTestByCertApp"])
            .AddKeyVault("mccdnbillingkvtest", PredefinedAADInfo["AFDCloudTestApp"])
            .AddKeyVault("mccdncloudtest", PredefinedAADInfo["AFDCloudTestApp"])
            //.AddKeyVault("cdnbillingkvprod", PredefinedAADInfo["mccdn-keyvault-reader"]);
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
}
