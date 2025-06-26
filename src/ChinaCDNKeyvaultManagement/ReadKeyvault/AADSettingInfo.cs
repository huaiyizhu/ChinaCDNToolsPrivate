using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Mooncake.Cdn.CredentialManagementTool
{
    public enum KeyVaultEnvironment
    {
        China,
        Global,
    }

    public enum AADAuthType
    {
        None = 0,
        Secret,
        CertificateThumbprint,
        SNICertificate,
    }

    public class AADSettingInfo
    {
        public const string KeyvaultSuffixChina = "vault.azure.cn";
        public const string KeyvaultSuffixGlobal = "vault.azure.net";

        public string Name { get; set; }
        public string ClientId { get; set; }
        public string CertificateThumbprintOrName { get; set; }

        public KeyVaultEnvironment Environment { get; set; }

        public string KeyvaultSuffix => Environment == KeyVaultEnvironment.China ? KeyvaultSuffixChina : KeyvaultSuffixGlobal;

        public AADAuthType AuthType { get; set; }

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
    public static class AADSettingInfoExtensions
    {
        public static Dictionary<string, AADSettingInfo> AddAADSettingInfo(
            this Dictionary<string, AADSettingInfo> dict,
            KeyVaultEnvironment env,
            string aadName,
            string clientId,
            AADAuthType authType,
            string certThumbprintOrName = null,
            Func<string> secretRetriever = null)
        {
            var info = GenerateAADSettingInfo(env, aadName, clientId, authType, certThumbprintOrName, secretRetriever);
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
                    Url = $"https://{keyvaultName}.{aadInfo.KeyvaultSuffix}/",
                    AADInfo = aadInfo,
                });
        }

        private static KeyValuePair<string, AADSettingInfo> GenerateAADSettingInfo(
            KeyVaultEnvironment env,
            string aadName,
            string clientId,
            AADAuthType authType,
            string certThumbprintOrName,
            Func<string> secretRetriever)
        {
            return new KeyValuePair<string, AADSettingInfo>(
                aadName,
                new AADSettingInfo
                {
                    Name = aadName,
                    ClientId = clientId,
                    AuthType = authType,
                    CertificateThumbprintOrName = certThumbprintOrName,
                    Environment = env,
                    SecretRetriever = secretRetriever,
                });
        }

    }

}
