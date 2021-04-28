using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.ConstrainedExecution;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.SqlServer.Server;

namespace ReadKeyvault
{
    public class AADSettingInfo
    {
        public string Name { get; set; }
        public string ClientId { get; set; }
        public string CertificateThumbprint { get; set; }

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

                //ReadTestSecret();

                KeyVaultSettingInfo srcKvInfo = PrepareSrcKeyVaultInfo();
                KeyVaultSettingInfo dstKvInfo = PrepareDstKeyVaultInfo();
                bool overwriteExisting = false;
                string[] ccsProdCertNames =
                {
                    //"cdnrestapiclientprodv2-cdn-azure-cn"
                    //"cdnrestapiclientprod-cdn-azure-cn"
                    //"clientauth-azurechinacdn-client"
                    //"cdnrestapiclientprod-cdn-azure-cn"

                    //"vscode-cdn-azure-cn",
                    //"vsassetscdn-azure-cn",

                    //"nuget-cdn-azure-cn",
                    //"nugetdev-cdn-azure-cn",

                    //"wildcard-gallerycdn-azure-cn",
                    //"wildcard-staging-cdn-azure-cn",

                    "cdnrestapiclientprodv2-cdn-azure-cn",
                    "cdnrestapiclientprod-cdn-azure-cn",

                    //"cdpx-acr-appid",
                    //"cdpx-acr-key",

                    //"config-keyvault-access-cdn-azure-cn",
                    //"log-cdn-azure-cn",
                    //"mccdn-encrypt-cdn-azure-cn"
                    //"grafana-cdn-azure-cn"
                    //"kibana-cdn-azure-cn"

                    //"imageprocess-e186d041-82b1-4221-acf6-5631a423def6-cdn-azure-cn",
                    //"portal-cdn-azure-cn",
                    //"restapi-cdn-azure-cn",
                    //"dashboard-cdn-azure-cn"
                    

                    //"imageprocess-e186d041-82b1-4221-acf6-5631a423def6-cdn-azure-cn",
                    //"gcs-geneva-keyvault-azurechinacdn-client"
                    //"icm-access-azurechinacdn-client"

                    //"SMTPBackupAccountPassword",
                    //"SMTPPrimaryAccountPassword",

                    //"CertificateRepositoryKeyVaultClientSecret",

                //"cdpx-acr-appid",
                //"cdpx-acr-key",
            };


                //CopyCertificates(
                //    srcKvInfo,
                //    dstKvInfo,
                //    x => ccsProdCertNames.Contains(x.Identifier.Name),
                //    //x => true,
                //    overwriteExisting);

                //KeyVaultAccess kvAccess = new KeyVaultAccess(srcKvInfo.Url, srcKvInfo.ClientId, srcKvInfo.CertificateThumbprint);
                //var result = kvAccess.DownloadSecretsAndCerts(x => true).Result;
                //var certsAll = kvAccess.GetAllCertificates().Result;
                //string name = "ccsbillingprod-sas1";
                //Console.WriteLine("Trying getting secret for KV: {0}, Secret Name: {1}", srcKvInfo.Url, name);

                //string secret = kvAccess.GetSecret(name);
                //Console.WriteLine(secret);
                //kvAccess.DownloadSecretsAndCerts(x => x.Identifier.Name == "SMTPPrimaryAccountPassword").Wait();

                //string newValue = "sv=2018-03-28&ss=bfqt&srt=sco&sp=rwdlacup&se=2021-03-30T18:34:05Z&st=2019-01-14T10:34:05Z&spr=https&sig=P%2FWGHqoBJNTtiI8KqO2K5PUGx2MqsvLf%2F3Id4DlSDlU%3D";
                //Console.WriteLine($"Writing new value for secret name {name}, new value: {newValue}  . press any key to continue...");
                //Console.ReadKey();

                //kvAccess.WriteSecret(name, newValue, overwriteExisting).Wait();
                //Console.WriteLine("done");

                //CopySecrets(srcKvInfo, dstKvInfo,
                //    x => ccsProdCertNames.Contains(x.Identifier.Name),
                //    //x => true,
                //    overwriteExisting);

                //CopySecrets(srcKvInfo, dstKvInfo, x => x.Identifier.Name.StartsWith("cdn-arm-prod-"), overwriteExisting);

                ListCertificates(srcKvInfo, x => ccsProdCertNames.Contains(x.Identifier.Name));
                //ListSecrets(srcKvInfo, x => ccsProdCertNames.Contains(x.Identifier.Name));

                //CopySecrets(srcKvInfo, dstKvInfo, x => x.Identifier.Name.StartsWith("ARMService"), overwriteExisting);
                //CopySecrets(srcKvInfo, dstKvInfo, x => true, overwriteExisting);

                ////KeyVaultAccess srckv = new KeyVaultAccess(srcKvInfo.Url, srcKvInfo.ClientId, srcKvInfo.CertificateThumbprint);
                ////var result = srckv.GetSecret("cdnbillingprod-sas1");
                ////Console.WriteLine(result);

                //CopySecrets(srcKvInfo, dstKvInfo, overwriteExisting);
                ////string[] secretNames =
                ////    {
                ////        "MonitoringXStoreAccounts-customer-portal",
                ////        "MonitoringXStoreAccounts-admin-portal",
                ////        "MonitoringXStoreAccounts-workerservice",
                ////    };

                ////string[] secretValues =
                ////    {
                ////    @"chinaccs-mds-moniker#308202D906092A864886F70D010703A08202CA308202C60201003182017D308201790201003061304D310B300906035504061302555331153013060355040A130C446967694365727420496E63312730250603550403131E44696769436572742053484132205365637572652053657276657220434102100AC98491ADAD4F0779E3465DDCAF22FF300D06092A864886F70D01010730000482010064E45150CA07DFE90B8738FFB56207AEA268CC41FC8298152C89051356A6E0EB79BDC99C8CE643D29926F1066E4912588B80B1C788B7F20FAE43B792AD9D86D341BE44B6E9BCF4AA310BA5C41588DF266BFB06CD871B3DA899EEB494C8F9BA41D96D4E0A4B6FB13FD4A14C1E5261035938179586C016353DB42CDD64D3368C4AD07A388F70261AC1E2BD4B793A5C4BC69FC0C2A9B0D046B1908C16E303E99ECAD06C3BB7E8ECB6B7AF88DCFF59C41F1F4B7BF499BA51D61A47850006A51ACD54ECE081B65E735A5497B9A970696E01E65EE33F7D96DD878CB30B8622525942FC452970B9AD34C7EA7C6307928E5A4DF51B698337184412BFE574C15A822C857F3082013E06092A864886F70D010701301D060960864801650304012A041085992965196185C6E08F789416546C81808201109D926AC20BDDE55BDDD5CC91E6CE2CC7BA80A88F039CFDE6476E69DA4A92D8A93534FFA42A7818478249888C521C80D670F800AC6328DC19165ECFD1547237C78D8CDE188C5AC93C4CE60A05F8AEBC0D557369D3D06A22B5F8E6BBF1488632963B520136310AA8ED461E1DE28BD067D479888F1E6A43BEEEED234040C6A04ADE3B1E5B01A173BCEF4C876DCCBB5921D6FAD3795EABA725246F825DDA9350E7A678F94486FA49261218075430BED9AF207C552CD1371284035165C38633A6032129F09004C1A3024C707CA9CD356C092390DE446C6B5FCA7A00A9E192D208D3886097157ED2DB757F909962BCD0F08A853914ADB52B628C98D53E155953EB872EF933CD71B252F9ECD7459E720D076EE4#LOCAL_MACHINE\MY;chinaccs-mdsaudit-moniker#308202D906092A864886F70D010703A08202CA308202C60201003182017D308201790201003061304D310B300906035504061302555331153013060355040A130C446967694365727420496E63312730250603550403131E44696769436572742053484132205365637572652053657276657220434102100AC98491ADAD4F0779E3465DDCAF22FF300D06092A864886F70D0101073000048201001EF42642A22A63C86BD78E7C05DC2CB33F4ADB018336B024E3E0EAE5DA2372F87CD22624462920A62B979FDA15EC94FE8C38F42397D2CF7641867E56C603E17F199171CCD011C603889D76DFDC087426FD6C06C4EAF553A82122EE921A11C166AFF9F43A2F4FF3A80281383E5E1D710F10EEA2EA2BCF9DBF4A82A83A35CABF5DD3612B3E9C975B035E473B4B9ADC70116C0A0D1C547EF3ACA040964CB22FE5732E034136C9D4AD790612E2262D5BD3D9420ABE2B8F5E29701A824D3B443ED53B89AC3F60CD5CA43D4D2771DAE26FBB5ADC05523A1E7D4E93153A6A7929ACD032B9A2F3E837B9D460FC0B1CC146E2CFE838837DCCABA1C639EEE32C51390120C43082013E06092A864886F70D010701301D060960864801650304012A04103DFF54DBCFD8FF2D47E699E8F6BB19FA8082011039253CF5D3B54503D1E50AE8F36452C1A9EEA379BF08AD3837D7D2776E5AD3982A2A234C8E0F76400F3A09BC80E9EDBF343F4B634CA4CDD42ACA81FC0C8358CB21A8B669FB7184F46A29CC499C24E7ED6E85B22D440FE2B60AA1ED387EC6BED6D5A0C8E938D0DBBE0C44AA2AC5A4C1435A63EA8B538D4AE4F44CF7F4ED0F681C81B9EEA54C9F66CC5C2D21EC18E3C58F97E44FFDDA489DADCF14E961FC27B6FF698B76591EC5B7A06F073EC6533E8D053A333748AC148B9D58DF5C6B03690BEA78F1E2775D0175F216DFCF4A922CB2B94697C78F74630D2C593E9D39A472F15E26362930E6A0594FA719FBFF331C0D9E327E2BE6279372E6BA8F757C530A5BA093089E2A9D9FDA49E18084CFF9D5D126#LOCAL_MACHINE\MY;chinaccs-mdssecurity-moniker#308202D906092A864886F70D010703A08202CA308202C60201003182017D308201790201003061304D310B300906035504061302555331153013060355040A130C446967694365727420496E63312730250603550403131E44696769436572742053484132205365637572652053657276657220434102100AC98491ADAD4F0779E3465DDCAF22FF300D06092A864886F70D0101073000048201008E49F877646C77C29DD62F40E77B384532FF227C3EB2E7BCF18D01249C25856FB3B4AA32F2A44484644B1D9DF3AED0EEA367436DCC41E00A708A27A4F0686C6B2ACDB39605DB204085351252908FDAF9EA7609F32D62D484AE50E61E76D68DABE1D58693C25E1C3014AD3C08626E30F327B79B16872CB4106E062B290086AABD34ED66918E81B4AC3978FAD4420A2B231330022BB82E9F86BFED57C6B926784ED500C94DB3808E008B4B49B5D22AF1F71D0FC5EAAADF3B7EDEFD190C32045316A6C13B351BBBC70E5461E4A6A00331D438A6CABF2B13010F08FB1ED91E6BF048B3485248560D5C36C1B309603AEF8560293D3ED029D4D4BA01BB75156A4E1BB33082013E06092A864886F70D010701301D060960864801650304012A0410CC26517ADA9C8EEB0B999BFF490D483480820110995336480EC8E2DC16B92B3C26981E4D82B5C39DC0057462672FA967CDB285AD6EE2B3FE43BC02A0759C784105BAB425257AC6C71DE0F1A8ED025604D56A97E6962819FF8FE1C94D4C0A259CC950E5B859EAB2E8376B802B8A3A5EF26A36EC1D494EC23E5E112F64ECC8D873CAC290ADE4F24CE37F8C1F2AE1A17FAA4E4851FB8007936AE93A5720A3754915A84196151F3B604DFBC16D0A116B6E5940D6AE71758F6ADA83F31D8BA80413A9AB0986BA3F0F72B15A1DB8EE8A0EFFE60C5085B86F429C9838916F837BF5356091C985C3B01DAC2C1CC523981B2685FEA79DB320AC8549CF8680061BB3CADA3CA7ED272D917AD0DF7B8EDDB6D61B53532BE28EDE80D4726E5A41221C64EDB9CBD5518AA4#LOCAL_MACHINE\MY",
                ////    @"chinaccs-mds-moniker#308202D906092A864886F70D010703A08202CA308202C60201003182017D308201790201003061304D310B300906035504061302555331153013060355040A130C446967694365727420496E63312730250603550403131E44696769436572742053484132205365637572652053657276657220434102100AC98491ADAD4F0779E3465DDCAF22FF300D06092A864886F70D01010730000482010064E45150CA07DFE90B8738FFB56207AEA268CC41FC8298152C89051356A6E0EB79BDC99C8CE643D29926F1066E4912588B80B1C788B7F20FAE43B792AD9D86D341BE44B6E9BCF4AA310BA5C41588DF266BFB06CD871B3DA899EEB494C8F9BA41D96D4E0A4B6FB13FD4A14C1E5261035938179586C016353DB42CDD64D3368C4AD07A388F70261AC1E2BD4B793A5C4BC69FC0C2A9B0D046B1908C16E303E99ECAD06C3BB7E8ECB6B7AF88DCFF59C41F1F4B7BF499BA51D61A47850006A51ACD54ECE081B65E735A5497B9A970696E01E65EE33F7D96DD878CB30B8622525942FC452970B9AD34C7EA7C6307928E5A4DF51B698337184412BFE574C15A822C857F3082013E06092A864886F70D010701301D060960864801650304012A041085992965196185C6E08F789416546C81808201109D926AC20BDDE55BDDD5CC91E6CE2CC7BA80A88F039CFDE6476E69DA4A92D8A93534FFA42A7818478249888C521C80D670F800AC6328DC19165ECFD1547237C78D8CDE188C5AC93C4CE60A05F8AEBC0D557369D3D06A22B5F8E6BBF1488632963B520136310AA8ED461E1DE28BD067D479888F1E6A43BEEEED234040C6A04ADE3B1E5B01A173BCEF4C876DCCBB5921D6FAD3795EABA725246F825DDA9350E7A678F94486FA49261218075430BED9AF207C552CD1371284035165C38633A6032129F09004C1A3024C707CA9CD356C092390DE446C6B5FCA7A00A9E192D208D3886097157ED2DB757F909962BCD0F08A853914ADB52B628C98D53E155953EB872EF933CD71B252F9ECD7459E720D076EE4#LOCAL_MACHINE\MY;chinaccs-mdsaudit-moniker#308202D906092A864886F70D010703A08202CA308202C60201003182017D308201790201003061304D310B300906035504061302555331153013060355040A130C446967694365727420496E63312730250603550403131E44696769436572742053484132205365637572652053657276657220434102100AC98491ADAD4F0779E3465DDCAF22FF300D06092A864886F70D0101073000048201001EF42642A22A63C86BD78E7C05DC2CB33F4ADB018336B024E3E0EAE5DA2372F87CD22624462920A62B979FDA15EC94FE8C38F42397D2CF7641867E56C603E17F199171CCD011C603889D76DFDC087426FD6C06C4EAF553A82122EE921A11C166AFF9F43A2F4FF3A80281383E5E1D710F10EEA2EA2BCF9DBF4A82A83A35CABF5DD3612B3E9C975B035E473B4B9ADC70116C0A0D1C547EF3ACA040964CB22FE5732E034136C9D4AD790612E2262D5BD3D9420ABE2B8F5E29701A824D3B443ED53B89AC3F60CD5CA43D4D2771DAE26FBB5ADC05523A1E7D4E93153A6A7929ACD032B9A2F3E837B9D460FC0B1CC146E2CFE838837DCCABA1C639EEE32C51390120C43082013E06092A864886F70D010701301D060960864801650304012A04103DFF54DBCFD8FF2D47E699E8F6BB19FA8082011039253CF5D3B54503D1E50AE8F36452C1A9EEA379BF08AD3837D7D2776E5AD3982A2A234C8E0F76400F3A09BC80E9EDBF343F4B634CA4CDD42ACA81FC0C8358CB21A8B669FB7184F46A29CC499C24E7ED6E85B22D440FE2B60AA1ED387EC6BED6D5A0C8E938D0DBBE0C44AA2AC5A4C1435A63EA8B538D4AE4F44CF7F4ED0F681C81B9EEA54C9F66CC5C2D21EC18E3C58F97E44FFDDA489DADCF14E961FC27B6FF698B76591EC5B7A06F073EC6533E8D053A333748AC148B9D58DF5C6B03690BEA78F1E2775D0175F216DFCF4A922CB2B94697C78F74630D2C593E9D39A472F15E26362930E6A0594FA719FBFF331C0D9E327E2BE6279372E6BA8F757C530A5BA093089E2A9D9FDA49E18084CFF9D5D126#LOCAL_MACHINE\MY;chinaccs-mdssecurity-moniker#308202D906092A864886F70D010703A08202CA308202C60201003182017D308201790201003061304D310B300906035504061302555331153013060355040A130C446967694365727420496E63312730250603550403131E44696769436572742053484132205365637572652053657276657220434102100AC98491ADAD4F0779E3465DDCAF22FF300D06092A864886F70D0101073000048201008E49F877646C77C29DD62F40E77B384532FF227C3EB2E7BCF18D01249C25856FB3B4AA32F2A44484644B1D9DF3AED0EEA367436DCC41E00A708A27A4F0686C6B2ACDB39605DB204085351252908FDAF9EA7609F32D62D484AE50E61E76D68DABE1D58693C25E1C3014AD3C08626E30F327B79B16872CB4106E062B290086AABD34ED66918E81B4AC3978FAD4420A2B231330022BB82E9F86BFED57C6B926784ED500C94DB3808E008B4B49B5D22AF1F71D0FC5EAAADF3B7EDEFD190C32045316A6C13B351BBBC70E5461E4A6A00331D438A6CABF2B13010F08FB1ED91E6BF048B3485248560D5C36C1B309603AEF8560293D3ED029D4D4BA01BB75156A4E1BB33082013E06092A864886F70D010701301D060960864801650304012A0410CC26517ADA9C8EEB0B999BFF490D483480820110995336480EC8E2DC16B92B3C26981E4D82B5C39DC0057462672FA967CDB285AD6EE2B3FE43BC02A0759C784105BAB425257AC6C71DE0F1A8ED025604D56A97E6962819FF8FE1C94D4C0A259CC950E5B859EAB2E8376B802B8A3A5EF26A36EC1D494EC23E5E112F64ECC8D873CAC290ADE4F24CE37F8C1F2AE1A17FAA4E4851FB8007936AE93A5720A3754915A84196151F3B604DFBC16D0A116B6E5940D6AE71758F6ADA83F31D8BA80413A9AB0986BA3F0F72B15A1DB8EE8A0EFFE60C5085B86F429C9838916F837BF5356091C985C3B01DAC2C1CC523981B2685FEA79DB320AC8549CF8680061BB3CADA3CA7ED272D917AD0DF7B8EDDB6D61B53532BE28EDE80D4726E5A41221C64EDB9CBD5518AA4#LOCAL_MACHINE\MY",
                ////    @"chinaccs-mds-moniker#308202C906092A864886F70D010703A08202BA308202B60201003182017D308201790201003061304D310B300906035504061302555331153013060355040A130C446967694365727420496E63312730250603550403131E44696769436572742053484132205365637572652053657276657220434102100AC98491ADAD4F0779E3465DDCAF22FF300D06092A864886F70D0101073000048201006DB41A50909D45D70013B185A4B48D619699A35F69F3F210ACB754CBA91DCAD7BEF2C68861442BB9C3104CA49CE516D6A3B17A2B15437E2907913EEFCFD2ADD84E3BC984D50433E33192FBC1B21000D228188411A5722D40BEC8745BA6A6CE525818F11FE42FC76FCF26297C22B7AC1578050F716A390F3315E54BCB35D34764B9D3B2807DEEA16075318CD38AFB07607A2909A462B861CD4002F26B9549D3E4AB8A7C0613A0B4717F037F61E8A1965D91B39F77D28F5F74C716FB5EDCEC5515151A84A778B030683678DA331A1533CAFF146E5CC99DC37095ACF43FB4840D5C543D7BCEF45E149C94D0D1D9047153673FD8ACA0EDF541E342FF7B2AD887BDC83082012E06092A864886F70D010701301D060960864801650304012A0410266A3B247D2242EBEDE74588C026E3D680820100935D3255DA8D542DD0185BEDB51CA1EE1937B5F79676ED4E1005AB32C698363C05F7E1FFFEC65981CC2F468A5C55EFEB56CA05A734312503FDA1FCCBA5D76E0D6A706DFCFD694072D51A592D66EE8126F41F8263CE26D0A4129FFFE479642448C9729C74E87CFDD5C0F48C9ED3669EFAE5BB24E4657DF9ECE3160ADAD349CAD07F5A220723CBE8923A6FBAAE6C4191CAD3D16688026EBDEEEF178C8549E7063C4DEA3C616D464A15B18157E24588B0A14FCE15A1B516A2A9475E9CD092C0B77D3BB685C530694E1E6DE719D8171E282E502E315200842E3E8E82DCE40BD4DBF1AA18682AEB946A78D1634CAC2EE4B4D3CDF82683836E4C1192FB4BA5B35BAF64#LOCAL_MACHINE\MY;chinaccs-mdsaudit-moniker#308202D906092A864886F70D010703A08202CA308202C60201003182017D308201790201003061304D310B300906035504061302555331153013060355040A130C446967694365727420496E63312730250603550403131E44696769436572742053484132205365637572652053657276657220434102100AC98491ADAD4F0779E3465DDCAF22FF300D06092A864886F70D01010730000482010064091D2FBA55B3E317E1858E510E16615A6A0B0D8A7390A7346B287CAAD45C417E0E43079862C3FCA71E2BACC91E33BD83D6A80308AFC0754E5481780E60BEEAEA2004F03D9A2A8CC8A3F4939A889290572F4C45A3BE400940D19A7801DA48F06009BFDFBCAA187B8506FAA605ED0C3FAAC07CE960023C224D480AC33DBC3BA4F476934DEC55B34703AC197914551C99103A229877642D1F5EE65D45D5C32071320457F5D44758006E6EA55F5E4908BD89D395CFDB0CDE8B75AD504E0F24F3D438573BE321D9ED9A40A0A1B23EDA74602BF1DC52F3FB7786994560F51DBF126D37081A3845AF92184B5E0097857E34965091D29749111722B8D180EC93E7B5023082013E06092A864886F70D010701301D060960864801650304012A0410C57BBB1E0FD4A571F23D28B6D1DE516F808201106084C37FD9B79D8811D34980DFB7758B68C5739FBB16683459580D6D39D53675C25FEE64E86843CB474C1369A066D38A75D307E556DFC15300A61B959532FF29D9B7BD793E57928D7057B51BEF2F32AFA50F686B16D89AB9D07525DB514A83FB48D4C33A44E96A188F08DD7AA0B772ED619570E68F100D2E724D9C95B25B1D9DE8B0FE31C301BFF2D94BD4371783B7FBFD2FDB185973F016F6283F1E0F689478BDF1738B7ACB26BB562E2C88CA37F49B238145C97DD7F536933AC7F19DFAC9A9F742B02DE9FBCC66B4FCAC89698677830AB8F727CA3F1927A439A8E6B653E7D8285896C0E51E080F1029AC1C61E4F713F58DB38BE9BEF4CF99AAF1E016FE5B3A168F586F8BAC3D01F1A0964333CE3515#LOCAL_MACHINE\MY;chinaccs-mdssecurity-moniker#308202D906092A864886F70D010703A08202CA308202C60201003182017D308201790201003061304D310B300906035504061302555331153013060355040A130C446967694365727420496E63312730250603550403131E44696769436572742053484132205365637572652053657276657220434102100AC98491ADAD4F0779E3465DDCAF22FF300D06092A864886F70D01010730000482010089FBDC80D2A3138B739FDECE47C74462BF4A97FC3042DCB0CBD3D9C6EBAD57E080E8D2C7D6256BEB1D09BC8054CE1ABC3485BBCDBCE39039BFD2D00C6EF5BE90B2A7FC4C701F447CDF7795602891992705D9BB5039FD13459D9F4B80F0C7744B4583766ECF49B5121A693CA181ECD4DF9349368C7E0972D08DE39A3CEF7CF37C8E9F5FB088E5213735B82169028B91F1FE618FF6B1E64F6171AE32DDD066A059934717ADD369FF733695C8686AAFA7EB7481815BA3A4E4AFE155E852A37A2FEFDAE2ADBC11A7C86A87D8C701485128D663B8BE1B6F72136AC973EAE09050D969E475DBF73549DB908C1E02E1BD35369B1CEA7E5A92DA19B00ECE21FDA98E8D893082013E06092A864886F70D010701301D060960864801650304012A0410A415708D001D4F84D021DF02248C86FC808201103DDBF835A1CE865CE7EB1F199CA4EE7EB2063BEB6D15E7C6AB853EB4E0919CFECC6752A92FD38BB7E3A328E54283784E0F7A24D74E2ED8433C50E4BA464B113A19489A7B4EB3B18BC09C80E30F0F3C2C1D31FA8537D1F0C4406F15C02A7DE28A5139465D9EF61B2126FD4789F4DB1E61E655E3C8E6BDFD8AAE8E75269DF823B9886D9EDB8B0928C80F0845A4DC929C300CA47B53257AA40D9ED0BA7E12FE69B330AC7B2BC992DCB95ED21D631145E4C86F2FD3E82D753B130CA7E5BFC09C537DE0164D998AE3826EC4AEF7DD12B644CF5B24BCC75FA3F49230FBD6B69ECED2A504F6150FC5732EC80C4DC99C53FC56AF990DE6C08D5522D7825B56B12832FF23B7CFE88AA00F808DB053847A07BF0DA8#LOCAL_MACHINE\MY",
                ////};

                ////for (int i = 0; i < 3; i++)
                ////{
                ////    WriteSecret(secretNames[i], secretValues[i], dstKvInfo, overwriteExisting);
                ////}

                //KeyVaultSettingInfo deleteKvInfo = PrepareSrcKeyVaultInfo();
                //DeleteCertificates(
                //    srcKvInfo,
                //    x => ccsProdCertNames.Contains(x.Identifier.Name));

                //KeyVaultSettingInfo deleteKvInfo = new KeyVaultSettingInfo
                //{
                //    Url = "https://mccdn-prod-savecustomer.vault.azure.cn/",
                //    ClientId = "e5853e7a-fb1d-439d-ac66-ca22b1054fc4",
                //    CertificateThumbprint = "0ed3c86cda68e9f087a93ec25b95b7c71cb86ae6",
                //};
                //KeyVaultSettingInfo deleteKvInfo = srcKvInfo;
                //DeleteSecrets(deleteKvInfo, IsGuidSecret);
                //DeleteSecrets(deleteKvInfo, x => true);

                //ReadAndProcessSecretStoreCertificate();

                //BackupCustomerCertificates();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
        }

        private static void BackupCustomerCertificates()
        {

            KeyVaultSettingInfo srcKvInfo = PredefinedKeyVaults["mccdnprod"];

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

        private static void ReadAndProcessSecretStoreCertificate()
        {
            int prefixLength = "mccdn/cert/".Length;
            int postfixLength = ".pfx".Length;
            string[] lines = File.ReadAllLines(@"d:\temp\secretstore\srccert.txt");
            var results = lines.Where(x => !string.IsNullOrWhiteSpace(x))
                 .ToList()
                 .Select(x => new Tuple<string, string>(x, x.Substring(prefixLength, x.Length - prefixLength - postfixLength).Replace('.', '-')))
                 .Select(x => string.Format("{0}\t{1}", x.Item1, x.Item2))
                 .ToArray();

            File.WriteAllLines(@"d:\temp\secretstore\dstcert.txt", results);
        }

        private static bool IsGuidSecret(SecretItem cert)
        {
            return !IsNotGuidName(cert.Identifier.Name);
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

        private static void WriteSecret(string secretName, string secretValue, KeyVaultSettingInfo dstKvInfo, bool overwirteExisting = false)
        {
            KeyVaultAccess dstkv = new KeyVaultAccess(dstKvInfo.Url, dstKvInfo.AADInfo);
            dstkv.WriteSecret(secretName, secretValue, overwirteExisting).Wait();
        }

        private static void ListSecrets(KeyVaultSettingInfo kvInfo, Predicate<SecretItem> match)
        {
            Console.WriteLine("List Secrets for key vault {0}...", kvInfo);

            KeyVaultAccess kv = new KeyVaultAccess(kvInfo);
            var allCredentials = kv.DownloadSecretsAndCerts(match).Result;
            Console.WriteLine($"Total credentials: {allCredentials.Count()}");
            foreach (var credential in allCredentials)
            {
                bool isCert = credential.ContentType == CertificateContentType.Pem;
                string value = isCert ? "<cert>" : credential.Value;
                Console.WriteLine($"Name: {credential.Name}, ContentType: {credential.ContentType}, NotBefore: {credential.NotBefore}, Expires: {credential.Expires}, Value: {value}");
            }
        }

        private static void ListCertificates(KeyVaultSettingInfo kvInfo, Predicate<CertificateItem> isMatched)
        {
            Console.WriteLine("List Certificates for key vault {0}...", kvInfo);

            KeyVaultAccess kv = new KeyVaultAccess(kvInfo);
            var allCertificates = kv.GetAllCertificates().Result;
            List<CertificateItem> certs = allCertificates.Where(x => isMatched(x)).ToList();

            Console.WriteLine($"Total Certificates: {allCertificates.Count}");
            Console.WriteLine($"Matched Certificates: {certs.Count}");
            foreach (var cert in certs)
            {
                string thumbprint = BitConverter.ToString(cert.X509Thumbprint).Replace("-", "");
                Console.WriteLine($"Name: {cert.Id}, Thumbprint: {thumbprint}， NotBefore: {cert.Attributes.NotBefore}, Expires: {cert.Attributes.Expires}");
            }
        }

        private static void CopySecrets(KeyVaultSettingInfo srcKvInfo, KeyVaultSettingInfo dstKvInfo, Predicate<SecretItem> isMatched, bool overwriteExisting = false)
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


        private static void DeleteSecrets(KeyVaultSettingInfo deleteKvInfo, Predicate<SecretItem> isMatchedSecret)
        {
            Console.WriteLine("DeteleSecrets for givin key vault {0}, press any key to continue...", deleteKvInfo);
            Console.ReadKey();

            KeyVaultAccess kv = new KeyVaultAccess(deleteKvInfo);
            kv.DeleteAllSecrets(isMatchedSecret).Wait();
        }

        private static void DeleteCertificates(KeyVaultSettingInfo deleteKvInfo, Predicate<CertificateItem> isMatched)
        {
            Console.WriteLine("DeteleCertificates for givin key vault {0}, press any key to continue...", deleteKvInfo);
            Console.ReadKey();

            KeyVaultAccess kv = new KeyVaultAccess(deleteKvInfo);
            kv.DeleteAllCertificates(isMatched).Wait();
        }

        private static void DisableCertificate(KeyVaultSettingInfo disableKvInfo, Predicate<CertificateItem> predict)
        {
            Console.WriteLine("DisableCertificates for givin key vault {0}, press any key to continue...", disableKvInfo);
            Console.ReadKey();

            KeyVaultAccess kv = new KeyVaultAccess(disableKvInfo);
            kv.DisableAllCertificates(predict).Wait();
        }

        private static void CopyCertificates(KeyVaultSettingInfo srcKvInfo, KeyVaultSettingInfo dstKvInfo, Predicate<CertificateItem> isMatched, bool overwriteExisting = false)
        {
            Console.WriteLine("CopyCertificates from key vault {0} to {1}, overwrite existing: {2}, press any key to continue...", srcKvInfo, dstKvInfo, overwriteExisting);
            Console.ReadKey();

            KeyVaultAccess srckv = new KeyVaultAccess(srcKvInfo);

            var certs = srckv.DownloadCertificates(isMatched).Result.ToList();

            KeyVaultAccess dstkv = new KeyVaultAccess(dstKvInfo);
            dstkv.ImportCertificates(certs, overwriteExisting).Wait();
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
            var kvInfo = PredefinedKeyVaults["mccdn-prodsecrets-holder"];

            KeyVaultAccess kv = new KeyVaultAccess(kvInfo);
            var secret = kv.GetSecret("CertificateRepositoryKeyVaultClientSecret");
            return secret;
        }

        private static KeyVaultSettingInfo PrepareDstKeyVaultInfo()
        {
            //return PredefinedKeyVaults["mccdn-prodsecrets-holder"];
            //return PredefinedKeyVaults["mccdnintkvn2"];
            //return PredefinedKeyVaults["mccdncoreconfig"];
            return PredefinedKeyVaults["mccdnkeyvault"];
            //return PredefinedKeyVaults["mccdn-prodv2-holder"];
        }

        private static KeyVaultSettingInfo PrepareSrcKeyVaultInfo()
        {
            return PredefinedKeyVaults["mccdndeployprodv2-cme"];
            //return PredefinedKeyVaults["mccdndeployprod-cme"];
            //return PredefinedKeyVaults["mccdn-prodsecrets-holder"];
            //return PredefinedKeyVaults["mccdnkeyvault"];
            //return PredefinedKeyVaults["mccdndeploytest-cme"];
        }

        private static readonly Dictionary<string, AADSettingInfo> PredefinedAADInfo = new Dictionary<string, AADSettingInfo>()
            .AddAADSettingInfo("KeyVaultMcCdnDeployProdCMEByCertApp3", "acd70671-bc7d-450d-8cc3-02c1f98d0561", "FE7A56C1DC4F91E7A2BA216C8464AB50AF29FB25")
            .AddAADSettingInfo("KeyVaultMcCdnDeployTestByCertApp", "e5853e7a-fb1d-439d-ac66-ca22b1054fc4", "0ed3c86cda68e9f087a93ec25b95b7c71cb86ae6")
            .AddAADSettingInfo("KeyVaultMcCdnDeployProdCMEByCertApp2", "5c83117e-eb3b-40c2-9afc-545893059b36", "FE7A56C1DC4F91E7A2BA216C8464AB50AF29FB25")
            .AddAADSettingInfo("KeyVaultMcCdnDeployProdByCertApp2", "000be46d-6e2e-4ab9-b6f4-996e4d1e834d", "FE7A56C1DC4F91E7A2BA216C8464AB50AF29FB25")
            .AddAADSettingInfo("KeyVaultMcCCSDeployProdCMEByCertApp3", "9a1a38f5-a221-4d21-9f3b-7655665f33fa", "FE7A56C1DC4F91E7A2BA216C8464AB50AF29FB25")
            .AddAADSettingInfo("mccdn-keyvault-reader", "d144f18e-c146-4d94-b9de-8f942bd30ccf", null, true, KeyvaultReaderSecretRetriever);

        private static readonly Dictionary<string, KeyVaultSettingInfo> PredefinedKeyVaults = new Dictionary<string, KeyVaultSettingInfo>()
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

    private static void ReadTestSecret()
        {

        //string kvUrl = args[0];
        //string clientId = args[1];
        //string certThumbprint = args[2];
        string kvUrl = "https://CdnHttpsAuto1190602555.vault.azure.cn";

            // for Baishan cert
            //string clientId = "cecc735b-4cfd-48b4-b005-23f21cd507d6";
            //string certThumbprint = "0A9FA76B81E10DF0514AE89E5DD0FED945647E6C";

            //for CDN cert
            string clientId = "e5853e7a-fb1d-439d-ac66-ca22b1054fc4";
            string certThumbprint = "0ed3c86cda68e9f087a93ec25b95b7c71cb86ae6";
            KeyVaultAccess kv = new KeyVaultAccess(kvUrl, clientId, certThumbprint, false, null);

            string clientToCDN_KeyVersion = kv.GetSecret("ClientToCDNAuthKeyVersion");
            string clientToCDN_Key = kv.GetSecret("ClientToCDNAuthKey");

            string cdnToOrigin_AccessKey = kv.GetSecret("CDNToOriginAuthAccessKey");
            string cdnToOrigin_SecretKey = kv.GetSecret("CDNToOriginAuthSecretKey");

            Console.WriteLine("# Client to cdn authentication");
            Console.WriteLine("key version = {0}", clientToCDN_KeyVersion);
            Console.WriteLine("key = \"{0}\"", clientToCDN_Key);

            Console.WriteLine();
            Console.WriteLine("#CDN to origin authentication");
            Console.WriteLine("access_key = \"{0}\"", cdnToOrigin_AccessKey);
            Console.WriteLine("secret_key = \"{0}\"", cdnToOrigin_SecretKey);
        }
    }

    public static class MyExtension
    {
        public static Dictionary<string, AADSettingInfo> AddAADSettingInfo(
            this Dictionary<string, AADSettingInfo> dict,
            string aadName,
            string clientId,
            string certThumbrpint,
            bool useSecret = false,
            Func<string> secretRetriever = null)
        {
            var info = GenerateAADSettingInfo(aadName, clientId, certThumbrpint, useSecret, secretRetriever);
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
            bool useSecret, Func<string> secretRetriever)
        {
            return new KeyValuePair<string, AADSettingInfo>(
                aadName,
                new AADSettingInfo
                {
                    Name = aadName,
                    ClientId = clientId,
                    CertificateThumbprint = certThumbprint,
                    UseSecret = useSecret,
                    SecretRetriever = secretRetriever,
                });
        }

    }
}
