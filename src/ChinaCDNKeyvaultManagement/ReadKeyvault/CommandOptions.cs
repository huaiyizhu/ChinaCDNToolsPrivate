using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CommandLine;

namespace ReadKeyvault
{
    public enum OperationType
    {
        list,

        get,

        update,

        delete,

        sync,
    }

    public enum OperationTarget
    {
        secret,

        certificate,
    }

    public class CommandOptions
    {
        const string keyvaultsString = "\r\nmccdn-prodsecrets-holder" +
                                       "\r\nmccdnkeyvault" +
                                       "\r\nmccdn-prodv2-holder" +
                                       "\r\nmccdndeployprodv2-cme" +
                                       "\r\nmccdndeployprod-cme" +
                                       "\r\nmccdnintkvn2";
        const string operationsString = "list, get, update, delete, sync";
        const string targetsString = "secret, certificate";

        [Option('o', "operation", Required = true, HelpText = "Operation type, can be following values: " + operationsString)]
        public OperationType Operation { get; set; }

        [Option('t', "target", Required = true, HelpText = "Operation target, can be following values: " + targetsString)]
        public OperationTarget Target { get; set; }

        [Option('s', "srckv", Required = true, HelpText = "Source key vaule name, can be following values: " + keyvaultsString)]
        public string SrcKeyVault { get; set; }

        [Option(
            'd',
            "dstkv", 
            Required = false, 
            HelpText = "Destination key vault name, can be following values: " + keyvaultsString)]
        public string DstKeyVault { get; set; }

        [Option('n', "name", Required = false, HelpText = "Operation Target Name")]
        public string TargetName { get; set; }

        [Option("force", Required = false, HelpText = "True to force override existing key vault values")]
        public bool OverrideIfExist { get; set; }
    }
}
