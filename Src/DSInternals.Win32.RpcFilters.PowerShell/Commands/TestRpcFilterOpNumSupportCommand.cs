using System.Management.Automation;

namespace DSInternals.Win32.RpcFilters.PowerShell.Commands;

[Cmdlet(VerbsDiagnostic.Test, "RpcFilterOpNumSupport")]
[OutputType(typeof(bool))]
public class TestRpcFilterOpNumSupportCommand : PSCmdlet
{
    protected override void BeginProcessing()
    {
        base.BeginProcessing();

        WriteObject(RpcFilterManager.IsOpnumFilterSupported);
    }
}
