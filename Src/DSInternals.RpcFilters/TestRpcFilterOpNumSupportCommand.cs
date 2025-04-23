using System.Management.Automation;

namespace DSInternals.Win32.RpcFilters.PowerShell;

[Cmdlet(VerbsDiagnostic.Test, "RpcFilterOpNumSupport")]
[OutputType(typeof(bool))]
public class TestRpcFilterOpNumSupportCommand : PSCmdlet
{
    protected override void BeginProcessing()
    {
        base.BeginProcessing();

        this.WriteObject(RpcFilterManager.IsOpnumFilterSupported);
    }
}
