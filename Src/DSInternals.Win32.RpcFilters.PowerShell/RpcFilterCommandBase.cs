using System.Management.Automation;

namespace DSInternals.Win32.RpcFilters.PowerShell;

public abstract class RpcFilterCommandBase : PSCmdlet, IDisposable
{
    protected RpcFilterManager? RpcFilterManager { get; private set; }

    protected override void BeginProcessing()
    {
        base.BeginProcessing();

        try
        {
            this.RpcFilterManager = new RpcFilterManager();
        }
        catch(Exception ex)
        {
            this.ThrowTerminatingError(new ErrorRecord(ex, "RpcFilterManagerInitializationFailed", ErrorCategory.ConnectionError, null));
        }
    }

    protected override void ProcessRecord()
    {
        base.ProcessRecord();

        if (this.RpcFilterManager == null)
        {
            this.ThrowTerminatingError(new ErrorRecord(new InvalidOperationException("RpcFilterManager is not initialized."), "RpcFilterManagerNotInitialized", ErrorCategory.InvalidOperation, null));
        }
    }

    protected override void EndProcessing()
    {
        this.Dispose();
        base.EndProcessing();
    }

    public void Dispose()
    {
        this.RpcFilterManager?.Dispose();
        this.RpcFilterManager = null;
    }
}
