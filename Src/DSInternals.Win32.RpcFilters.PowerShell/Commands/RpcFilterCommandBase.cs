using System.Management.Automation;

namespace DSInternals.Win32.RpcFilters.PowerShell.Commands;

public abstract class RpcFilterCommandBase : PSCmdlet, IDisposable
{
    protected RpcFilterManager? RpcFilterManager { get; private set; }

    protected override void BeginProcessing()
    {
        base.BeginProcessing();

        try
        {
            RpcFilterManager = new RpcFilterManager();
        }
        catch (Exception ex)
        {
            ThrowTerminatingError(new ErrorRecord(ex, "RpcFilterManagerInitializationFailed", ErrorCategory.ConnectionError, null));
        }
    }

    protected override void ProcessRecord()
    {
        base.ProcessRecord();

        if (RpcFilterManager == null)
        {
            ThrowTerminatingError(new ErrorRecord(new InvalidOperationException("RpcFilterManager is not initialized."), "RpcFilterManagerNotInitialized", ErrorCategory.InvalidOperation, null));
        }
    }

    protected override void EndProcessing()
    {
        Dispose();
        base.EndProcessing();
    }

    public void Dispose()
    {
        GC.SuppressFinalize(this);

        RpcFilterManager?.Dispose();
        RpcFilterManager = null;
    }
}
