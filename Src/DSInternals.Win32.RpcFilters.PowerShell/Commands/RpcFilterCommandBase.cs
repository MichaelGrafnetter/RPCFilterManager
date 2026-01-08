using System.Diagnostics.CodeAnalysis;
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

    [MemberNotNull(nameof(RpcFilterManager))]
    protected override void ProcessRecord()
    {
        base.ProcessRecord();

        if (RpcFilterManager == null)
        {
            var ex = new InvalidOperationException("RpcFilterManager is not initialized.");
            ThrowTerminatingError(new ErrorRecord(ex, "RpcFilterManagerNotInitialized", ErrorCategory.InvalidOperation, null));
            throw ex; // This will never be reached. Only to satisfy the compiler regarding nullability.
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
