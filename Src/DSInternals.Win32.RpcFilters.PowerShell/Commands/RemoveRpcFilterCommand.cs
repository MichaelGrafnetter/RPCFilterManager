using System.Management.Automation;

namespace DSInternals.Win32.RpcFilters.PowerShell.Commands;

[Cmdlet(VerbsCommon.Remove, "RpcFilter", DefaultParameterSetName = ParameterSetById)]
[OutputType("None")]
public class RemoveRpcFilterCommand : RpcFilterCommandBase
{
    private const string ParameterSetById = "Id";
    private const string ParameterSetByInputObject = "InputObject";

    [Parameter(Mandatory = true, Position = 0, ParameterSetName = ParameterSetById, ValueFromPipelineByPropertyName = true)]
    [Alias("FilterId", "RpcFilter")]
    public ulong Id { get; set; }

    [Parameter(Mandatory = true, Position = 0, ParameterSetName = ParameterSetByInputObject, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    [Alias("Filter")]
    public RpcFilter? InputObject { get; set; }

    protected override void ProcessRecord()
    {
        base.ProcessRecord();

        ulong? filterId = ParameterSetName switch
        {
            ParameterSetById => Id,
            ParameterSetByInputObject => InputObject?.FilterId,
            _ => null // This should never happen
        };

        if (filterId.HasValue)
        {
            // TODO: Verbose message

#pragma warning disable CS8602 // Dereference of a possibly null reference.
            RpcFilterManager.RemoveFilter(filterId.Value);
#pragma warning restore CS8602 // Dereference of a possibly null reference.
        }
        else
        {
            WriteError(new ErrorRecord(new ArgumentNullException(nameof(RpcFilter.FilterId), "Could not determine the filter identifier."), "FilterIdIsNull", ErrorCategory.InvalidArgument, InputObject));
        }
    }
}
