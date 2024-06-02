// See https://aka.ms/new-console-template for more information
using DSInternals.Win32.RpcFilters;

using (var fw = new RpcFilterManager())
{
    var filters = fw.GetFilters().ToList();
}
