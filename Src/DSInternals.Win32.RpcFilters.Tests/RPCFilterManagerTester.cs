using System.ComponentModel;
using System.Net;

namespace DSInternals.Win32.RpcFilters.Tests;

[TestClass]
public class RPCFilterManagerTester
{
    [TestMethod]
    public void RPCFilterManager_List_Empty()
    {
        using var fw = new RpcFilterManager();
        var filters = fw.GetFilters();
        Assert.IsNotNull(filters);
        Assert.IsEmpty(filters.ToList());
    }

    [TestMethod]
    public void RPCFilterManager_Add_Filter1()
    {
        using var fw = new RpcFilterManager();

        // Define a dummy filter with as many conditions as possible
        var filter = new RpcFilter()
        {
            Name = "TestFilter",
            Description = "Test filter description",
            FilterKey = Guid.Parse("f95761b6-905e-4c31-8d3f-2d9d756ce298"),
            InterfaceUUID = Guid.Parse("338CD001-2244-31F1-AAAA-900038001003"),
            DcomAppId = Guid.Parse("10000000-0000-0000-0000-000000000002"),
            Transport = RpcProtocolSequence.ncacn_ip_tcp,
            NamedPipe = "\\PIPE\\winreg",
            SDDL = "D:(A;;CC;;;BA)",
            SecurityDescriptorNegativeMatch = true,
            Action = RpcFilterAction.Block,
            Audit = RpcFilterAuditOptions.Enabled,
            IsPersistent = true,
            AuthenticationLevel = RpcAuthenticationLevel.PacketPrivacy,
            AuthenticationLevelMatchType = NumericMatchType.LessThan,
            AuthenticationType = RpcAuthenticationType.Kerberos,
            IsBootTimeEnforced = false,
            Weight = 3,
            ImageName = "svchost.exe",
            LocalPort = 56345,
            RemoteAddress = IPAddress.Parse("fe80::bf1c:8c8e:f09d:c074"),
            OperationNumber = 25,
            LocalAddress = IPAddress.Parse("10.255.255.0"),
            LocalAddressMask = 24,
            InterfaceVersion = 1,
            InterfaceFlag = 2,
        };

        IList<RpcFilter> filters;

        // Create the filter
        ulong id = fw.AddFilter(filter);

        try
        {
            // Test the existence of the filter
            filters = [.. fw.GetFilters()];
            Assert.HasCount(1, filters);
            var createdFilter = filters.First();

            // Test that the filter has all the expected properties
            Assert.AreEqual(id, createdFilter.FilterId);
            Assert.AreEqual(filter.Name, createdFilter.Name);
            Assert.AreEqual(filter.Description, createdFilter.Description);

            Assert.AreEqual(filter.InterfaceUUID, createdFilter.InterfaceUUID);
            Assert.AreEqual(filter.FilterKey, createdFilter.FilterKey);
            Assert.AreEqual(filter.Transport, createdFilter.Transport);
            Assert.AreEqual(filter.DcomAppId, createdFilter.DcomAppId);
            Assert.AreEqual(filter.NamedPipe, createdFilter.NamedPipe);
            Assert.AreEqual(filter.Action, createdFilter.Action);
            Assert.AreEqual(filter.SDDL, createdFilter.SDDL);
            Assert.AreEqual(filter.SecurityDescriptorNegativeMatch, createdFilter.SecurityDescriptorNegativeMatch);
            Assert.AreEqual(filter.Audit, createdFilter.Audit);
            Assert.AreEqual(filter.IsPersistent, createdFilter.IsPersistent);
            Assert.AreEqual(filter.AuthenticationLevel, createdFilter.AuthenticationLevel);
            Assert.AreEqual(filter.AuthenticationLevelMatchType, createdFilter.AuthenticationLevelMatchType);
            Assert.AreEqual(filter.AuthenticationType, createdFilter.AuthenticationType);
            Assert.AreEqual(filter.IsBootTimeEnforced, createdFilter.IsBootTimeEnforced);
            Assert.AreEqual(filter.Weight, createdFilter.Weight);
            Assert.AreEqual(filter.ImageName, createdFilter.ImageName);
            Assert.AreEqual(filter.LocalPort, createdFilter.LocalPort);
            Assert.AreEqual(filter.RemoteAddress, createdFilter.RemoteAddress);
            Assert.AreEqual(filter.OperationNumber, createdFilter.OperationNumber);
            Assert.AreEqual(filter.LocalAddress, createdFilter.LocalAddress);
            Assert.AreEqual(filter.LocalAddressMask, createdFilter.LocalAddressMask);
            Assert.AreEqual(filter.InterfaceVersion, createdFilter.InterfaceVersion);
            Assert.AreEqual(filter.InterfaceFlag, createdFilter.InterfaceFlag);
        }
        finally
        {
            // Delete the filter
            fw.RemoveFilter(id);
        }

        // Check that no filter exist
        filters = [.. fw.GetFilters()];
        Assert.IsEmpty(filters);
    }

    [TestMethod]
    public void RPCFilterManager_List_RandomProviderKey()
    {
        Guid dummyProviderKey = new("1ea268da-4317-478e-aea9-f948f0d11b3b");

        using var fw = new RpcFilterManager();
        var filters = fw.GetFilters(dummyProviderKey);
        Assert.IsNotNull(filters);
        Assert.IsEmpty(filters.ToList());
    }

    [TestMethod]
    [ExpectedException(typeof(Win32Exception))]
    public void RPCFilterManager_Delete_NonExisting()
    {
        using var fw = new RpcFilterManager();
        fw.RemoveFilter(123456789);
    }

    [TestMethod]
    [ExpectedException(typeof(InvalidOperationException))]
    public void RPCFilterManager_Dispose_List()
    {
        var fw = new RpcFilterManager();
        fw.Dispose();
        fw.GetFilters().ToList();
    }

    [TestMethod]
    [ExpectedException(typeof(InvalidOperationException))]
    public void RPCFilterManager_Dispose_Delete()
    {
        var fw = new RpcFilterManager();
        fw.Dispose();
        fw.RemoveFilter(123456789);
    }

    [TestMethod]
    [ExpectedException(typeof(InvalidOperationException))]
    public void RPCFilterManager_Dispose_Add()
    {
        var fw = new RpcFilterManager();
        fw.Dispose();

        var filter = new RpcFilter()
        {
            Name = "TestFilter"
        };

        fw.AddFilter(filter);
    }

    [TestMethod]
    public void RPCFilterManager_Dispose_Twice()
    {
        var fw = new RpcFilterManager();
        fw.Dispose();
        fw.Dispose();
    }
}
