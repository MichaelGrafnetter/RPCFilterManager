namespace DSInternals.Win32.RpcFilters.Tests;

[TestClass]
public class WellKnownProtocolTranslatorTester
{
    [TestMethod]
    public void WellKnownProtocolTranslator_ToInterfaceUUID_NonExisting()
    {
        WellKnownProtocol dummyValue = (WellKnownProtocol)int.MaxValue;

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() =>
        {
            dummyValue.ToInterfaceUUID();
        });
    }

    [TestMethod]
    public void WellKnownProtocolTranslator_ToInterfaceUUID_DRSR()
    {
        Assert.AreEqual(
            new Guid("e3514235-4b06-11d1-ab04-00c04fc2dcd2"),
            WellKnownProtocol.DirectoryReplicationService.ToInterfaceUUID()
        );
    }

    [TestMethod]
    public void WellKnownProtocolTranslator_ToProtocolName_Null()
    {
        Guid? nullGuid = null;
        Assert.IsNull(nullGuid.ToProtocolName());
    }

    [TestMethod]
    public void WellKnownProtocolTranslator_ToProtocolName_NonExisting()
    {
        string randomGuidString = "436ca5e4-54c6-40d6-96b9-9cc9c8783963";
        Guid? randomGuid = new(randomGuidString);

        // Test all parameter combinations
        Assert.AreEqual(randomGuidString, randomGuid.ToProtocolName());
        Assert.AreEqual(randomGuidString, randomGuid.ToProtocolName(false));
        Assert.AreEqual(randomGuidString, randomGuid.ToProtocolName(true));
    }

    [TestMethod]
    public void WellKnownProtocolTranslator_ToProtocolName_DRSR()
    {
        Guid? drsuapi = new("e3514235-4b06-11d1-ab04-00c04fc2dcd2");

        // Test all parameter combinations
        Assert.AreEqual("MS-DRSR (drsuapi)", drsuapi.ToProtocolName());
        Assert.AreEqual("MS-DRSR (drsuapi)", drsuapi.ToProtocolName(false));
        Assert.AreEqual("MS-DRSR (drsuapi) - {e3514235-4b06-11d1-ab04-00c04fc2dcd2}", drsuapi.ToProtocolName(true));
    }

    [TestMethod]
    public void WellKnownProtocolTranslator_ToOperationNumber_NonExisting()
    {
        WellKnownOperation dummyValue = (WellKnownOperation)int.MaxValue;

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() =>
        {
            dummyValue.ToOperationNumber();
        });
    }

    [TestMethod]
    public void WellKnownProtocolTranslator_ToOperationNumber_IDL_DRSGetNCChanges()
    {
        (WellKnownProtocol protocol, ushort operationNumber) = WellKnownOperation.IDL_DRSGetNCChanges.ToOperationNumber();
        Assert.AreEqual(WellKnownProtocol.DirectoryReplicationService, protocol);
        Assert.AreEqual(3, operationNumber);
    }

    [TestMethod]
    public void WellKnownProtocolTranslator_ToOperationName_IDL_DRSGetNCChanges()
    {
        Guid? drsuapi = new Guid("e3514235-4b06-11d1-ab04-00c04fc2dcd2");

        Assert.AreEqual("IDL_DRSGetNCChanges (3)", WellKnownProtocolTranslator.ToOperationName(drsuapi, 3));
        Assert.AreEqual("IDL_DRSGetNCChanges (3)", WellKnownProtocolTranslator.ToOperationName(drsuapi, 3, true));
        Assert.AreEqual("IDL_DRSGetNCChanges", WellKnownProtocolTranslator.ToOperationName(drsuapi, 3, false));
    }

    [TestMethod]
    public void WellKnownProtocolTranslator_ToOperationName_UnknownOperation()
    {
        Guid? drsuapi = new Guid("e3514235-4b06-11d1-ab04-00c04fc2dcd2");
        ushort dummyOperationNumber = 12345;

        Assert.AreEqual("12345", WellKnownProtocolTranslator.ToOperationName(drsuapi, dummyOperationNumber));
        Assert.AreEqual("12345", WellKnownProtocolTranslator.ToOperationName(drsuapi, dummyOperationNumber, false));
        Assert.AreEqual("12345", WellKnownProtocolTranslator.ToOperationName(drsuapi, dummyOperationNumber, true));
    }

    [TestMethod]
    public void WellKnownProtocolTranslator_ToOperationName_UnknownProtocol()
    {
        Guid? randomGuid = new("436ca5e4-54c6-40d6-96b9-9cc9c8783963");

        Assert.AreEqual("3", WellKnownProtocolTranslator.ToOperationName(randomGuid, 3));
        Assert.AreEqual("3", WellKnownProtocolTranslator.ToOperationName(randomGuid, 3, true));
        Assert.AreEqual("3", WellKnownProtocolTranslator.ToOperationName(randomGuid, 3, false));
    }

    [TestMethod]
    public void WellKnownProtocolTranslator_ToOperationName_UnknownBoth()
    {
        Guid? randomGuid = new("436ca5e4-54c6-40d6-96b9-9cc9c8783963");
        ushort dummyOperationNumber = 12345;

        Assert.AreEqual("12345", WellKnownProtocolTranslator.ToOperationName(randomGuid, dummyOperationNumber));
        Assert.AreEqual("12345", WellKnownProtocolTranslator.ToOperationName(randomGuid, dummyOperationNumber, true));
        Assert.AreEqual("12345", WellKnownProtocolTranslator.ToOperationName(randomGuid, dummyOperationNumber, false));
    }
}
