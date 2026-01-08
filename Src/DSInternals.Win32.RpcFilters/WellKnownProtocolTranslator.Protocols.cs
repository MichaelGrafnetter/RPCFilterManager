#pragma warning disable CA1707 // Identifiers should not contain underscores
#pragma warning disable CA1711 // Identifiers should not have incorrect suffix

namespace DSInternals.Win32.RpcFilters;

/// <summary>
/// Well-known RPC protocol translator.
/// </summary>
public static partial class WellKnownProtocolTranslator
{
    /// <summary>
    /// MimiCom: Mimikatz Remote Protocol
    /// </summary>
    private const string KIWI_UUID = "17fc11e9-c258-4b8d-8d07-2f4125156244";

    /// <summary>
    /// MimiCom: Mimikatz Remote Protocol
    /// </summary>
    public static readonly Guid KIWI = new(KIWI_UUID);

    /// <summary>
    /// MS-DCOM: Distributed Component Object Model (DCOM) Remote Protocol (IActivationPropertiesIn interface)
    /// </summary>
    private const string DCOM_IActivationPropertiesIn_UUID = "000001a2-0000-0000-c000-000000000046";

    /// <summary>
    /// MS-DCOM: Distributed Component Object Model (DCOM) Remote Protocol (IActivationPropertiesIn interface)
    /// </summary>
    public static readonly Guid DCOM_IActivationPropertiesIn = new(DCOM_IActivationPropertiesIn_UUID);

    /// <summary>
    /// MS-DCOM: Distributed Component Object Model (DCOM) Remote Protocol (IActivationPropertiesOut interface)
    /// </summary>
    private const string DCOM_IActivationPropertiesOut_UUID = "000001a3-0000-0000-c000-000000000046";

    /// <summary>
    /// MS-DCOM: Distributed Component Object Model (DCOM) Remote Protocol (IActivationPropertiesOut interface)
    /// </summary>
    public static readonly Guid DCOM_IActivationPropertiesOut = new(DCOM_IActivationPropertiesOut_UUID);

    /// <summary>
    /// MS-DCOM: Distributed Component Object Model (DCOM) Remote Protocol (IContext interface)
    /// </summary>
    private const string DCOM_IContext_UUID = "000001c0-0000-0000-c000-000000000046";

    /// <summary>
    /// MS-DCOM: Distributed Component Object Model (DCOM) Remote Protocol (IContext interface)
    /// </summary>
    public static readonly Guid DCOM_IContext = new(DCOM_IContext_UUID);

    /// <summary>
    /// MS-EPM: Endpoint Mapper Protocol
    /// </summary>
    private const string EPMAP_UUID = "e1af8308-5d1f-11c9-91a4-08002b14a0fa";

    /// <summary>
    /// MS-EPM: Endpoint Mapper Protocol
    /// </summary>
    public static readonly Guid EPMAP = new(EPMAP_UUID);

    /// <summary>
    /// MC-CCFG: Server Cluster: Configuration (ClusCfg) Protocol
    /// </summary>
    private const string CCFG_UUID = "52c80b95-c1ad-4240-8d89-72e9fa84025e";

    /// <summary>
    /// MC-CCFG: Server Cluster: Configuration (ClusCfg) Protocol
    /// </summary>
    public static readonly Guid CCFG = new(CCFG_UUID);

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostWritableAdminManager interface)
    /// </summary>
    private const string IISA_IAppHostWritableAdminManager_UUID = "fa7660f6-7b3f-4237-a8bf-ed0ad0dcbbd9";

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostWritableAdminManager interface)
    /// </summary>
    public static readonly Guid IISA_IAppHostWritableAdminManager = new(IISA_IAppHostWritableAdminManager_UUID);

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostPropertySchema interface)
    /// </summary>
    private const string IISA_IAppHostPropertySchema_UUID = "450386db-7409-4667-935e-384dbbee2a9e";

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostPropertySchema interface)
    /// </summary>
    public static readonly Guid IISA_IAppHostPropertySchema = new(IISA_IAppHostPropertySchema_UUID);

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostConfigLocationCollection interface)
    /// </summary>
    private const string IISA_IAppHostConfigLocationCollection_UUID = "832a32f7-b3ea-4b8c-b260-9a2923001184";

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostConfigLocationCollection interface)
    /// </summary>
    public static readonly Guid IISA_IAppHostConfigLocationCollection = new(IISA_IAppHostConfigLocationCollection_UUID);

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostMethodSchema interface)
    /// </summary>
    private const string IISA_IAppHostMethodSchema_UUID = "2d9915fb-9d42-4328-b782-1b46819fab9e";

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostMethodSchema interface)
    /// </summary>
    public static readonly Guid IISA_IAppHostMethodSchema = new(IISA_IAppHostMethodSchema_UUID);

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostSectionGroup interface)
    /// </summary>
    private const string IISA_IAppHostSectionGroup_UUID = "0dd8a158-ebe6-4008-a1d9-b7ecc8f1104b";

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostSectionGroup interface)
    /// </summary>
    public static readonly Guid IISA_IAppHostSectionGroup = new(IISA_IAppHostSectionGroup_UUID);

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostConstantValue interface)
    /// </summary>
    private const string IISA_IAppHostConstantValue_UUID = "0716caf8-7d05-4a46-8099-77594be91394";

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostConstantValue interface)
    /// </summary>
    public static readonly Guid IISA_IAppHostConstantValue = new(IISA_IAppHostConstantValue_UUID);

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostMethodInstance interface)
    /// </summary>
    private const string IISA_IAppHostMethodInstance_UUID = "b80f3c42-60e0-4ae0-9007-f52852d3dbed";

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostMethodInstance interface)
    /// </summary>
    public static readonly Guid IISA_IAppHostMethodInstance = new(IISA_IAppHostMethodInstance_UUID);

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostElementSchemaCollection interface)
    /// </summary>
    private const string IISA_IAppHostElementSchemaCollection_UUID = "0344cdda-151e-4cbf-82da-66ae61e97754";

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostElementSchemaCollection interface)
    /// </summary>
    public static readonly Guid IISA_IAppHostElementSchemaCollection = new(IISA_IAppHostElementSchemaCollection_UUID);

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostPropertySchemaCollection interface)
    /// </summary>
    private const string IISA_IAppHostPropertySchemaCollection_UUID = "8bed2c68-a5fb-4b28-8581-a0dc5267419f";

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostPropertySchemaCollection interface)
    /// </summary>
    public static readonly Guid IISA_IAppHostPropertySchemaCollection = new(IISA_IAppHostPropertySchemaCollection_UUID);

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostMethod interface)
    /// </summary>
    private const string IISA_IAppHostMethod_UUID = "7883ca1c-1112-4447-84c3-52fbeb38069d";

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostMethod interface)
    /// </summary>
    public static readonly Guid IISA_IAppHostMethod = new(IISA_IAppHostMethod_UUID);

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostChangeHandler interface)
    /// </summary>
    private const string IISA_IAppHostChangeHandler_UUID = "09829352-87c2-418d-8d79-4133969a489d";

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostChangeHandler interface)
    /// </summary>
    public static readonly Guid IISA_IAppHostChangeHandler = new(IISA_IAppHostChangeHandler_UUID);

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostConstantValueCollection interface)
    /// </summary>
    private const string IISA_IAppHostConstantValueCollection_UUID = "5b5a68e6-8b9f-45e1-8199-a95ffccdffff";

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostConstantValueCollection interface)
    /// </summary>
    public static readonly Guid IISA_IAppHostConstantValueCollection = new(IISA_IAppHostConstantValueCollection_UUID);

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostAdminManager interface)
    /// </summary>
    private const string IISA_IAppHostAdminManager_UUID = "9be77978-73ed-4a9a-87fd-13f09fec1b13";

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostAdminManager interface)
    /// </summary>
    public static readonly Guid IISA_IAppHostAdminManager = new(IISA_IAppHostAdminManager_UUID);

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostProperty interface)
    /// </summary>
    private const string IISA_IAppHostProperty_UUID = "ed35f7a1-5024-4e7b-a44d-07ddaf4b524d";

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostProperty interface)
    /// </summary>
    public static readonly Guid IISA_IAppHostProperty = new(IISA_IAppHostProperty_UUID);

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostConfigException interface)
    /// </summary>
    private const string IISA_IAppHostConfigException_UUID = "4dfa1df3-8900-4bc7-bbb5-d1a458c52410";

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostConfigException interface)
    /// </summary>
    public static readonly Guid IISA_IAppHostConfigException = new(IISA_IAppHostConfigException_UUID);

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostConfigLocation interface)
    /// </summary>
    private const string IISA_IAppHostConfigLocation_UUID = "370af178-7758-4dad-8146-7391f6e18585";

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostConfigLocation interface)
    /// </summary>
    public static readonly Guid IISA_IAppHostConfigLocation = new(IISA_IAppHostConfigLocation_UUID);

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostElementCollection interface)
    /// </summary>
    private const string IISA_IAppHostElementCollection_UUID = "c8550bff-5281-4b1e-ac34-99b6fa38464d";

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostElementCollection interface)
    /// </summary>
    public static readonly Guid IISA_IAppHostElementCollection = new(IISA_IAppHostElementCollection_UUID);

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostChildElementCollection interface)
    /// </summary>
    private const string IISA_IAppHostChildElementCollection_UUID = "08a90f5f-0702-48d6-b45f-02a9885a9768";

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostChildElementCollection interface)
    /// </summary>
    public static readonly Guid IISA_IAppHostChildElementCollection = new(IISA_IAppHostChildElementCollection_UUID);

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostConfigManager interface)
    /// </summary>
    private const string IISA_IAppHostConfigManager_UUID = "8f6d760f-f0cb-4d69-b5f6-848b33e9bdc6";

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostConfigManager interface)
    /// </summary>
    public static readonly Guid IISA_IAppHostConfigManager = new(IISA_IAppHostConfigManager_UUID);

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostPathMapper interface)
    /// </summary>
    private const string IISA_IAppHostPathMapper_UUID = "e7927575-5cc3-403b-822e-328a6b904bee";

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostPathMapper interface)
    /// </summary>
    public static readonly Guid IISA_IAppHostPathMapper = new(IISA_IAppHostPathMapper_UUID);

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostCollectionSchema interface)
    /// </summary>
    private const string IISA_IAppHostCollectionSchema_UUID = "de095db1-5368-4d11-81f6-efef619b7bcf";

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostCollectionSchema interface)
    /// </summary>
    public static readonly Guid IISA_IAppHostCollectionSchema = new(IISA_IAppHostCollectionSchema_UUID);

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostElement interface)
    /// </summary>
    private const string IISA_IAppHostElement_UUID = "64ff8ccc-b287-4dae-b08a-a72cbf45f453";

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostElement interface)
    /// </summary>
    public static readonly Guid IISA_IAppHostElement = new(IISA_IAppHostElement_UUID);

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostPropertyException interface)
    /// </summary>
    private const string IISA_IAppHostPropertyException_UUID = "eafe4895-a929-41ea-b14d-613e23f62b71";

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostPropertyException interface)
    /// </summary>
    public static readonly Guid IISA_IAppHostPropertyException = new(IISA_IAppHostPropertyException_UUID);

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostElementSchema interface)
    /// </summary>
    private const string IISA_IAppHostElementSchema_UUID = "ef13d885-642c-4709-99ec-b89561c6bc69";

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostElementSchema interface)
    /// </summary>
    public static readonly Guid IISA_IAppHostElementSchema = new(IISA_IAppHostElementSchema_UUID);

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostPropertyCollection interface)
    /// </summary>
    private const string IISA_IAppHostPropertyCollection_UUID = "0191775e-bcff-445a-b4f4-3bdda54e2816";

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostPropertyCollection interface)
    /// </summary>
    public static readonly Guid IISA_IAppHostPropertyCollection = new(IISA_IAppHostPropertyCollection_UUID);

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostMappingExtension interface)
    /// </summary>
    private const string IISA_IAppHostMappingExtension_UUID = "31a83ea0-c0e4-4a2c-8a01-353cc2a4c60a";

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostMappingExtension interface)
    /// </summary>
    public static readonly Guid IISA_IAppHostMappingExtension = new(IISA_IAppHostMappingExtension_UUID);

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostMethodCollection interface)
    /// </summary>
    private const string IISA_IAppHostMethodCollection_UUID = "d6c7cd8f-bb8d-4f96-b591-d3a5f1320269";

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostMethodCollection interface)
    /// </summary>
    public static readonly Guid IISA_IAppHostMethodCollection = new(IISA_IAppHostMethodCollection_UUID);

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostConfigFile interface)
    /// </summary>
    private const string IISA_IAppHostConfigFile_UUID = "ada4e6fb-e025-401e-a5d0-c3134a281f07";

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostConfigFile interface)
    /// </summary>
    public static readonly Guid IISA_IAppHostConfigFile = new(IISA_IAppHostConfigFile_UUID);

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostSectionDefinitionCollection interface)
    /// </summary>
    private const string IISA_IAppHostSectionDefinitionCollection_UUID = "b7d381ee-8860-47a1-8af4-1f33b2b1f325";

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostSectionDefinitionCollection interface)
    /// </summary>
    public static readonly Guid IISA_IAppHostSectionDefinitionCollection = new(IISA_IAppHostSectionDefinitionCollection_UUID);

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostSectionDefinition interface)
    /// </summary>
    private const string IISA_IAppHostSectionDefinition_UUID = "c5c04795-321c-4014-8fd6-d44658799393";

    /// <summary>
    /// MC-IISA: Internet Information Services (IIS) Application Host COM Protocol (IAppHostSectionDefinition interface)
    /// </summary>
    public static readonly Guid IISA_IAppHostSectionDefinition = new(IISA_IAppHostSectionDefinition_UUID);

    /// <summary>
    /// MS-ADTG: Remote Data Services (RDS) Transport Protocol (IDataFactory interface)
    /// </summary>
    private const string ADTG_IDataFactory_UUID = "0eac4842-8763-11cf-a743-00aa00a3f00d";

    /// <summary>
    /// MS-ADTG: Remote Data Services (RDS) Transport Protocol (IDataFactory interface)
    /// </summary>
    public static readonly Guid ADTG_IDataFactory = new(ADTG_IDataFactory_UUID);

    /// <summary>
    /// MS-ADTG: Remote Data Services (RDS) Transport Protocol (IDataFactory2 interface)
    /// </summary>
    private const string ADTG_IDataFactory2_UUID = "070669eb-b52f-11d1-9270-00c04fbbbfb3";

    /// <summary>
    /// MS-ADTG: Remote Data Services (RDS) Transport Protocol (IDataFactory2 interface)
    /// </summary>
    public static readonly Guid ADTG_IDataFactory2 = new(ADTG_IDataFactory2_UUID);

    /// <summary>
    /// MS-ADTG: Remote Data Services (RDS) Transport Protocol (IDataFactory3 interface)
    /// </summary>
    private const string ADTG_IDataFactory3_UUID = "4639db2a-bfc5-11d2-9318-00c04fbbbfb3";

    /// <summary>
    /// MS-ADTG: Remote Data Services (RDS) Transport Protocol (IDataFactory3 interface)
    /// </summary>
    public static readonly Guid ADTG_IDataFactory3 = new(ADTG_IDataFactory3_UUID);

    /// <summary>
    /// MS-BKRP: BackupKey Remote Protocol
    /// </summary>
    private const string BKRP_UUID = "3dde7c30-165d-11d1-ab8f-00805f14db40";

    /// <summary>
    /// MS-BKRP: BackupKey Remote Protocol
    /// </summary>
    public static readonly Guid BKRP = new(BKRP_UUID);

    /// <summary>
    /// MS-BPAU: Background Intelligent Transfer Service (BITS) Peer-Caching: Peer Authentication Protocol
    /// </summary>
    private const string BPAU_UUID = "e3d0d746-d2af-40fd-8a7a-0d7078bb7092";

    /// <summary>
    /// MS-BPAU: Background Intelligent Transfer Service (BITS) Peer-Caching: Peer Authentication Protocol
    /// </summary>
    public static readonly Guid BPAU = new(BPAU_UUID);

    /// <summary>
    /// MS-BRWSA: Common Internet File System (CIFS) Browser Auxiliary Protocol
    /// </summary>
    private const string BRWSA_UUID = "6bffd098-a112-3610-9833-012892020162";

    /// <summary>
    /// MS-BRWSA: Common Internet File System (CIFS) Browser Auxiliary Protocol
    /// </summary>
    public static readonly Guid BRWSA = new(BRWSA_UUID);

    /// <summary>
    /// MS-CAPR: Central Access Policy Identifier (ID) Retrieval Protocol
    /// </summary>
    private const string CAPR_UUID = "afc07e2e-311c-4435-808c-c483ffeec7c9";

    /// <summary>
    /// MS-CAPR: Central Access Policy Identifier (ID) Retrieval Protocol
    /// </summary>
    public static readonly Guid CAPR = new(CAPR_UUID);

    /// <summary>
    /// MS-CMPO: MSDTC Connection Manager: OleTx Transports Protocol
    /// </summary>
    private const string CMPO_UUID = "906b0ce0-c70b-1067-b317-00dd010662da";

    /// <summary>
    /// MS-CMPO: MSDTC Connection Manager: OleTx Transports Protocol
    /// </summary>
    public static readonly Guid CMPO = new(CMPO_UUID);

    /// <summary>
    /// MS-CMRP: Failover Cluster: Management API (ClusAPI) Protocol
    /// </summary>
    private const string CMRP_UUID = "b97db8b2-4c63-11cf-bff6-08002be23f2f";

    /// <summary>
    /// MS-CMRP: Failover Cluster: Management API (ClusAPI) Protocol
    /// </summary>
    public static readonly Guid CMRP = new(CMRP_UUID);

    /// <summary>
    /// MS-COM: Component Object Model Plus (COM+) Protocol
    /// </summary>
    private const string COM_UUID = "97199110-db2e-11d1-a251-0000f805ca53";

    /// <summary>
    /// MS-COM: Component Object Model Plus (COM+) Protocol
    /// </summary>
    public static readonly Guid COM = new(COM_UUID);

    /// <summary>
    /// MS-COMA: Component Object Model Plus (COM+) Remote Administration Protocol (ICatalogTableRead interface)
    /// </summary>
    private const string COMA_ICatalogTableRead_UUID = "0e3d6630-b46b-11d1-9d2d-006008b0e5ca";

    /// <summary>
    /// MS-COMA: Component Object Model Plus (COM+) Remote Administration Protocol (ICatalogTableRead interface)
    /// </summary>
    public static readonly Guid COMA_ICatalogTableRead = new(COMA_ICatalogTableRead_UUID);

    /// <summary>
    /// MS-COMA: Component Object Model Plus (COM+) Remote Administration Protocol (IContainerControl interface)
    /// </summary>
    private const string COMA_IContainerControl_UUID = "3f3b1b86-dbbe-11d1-9da6-00805f85cfe3";

    /// <summary>
    /// MS-COMA: Component Object Model Plus (COM+) Remote Administration Protocol (IContainerControl interface)
    /// </summary>
    public static readonly Guid COMA_IContainerControl = new(COMA_IContainerControl_UUID);

    /// <summary>
    /// MS-COMA: Component Object Model Plus (COM+) Remote Administration Protocol (IAlternateLaunch interface)
    /// </summary>
    private const string COMA_IAlternateLaunch_UUID = "7f43b400-1a0e-4d57-bbc9-6b0c65f7a889";

    /// <summary>
    /// MS-COMA: Component Object Model Plus (COM+) Remote Administration Protocol (IAlternateLaunch interface)
    /// </summary>
    public static readonly Guid COMA_IAlternateLaunch = new(COMA_IAlternateLaunch_UUID);

    /// <summary>
    /// MS-COMA: Component Object Model Plus (COM+) Remote Administration Protocol (ICatalogUtils interface)
    /// </summary>
    private const string COMA_ICatalogUtils_UUID = "456129e2-1078-11d2-b0f9-00805fc73204";

    /// <summary>
    /// MS-COMA: Component Object Model Plus (COM+) Remote Administration Protocol (ICatalogUtils interface)
    /// </summary>
    public static readonly Guid COMA_ICatalogUtils = new(COMA_ICatalogUtils_UUID);

    /// <summary>
    /// MS-COMA: Component Object Model Plus (COM+) Remote Administration Protocol (IRegister interface)
    /// </summary>
    private const string COMA_IRegister_UUID = "8db2180e-bd29-11d1-8b7e-00c04fd7a924";

    /// <summary>
    /// MS-COMA: Component Object Model Plus (COM+) Remote Administration Protocol (IRegister interface)
    /// </summary>
    public static readonly Guid COMA_IRegister = new(COMA_IRegister_UUID);

    /// <summary>
    /// MS-COMA: Component Object Model Plus (COM+) Remote Administration Protocol (ICatalogSession interface)
    /// </summary>
    private const string COMA_ICatalogSession_UUID = "182c40fa-32e4-11d0-818b-00a0c9231c29";

    /// <summary>
    /// MS-COMA: Component Object Model Plus (COM+) Remote Administration Protocol (ICatalogSession interface)
    /// </summary>
    public static readonly Guid COMA_ICatalogSession = new(COMA_ICatalogSession_UUID);

    /// <summary>
    /// MS-COMA: Component Object Model Plus (COM+) Remote Administration Protocol (IRegister2 interface)
    /// </summary>
    private const string COMA_IRegister2_UUID = "971668dc-c3fe-4ea1-9643-0c7230f494a1";

    /// <summary>
    /// MS-COMA: Component Object Model Plus (COM+) Remote Administration Protocol (IRegister2 interface)
    /// </summary>
    public static readonly Guid COMA_IRegister2 = new(COMA_IRegister2_UUID);

    /// <summary>
    /// MS-COMA: Component Object Model Plus (COM+) Remote Administration Protocol (IReplicationUtil interface)
    /// </summary>
    private const string COMA_IReplicationUtil_UUID = "98315903-7be5-11d2-adc1-00a02463d6e7";

    /// <summary>
    /// MS-COMA: Component Object Model Plus (COM+) Remote Administration Protocol (IReplicationUtil interface)
    /// </summary>
    public static readonly Guid COMA_IReplicationUtil = new(COMA_IReplicationUtil_UUID);

    /// <summary>
    /// MS-COMA: Component Object Model Plus (COM+) Remote Administration Protocol (IContainerControl2 interface)
    /// </summary>
    private const string COMA_IContainerControl2_UUID = "6c935649-30a6-4211-8687-c4c83e5fe1c7";

    /// <summary>
    /// MS-COMA: Component Object Model Plus (COM+) Remote Administration Protocol (IContainerControl2 interface)
    /// </summary>
    public static readonly Guid COMA_IContainerControl2 = new(COMA_IContainerControl2_UUID);

    /// <summary>
    /// MS-COMA: Component Object Model Plus (COM+) Remote Administration Protocol (IExport2 interface)
    /// </summary>
    private const string COMA_IExport2_UUID = "f131ea3e-b7be-480e-a60d-51cb2785779e";

    /// <summary>
    /// MS-COMA: Component Object Model Plus (COM+) Remote Administration Protocol (IExport2 interface)
    /// </summary>
    public static readonly Guid COMA_IExport2 = new(COMA_IExport2_UUID);

    /// <summary>
    /// MS-COMA: Component Object Model Plus (COM+) Remote Administration Protocol (IImport2 interface)
    /// </summary>
    private const string COMA_IImport2_UUID = "1f7b1697-ecb2-4cbb-8a0e-75c427f4a6f0";

    /// <summary>
    /// MS-COMA: Component Object Model Plus (COM+) Remote Administration Protocol (IImport2 interface)
    /// </summary>
    public static readonly Guid COMA_IImport2 = new(COMA_IImport2_UUID);

    /// <summary>
    /// MS-COMA: Component Object Model Plus (COM+) Remote Administration Protocol (ICatalogTableInfo interface)
    /// </summary>
    private const string COMA_ICatalogTableInfo_UUID = "a8927a41-d3ce-11d1-8472-006008b0e5ca";

    /// <summary>
    /// MS-COMA: Component Object Model Plus (COM+) Remote Administration Protocol (ICatalogTableInfo interface)
    /// </summary>
    public static readonly Guid COMA_ICatalogTableInfo = new(COMA_ICatalogTableInfo_UUID);

    /// <summary>
    /// MS-COMA: Component Object Model Plus (COM+) Remote Administration Protocol (IExport interface)
    /// </summary>
    private const string COMA_IExport_UUID = "cfadac84-e12c-11d1-b34c-00c04f990d54";

    /// <summary>
    /// MS-COMA: Component Object Model Plus (COM+) Remote Administration Protocol (IExport interface)
    /// </summary>
    public static readonly Guid COMA_IExport = new(COMA_IExport_UUID);

    /// <summary>
    /// MS-COMA: Component Object Model Plus (COM+) Remote Administration Protocol (ICatalog64BitSupport interface)
    /// </summary>
    private const string COMA_ICatalog64BitSupport_UUID = "1d118904-94b3-4a64-9fa6-ed432666a7b9";

    /// <summary>
    /// MS-COMA: Component Object Model Plus (COM+) Remote Administration Protocol (ICatalog64BitSupport interface)
    /// </summary>
    public static readonly Guid COMA_ICatalog64BitSupport = new(COMA_ICatalog64BitSupport_UUID);

    /// <summary>
    /// MS-COMA: Component Object Model Plus (COM+) Remote Administration Protocol (ICapabilitySupport interface)
    /// </summary>
    private const string COMA_ICapabilitySupport_UUID = "47cde9a1-0bf6-11d2-8016-00c04fb9988e";

    /// <summary>
    /// MS-COMA: Component Object Model Plus (COM+) Remote Administration Protocol (ICapabilitySupport interface)
    /// </summary>
    public static readonly Guid COMA_ICapabilitySupport = new(COMA_ICapabilitySupport_UUID);

    /// <summary>
    /// MS-COMA: Component Object Model Plus (COM+) Remote Administration Protocol (ICatalogTableWrite interface)
    /// </summary>
    private const string COMA_ICatalogTableWrite_UUID = "0e3d6631-b46b-11d1-9d2d-006008b0e5ca";

    /// <summary>
    /// MS-COMA: Component Object Model Plus (COM+) Remote Administration Protocol (ICatalogTableWrite interface)
    /// </summary>
    public static readonly Guid COMA_ICatalogTableWrite = new(COMA_ICatalogTableWrite_UUID);

    /// <summary>
    /// MS-COMA: Component Object Model Plus (COM+) Remote Administration Protocol (IImport interface)
    /// </summary>
    private const string COMA_IImport_UUID = "c2be6970-df9e-11d1-8b87-00c04fd7a924";

    /// <summary>
    /// MS-COMA: Component Object Model Plus (COM+) Remote Administration Protocol (IImport interface)
    /// </summary>
    public static readonly Guid COMA_IImport = new(COMA_IImport_UUID);

    /// <summary>
    /// MS-COMA: Component Object Model Plus (COM+) Remote Administration Protocol (ICatalogUtils2 interface)
    /// </summary>
    private const string COMA_ICatalogUtils2_UUID = "c726744e-5735-4f08-8286-c510ee638fb6";

    /// <summary>
    /// MS-COMA: Component Object Model Plus (COM+) Remote Administration Protocol (ICatalogUtils2 interface)
    /// </summary>
    public static readonly Guid COMA_ICatalogUtils2 = new(COMA_ICatalogUtils2_UUID);

    /// <summary>
    /// MS-COMEV: Component Object Model Plus (COM+) Event System Protocol (IEventClass interface)
    /// </summary>
    private const string COMEV_IEventClass_UUID = "fb2b72a0-7a68-11d1-88f9-0080c7d771bf";

    /// <summary>
    /// MS-COMEV: Component Object Model Plus (COM+) Event System Protocol (IEventClass interface)
    /// </summary>
    public static readonly Guid COMEV_IEventClass = new(COMEV_IEventClass_UUID);

    /// <summary>
    /// MS-COMEV: Component Object Model Plus (COM+) Event System Protocol (IEventClass2 interface)
    /// </summary>
    private const string COMEV_IEventClass2_UUID = "fb2b72a1-7a68-11d1-88f9-0080c7d771bf";

    /// <summary>
    /// MS-COMEV: Component Object Model Plus (COM+) Event System Protocol (IEventClass2 interface)
    /// </summary>
    public static readonly Guid COMEV_IEventClass2 = new(COMEV_IEventClass2_UUID);

    /// <summary>
    /// MS-COMEV: Component Object Model Plus (COM+) Event System Protocol (IEventClass3 interface)
    /// </summary>
    private const string COMEV_IEventClass3_UUID = "7fb7ea43-2d76-4ea8-8cd9-3decc270295e";

    /// <summary>
    /// MS-COMEV: Component Object Model Plus (COM+) Event System Protocol (IEventClass3 interface)
    /// </summary>
    public static readonly Guid COMEV_IEventClass3 = new(COMEV_IEventClass3_UUID);

    /// <summary>
    /// MS-COMEV: Component Object Model Plus (COM+) Event System Protocol (IEventSystem interface)
    /// </summary>
    private const string COMEV_IEventSystem_UUID = "4e14fb9f-2e22-11d1-9964-00c04fbbb345";

    /// <summary>
    /// MS-COMEV: Component Object Model Plus (COM+) Event System Protocol (IEventSystem interface)
    /// </summary>
    public static readonly Guid COMEV_IEventSystem = new(COMEV_IEventSystem_UUID);

    /// <summary>
    /// MS-COMEV: Component Object Model Plus (COM+) Event System Protocol (IEventSystem2 interface)
    /// </summary>
    private const string COMEV_IEventSystem2_UUID = "99cc098f-a48a-4e9c-8e58-965c0afc19d5";

    /// <summary>
    /// MS-COMEV: Component Object Model Plus (COM+) Event System Protocol (IEventSystem2 interface)
    /// </summary>
    public static readonly Guid COMEV_IEventSystem2 = new(COMEV_IEventSystem2_UUID);

    /// <summary>
    /// MS-COMEV: Component Object Model Plus (COM+) Event System Protocol (IEventSubscription interface)
    /// </summary>
    private const string COMEV_IEventSubscription_UUID = "4a6b0e15-2e38-11d1-9965-00c04fbbb345";

    /// <summary>
    /// MS-COMEV: Component Object Model Plus (COM+) Event System Protocol (IEventSubscription interface)
    /// </summary>
    public static readonly Guid COMEV_IEventSubscription = new(COMEV_IEventSubscription_UUID);

    /// <summary>
    /// MS-COMEV: Component Object Model Plus (COM+) Event System Protocol (IEventSubscription2 interface)
    /// </summary>
    private const string COMEV_IEventSubscription2_UUID = "4a6b0e16-2e38-11d1-9965-00c04fbbb345";

    /// <summary>
    /// MS-COMEV: Component Object Model Plus (COM+) Event System Protocol (IEventSubscription2 interface)
    /// </summary>
    public static readonly Guid COMEV_IEventSubscription2 = new(COMEV_IEventSubscription2_UUID);

    /// <summary>
    /// MS-COMEV: Component Object Model Plus (COM+) Event System Protocol (IEventSubscription3 interface)
    /// </summary>
    private const string COMEV_IEventSubscription3_UUID = "fbc1d17d-c498-43a0-81af-423ddd530af6";

    /// <summary>
    /// MS-COMEV: Component Object Model Plus (COM+) Event System Protocol (IEventSubscription3 interface)
    /// </summary>
    public static readonly Guid COMEV_IEventSubscription3 = new(COMEV_IEventSubscription3_UUID);

    /// <summary>
    /// MS-COMEV: Component Object Model Plus (COM+) Event System Protocol (IEventObjectCollection interface)
    /// </summary>
    private const string COMEV_IEventObjectCollection_UUID = "f89ac270-d4eb-11d1-b682-00805fc79216";

    /// <summary>
    /// MS-COMEV: Component Object Model Plus (COM+) Event System Protocol (IEventObjectCollection interface)
    /// </summary>
    public static readonly Guid COMEV_IEventObjectCollection = new(COMEV_IEventObjectCollection_UUID);

    /// <summary>
    /// MS-COMEV: Component Object Model Plus (COM+) Event System Protocol (IEventSystemInitialize interface)
    /// </summary>
    private const string COMEV_IEventSystemInitialize_UUID = "a0e8f27a-888c-11d1-b763-00c04fb926af";

    /// <summary>
    /// MS-COMEV: Component Object Model Plus (COM+) Event System Protocol (IEventSystemInitialize interface)
    /// </summary>
    public static readonly Guid COMEV_IEventSystemInitialize = new(COMEV_IEventSystemInitialize_UUID);

    /// <summary>
    /// MS-COMEV: Component Object Model Plus (COM+) Event System Protocol (IEnumEventObject interface)
    /// </summary>
    private const string COMEV_IEnumEventObject_UUID = "f4a07d63-2e25-11d1-9964-00c04fbbb345";

    /// <summary>
    /// MS-COMEV: Component Object Model Plus (COM+) Event System Protocol (IEnumEventObject interface)
    /// </summary>
    public static readonly Guid COMEV_IEnumEventObject = new(COMEV_IEnumEventObject_UUID);

    /// <summary>
    /// MS-COMT: Component Object Model Plus (COM+) Event System Protocol (IGetTrackingData interface)
    /// </summary>
    private const string COMT_IGetTrackingData_UUID = "b60040e0-bcf3-11d1-861d-0080c729264d";

    /// <summary>
    /// MS-COMT: Component Object Model Plus (COM+) Event System Protocol (IGetTrackingData interface)
    /// </summary>
    public static readonly Guid COMT_IGetTrackingData = new(COMT_IGetTrackingData_UUID);

    /// <summary>
    /// MS-COMT: Component Object Model Plus (COM+) Event System Protocol (IProcessDump interface)
    /// </summary>
    private const string COMT_IProcessDump_UUID = "23c9dd26-2355-4fe2-84de-f779a238adbd";

    /// <summary>
    /// MS-COMT: Component Object Model Plus (COM+) Event System Protocol (IProcessDump interface)
    /// </summary>
    public static readonly Guid COMT_IProcessDump = new(COMT_IProcessDump_UUID);

    /// <summary>
    /// MS-COMT: Component Object Model Plus (COM+) Event System Protocol (IComTrackingInfoEvents interface)
    /// </summary>
    private const string COMT_IComTrackingInfoEvents_UUID = "4e6cdcc9-fb25-4fd5-9cc5-c9f4b6559cec";

    /// <summary>
    /// MS-COMT: Component Object Model Plus (COM+) Event System Protocol (IComTrackingInfoEvents interface)
    /// </summary>
    public static readonly Guid COMT_IComTrackingInfoEvents = new(COMT_IComTrackingInfoEvents_UUID);

    /// <summary>
    /// MS-CSRA: Certificate Services Remote Administration Protocol (ICertAdminD interface)
    /// </summary>
    private const string CSRA_ICertAdminD_UUID = "d99e6e71-fc88-11d0-b498-00a0c90312f3";

    /// <summary>
    /// MS-CSRA: Certificate Services Remote Administration Protocol (ICertAdminD interface)
    /// </summary>
    public static readonly Guid CSRA_ICertAdminD = new(CSRA_ICertAdminD_UUID);

    /// <summary>
    /// MS-CSRA: Certificate Services Remote Administration Protocol (ICertAdminD2 interface)
    /// </summary>
    private const string CSRA_ICertAdminD2_UUID = "7fe0d935-dda6-443f-85d0-1cfb58fe41dd";

    /// <summary>
    /// MS-CSRA: Certificate Services Remote Administration Protocol (ICertAdminD2 interface)
    /// </summary>
    public static readonly Guid CSRA_ICertAdminD2 = new(CSRA_ICertAdminD2_UUID);

    /// <summary>
    /// MS-CSVP: Failover Cluster: Setup and Validation Protocol (ClusPrep) (IClusterSetup interface)
    /// </summary>
    private const string CSVP_IClusterSetup_UUID = "491260b5-05c9-40d9-b7f2-1f7bdae0927f";

    /// <summary>
    /// MS-CSVP: Failover Cluster: Setup and Validation Protocol (ClusPrep) (IClusterSetup interface)
    /// </summary>
    public static readonly Guid CSVP_IClusterSetup = new(CSVP_IClusterSetup_UUID);

    /// <summary>
    /// MS-CSVP: Failover Cluster: Setup and Validation Protocol (ClusPrep) (IClusterUpdate interface)
    /// </summary>
    private const string CSVP_IClusterUpdate_UUID = "e3c9b851-c442-432b-8fc6-a7faafc09d3b";

    /// <summary>
    /// MS-CSVP: Failover Cluster: Setup and Validation Protocol (ClusPrep) (IClusterUpdate interface)
    /// </summary>
    public static readonly Guid CSVP_IClusterUpdate = new(CSVP_IClusterUpdate_UUID);

    /// <summary>
    /// MS-CSVP: Failover Cluster: Setup and Validation Protocol (ClusPrep) (IClusterCleanup interface)
    /// </summary>
    private const string CSVP_IClusterCleanup_UUID = "d6105110-8917-41a5-aa32-8e0aa2933dc9";

    /// <summary>
    /// MS-CSVP: Failover Cluster: Setup and Validation Protocol (ClusPrep) (IClusterCleanup interface)
    /// </summary>
    public static readonly Guid CSVP_IClusterCleanup = new(CSVP_IClusterCleanup_UUID);

    /// <summary>
    /// MS-CSVP: Failover Cluster: Setup and Validation Protocol (ClusPrep) (IClusterLog interface)
    /// </summary>
    private const string CSVP_IClusterLog_UUID = "85923ca7-1b6b-4e83-a2e4-f5ba3bfbb8a3";

    /// <summary>
    /// MS-CSVP: Failover Cluster: Setup and Validation Protocol (ClusPrep) (IClusterLog interface)
    /// </summary>
    public static readonly Guid CSVP_IClusterLog = new(CSVP_IClusterLog_UUID);

    /// <summary>
    /// MS-CSVP: Failover Cluster: Setup and Validation Protocol (ClusPrep) (IClusterFirewall interface)
    /// </summary>
    private const string CSVP_IClusterFirewall_UUID = "f1d6c29c-8fbe-4691-8724-f6d8deaeafc8";

    /// <summary>
    /// MS-CSVP: Failover Cluster: Setup and Validation Protocol (ClusPrep) (IClusterFirewall interface)
    /// </summary>
    public static readonly Guid CSVP_IClusterFirewall = new(CSVP_IClusterFirewall_UUID);

    /// <summary>
    /// MS-CSVP: Failover Cluster: Setup and Validation Protocol (ClusPrep) (IClusterStorage2 interface)
    /// </summary>
    private const string CSVP_IClusterStorage2_UUID = "12108a88-6858-4467-b92f-e6cf4568dfb6";

    /// <summary>
    /// MS-CSVP: Failover Cluster: Setup and Validation Protocol (ClusPrep) (IClusterStorage2 interface)
    /// </summary>
    public static readonly Guid CSVP_IClusterStorage2 = new(CSVP_IClusterStorage2_UUID);

    /// <summary>
    /// MS-CSVP: Failover Cluster: Setup and Validation Protocol (ClusPrep) (IClusterStorage3 interface)
    /// </summary>
    private const string CSVP_IClusterStorage3_UUID = "11942d87-a1de-4e7f-83fb-a840d9c5928d";

    /// <summary>
    /// MS-CSVP: Failover Cluster: Setup and Validation Protocol (ClusPrep) (IClusterStorage3 interface)
    /// </summary>
    public static readonly Guid CSVP_IClusterStorage3 = new(CSVP_IClusterStorage3_UUID);

    /// <summary>
    /// MS-CSVP: Failover Cluster: Setup and Validation Protocol (ClusPrep) (IClusterNetwork2 interface)
    /// </summary>
    private const string CSVP_IClusterNetwork2_UUID = "2931c32c-f731-4c56-9feb-3d5f1c5e72bf";

    /// <summary>
    /// MS-CSVP: Failover Cluster: Setup and Validation Protocol (ClusPrep) (IClusterNetwork2 interface)
    /// </summary>
    public static readonly Guid CSVP_IClusterNetwork2 = new(CSVP_IClusterNetwork2_UUID);

    /// <summary>
    /// MS-CSVP: Failover Cluster: Setup and Validation Protocol (ClusPrep) (ClusterStorage2 interface)
    /// </summary>
    private const string CSVP_ClusterStorage2_UUID = "c72b09db-4d53-4f41-8dcc-2d752ab56f7c";

    /// <summary>
    /// MS-CSVP: Failover Cluster: Setup and Validation Protocol (ClusPrep) (ClusterStorage2 interface)
    /// </summary>
    public static readonly Guid CSVP_ClusterStorage2 = new(CSVP_ClusterStorage2_UUID);

    /// <summary>
    /// MS-CSVP: Failover Cluster: Setup and Validation Protocol (ClusPrep) (ClusterNetwork2 interface)
    /// </summary>
    private const string CSVP_ClusterNetwork2_UUID = "e1568352-586d-43e4-933f-8e6dc4de317a";

    /// <summary>
    /// MS-CSVP: Failover Cluster: Setup and Validation Protocol (ClusPrep) (ClusterNetwork2 interface)
    /// </summary>
    public static readonly Guid CSVP_ClusterNetwork2 = new(CSVP_ClusterNetwork2_UUID);

    /// <summary>
    /// MS-CSVP: Failover Cluster: Setup and Validation Protocol (ClusPrep) (ClusterCleanup interface)
    /// </summary>
    private const string CSVP_ClusterCleanup_UUID = "a6d3e32b-9814-4409-8de3-cfa673e6d3de";

    /// <summary>
    /// MS-CSVP: Failover Cluster: Setup and Validation Protocol (ClusPrep) (ClusterCleanup interface)
    /// </summary>
    public static readonly Guid CSVP_ClusterCleanup = new(CSVP_ClusterCleanup_UUID);

    /// <summary>
    /// MS-CSVP: Failover Cluster: Setup and Validation Protocol (ClusPrep) (ClusterSetup interface)
    /// </summary>
    private const string CSVP_ClusterSetup_UUID = "04d55210-b6ac-4248-9e69-2a569d1d2ab6";

    /// <summary>
    /// MS-CSVP: Failover Cluster: Setup and Validation Protocol (ClusPrep) (ClusterSetup interface)
    /// </summary>
    public static readonly Guid CSVP_ClusterSetup = new(CSVP_ClusterSetup_UUID);

    /// <summary>
    /// MS-CSVP: Failover Cluster: Setup and Validation Protocol (ClusPrep) (ClusterLog interface)
    /// </summary>
    private const string CSVP_ClusterLog_UUID = "88e7ac6d-c561-4f03-9a60-39dd768f867d";

    /// <summary>
    /// MS-CSVP: Failover Cluster: Setup and Validation Protocol (ClusPrep) (ClusterLog interface)
    /// </summary>
    public static readonly Guid CSVP_ClusterLog = new(CSVP_ClusterLog_UUID);

    /// <summary>
    /// MS-CSVP: Failover Cluster: Setup and Validation Protocol (ClusPrep) (ClusterFirewall interface)
    /// </summary>
    private const string CSVP_ClusterFirewall_UUID = "3cfee98c-fb4b-44c6-bd98-a1db14abca3f";

    /// <summary>
    /// MS-CSVP: Failover Cluster: Setup and Validation Protocol (ClusPrep) (ClusterFirewall interface)
    /// </summary>
    public static readonly Guid CSVP_ClusterFirewall = new(CSVP_ClusterFirewall_UUID);

    /// <summary>
    /// MS-CSVP: Failover Cluster: Setup and Validation Protocol (ClusPrep) (ClusterUpdate interface)
    /// </summary>
    private const string CSVP_ClusterUpdate_UUID = "4142dd5d-3472-4370-8641-de7856431fb0";

    /// <summary>
    /// MS-CSVP: Failover Cluster: Setup and Validation Protocol (ClusPrep) (ClusterUpdate interface)
    /// </summary>
    public static readonly Guid CSVP_ClusterUpdate = new(CSVP_ClusterUpdate_UUID);

    /// <summary>
    /// MS-DCOM: Distributed Component Object Model (DCOM) Remote Protocol (IRemUnknown interface)
    /// </summary>
    private const string DCOM_IRemUnknown_UUID = "00000131-0000-0000-c000-000000000046";

    /// <summary>
    /// MS-DCOM: Distributed Component Object Model (DCOM) Remote Protocol (IRemUnknown interface)
    /// </summary>
    public static readonly Guid DCOM_IRemUnknown = new(DCOM_IRemUnknown_UUID);

    /// <summary>
    /// MS-DCOM: Distributed Component Object Model (DCOM) Remote Protocol (IActivation interface)
    /// </summary>
    private const string DCOM_IActivation_UUID = "4d9f4ab8-7d1c-11cf-861e-0020af6e7c57";

    /// <summary>
    /// MS-DCOM: Distributed Component Object Model (DCOM) Remote Protocol (IActivation interface)
    /// </summary>
    public static readonly Guid DCOM_IActivation = new(DCOM_IActivation_UUID);

    /// <summary>
    /// MS-DCOM: Distributed Component Object Model (DCOM) Remote Protocol (IRemUnknown2 interface)
    /// </summary>
    private const string DCOM_IRemUnknown2_UUID = "00000143-0000-0000-c000-000000000046";

    /// <summary>
    /// MS-DCOM: Distributed Component Object Model (DCOM) Remote Protocol (IRemUnknown2 interface)
    /// </summary>
    public static readonly Guid DCOM_IRemUnknown2 = new(DCOM_IRemUnknown2_UUID);

    /// <summary>
    /// MS-DCOM: Distributed Component Object Model (DCOM) Remote Protocol (IRemoteSCMActivator interface)
    /// </summary>
    private const string DCOM_IRemoteSCMActivator_UUID = "000001a0-0000-0000-c000-000000000046";

    /// <summary>
    /// MS-DCOM: Distributed Component Object Model (DCOM) Remote Protocol (IRemoteSCMActivator interface)
    /// </summary>
    public static readonly Guid DCOM_IRemoteSCMActivator = new(DCOM_IRemoteSCMActivator_UUID);

    /// <summary>
    /// MS-DCOM: Distributed Component Object Model (DCOM) Remote Protocol (IObjectExporter interface)
    /// </summary>
    private const string DCOM_IObjectExporter_UUID = "99fcfec4-5260-101b-bbcb-00aa0021347a";

    /// <summary>
    /// MS-DCOM: Distributed Component Object Model (DCOM) Remote Protocol (IObjectExporter interface)
    /// </summary>
    public static readonly Guid DCOM_IObjectExporter = new(DCOM_IObjectExporter_UUID);

    /// <summary>
    /// MS-DCOM: Distributed Component Object Model (DCOM) Remote Protocol (IUnknown interface)
    /// </summary>
    private const string DCOM_IUnknown_UUID = "00000000-0000-0000-c000-000000000046";

    /// <summary>
    /// MS-DCOM: Distributed Component Object Model (DCOM) Remote Protocol (IUnknown interface)
    /// </summary>
    public static readonly Guid DCOM_IUnknown = new(DCOM_IUnknown_UUID);

    /// <summary>
    /// MS-DFSNM: Distributed File System (DFS): Namespace Management Protocol
    /// </summary>
    private const string DFSNM_UUID = "4fc742e0-4a10-11cf-8273-00aa004ae673";

    /// <summary>
    /// MS-DFSNM: Distributed File System (DFS): Namespace Management Protocol
    /// </summary>
    public static readonly Guid DFSNM = new(DFSNM_UUID);

    /// <summary>
    /// MS-DFSRH: DFS Replication Helper Protocol (IServerHealthReport interface)
    /// </summary>
    private const string DFSRH_IServerHealthReport_UUID = "e65e8028-83e8-491b-9af7-aaf6bd51a0ce";

    /// <summary>
    /// MS-DFSRH: DFS Replication Helper Protocol (IServerHealthReport interface)
    /// </summary>
    public static readonly Guid DFSRH_IServerHealthReport = new(DFSRH_IServerHealthReport_UUID);

    /// <summary>
    /// MS-DFSRH: DFS Replication Helper Protocol (IServerHealthReport2 interface)
    /// </summary>
    private const string DFSRH_IServerHealthReport2_UUID = "20d15747-6c48-4254-a358-65039fd8c63c";

    /// <summary>
    /// MS-DFSRH: DFS Replication Helper Protocol (IServerHealthReport2 interface)
    /// </summary>
    public static readonly Guid DFSRH_IServerHealthReport2 = new(DFSRH_IServerHealthReport2_UUID);

    /// <summary>
    /// MS-DFSRH: DFS Replication Helper Protocol (IADProxy interface)
    /// </summary>
    private const string DFSRH_IADProxy_UUID = "4bb8ab1d-9ef9-4100-8eb6-dd4b4e418b72";

    /// <summary>
    /// MS-DFSRH: DFS Replication Helper Protocol (IADProxy interface)
    /// </summary>
    public static readonly Guid DFSRH_IADProxy = new(DFSRH_IADProxy_UUID);

    /// <summary>
    /// MS-DFSRH: DFS Replication Helper Protocol (IADProxy2 interface)
    /// </summary>
    private const string DFSRH_IADProxy2_UUID = "c4b0c7d9-abe0-4733-a1e1-9fdedf260c7a";

    /// <summary>
    /// MS-DFSRH: DFS Replication Helper Protocol (IADProxy2 interface)
    /// </summary>
    public static readonly Guid DFSRH_IADProxy2 = new(DFSRH_IADProxy2_UUID);

    /// <summary>
    /// MS-DHCPM: Dynamic Host Configuration Protocol (DHCP) Server Management Protocol (dhcpsrv interface)
    /// </summary>
    private const string DHCPM_dhcpsrv_UUID = "6bffd098-a112-3610-9833-46c3f874532d";

    /// <summary>
    /// MS-DHCPM: Dynamic Host Configuration Protocol (DHCP) Server Management Protocol (dhcpsrv interface)
    /// </summary>
    public static readonly Guid DHCPM_dhcpsrv = new(DHCPM_dhcpsrv_UUID);

    /// <summary>
    /// MS-DHCPM: Dynamic Host Configuration Protocol (DHCP) Server Management Protocol (dhcpsrv2 interface)
    /// </summary>
    private const string DHCPM_dhcpsrv2_UUID = "5b821720-f63b-11d0-aad2-00c04fc324db";

    /// <summary>
    /// MS-DHCPM: Dynamic Host Configuration Protocol (DHCP) Server Management Protocol (dhcpsrv2 interface)
    /// </summary>
    public static readonly Guid DHCPM_dhcpsrv2 = new(DHCPM_dhcpsrv2_UUID);

    /// <summary>
    /// MS-DLTM: Distributed Link Tracking: Central Manager Protocol
    /// </summary>
    private const string DLTM_UUID = "4da1c422-943d-11d1-acae-00c04fc2aa3f";

    /// <summary>
    /// MS-DLTM: Distributed Link Tracking: Central Manager Protocol
    /// </summary>
    public static readonly Guid DLTM = new(DLTM_UUID);

    /// <summary>
    /// MS-DLTW: Distributed Link Tracking: Workstation Protocol
    /// </summary>
    private const string DLTW_UUID = "300f3532-38cc-11d0-a3f0-0020af6b0add";

    /// <summary>
    /// MS-DLTW: Distributed Link Tracking: Workstation Protocol
    /// </summary>
    public static readonly Guid DLTW = new(DLTW_UUID);

    /// <summary>
    /// MS-DMRP: Disk Management Remote Protocol (IVolumeClient interface)
    /// </summary>
    private const string DMRP_IVolumeClient_UUID = "d2d79df5-3400-11d0-b40b-00aa005ff586";

    /// <summary>
    /// MS-DMRP: Disk Management Remote Protocol (IVolumeClient interface)
    /// </summary>
    public static readonly Guid DMRP_IVolumeClient = new(DMRP_IVolumeClient_UUID);

    /// <summary>
    /// MS-DMRP: Disk Management Remote Protocol (IDMRemoteServer interface)
    /// </summary>
    private const string DMRP_IDMRemoteServer_UUID = "3a410f21-553f-11d1-8e5e-00a0c92c9d5d";

    /// <summary>
    /// MS-DMRP: Disk Management Remote Protocol (IDMRemoteServer interface)
    /// </summary>
    public static readonly Guid DMRP_IDMRemoteServer = new(DMRP_IDMRemoteServer_UUID);

    /// <summary>
    /// MS-DMRP: Disk Management Remote Protocol (IDMNotify interface)
    /// </summary>
    private const string DMRP_IDMNotify_UUID = "d2d79df7-3400-11d0-b40b-00aa005ff586";

    /// <summary>
    /// MS-DMRP: Disk Management Remote Protocol (IDMNotify interface)
    /// </summary>
    public static readonly Guid DMRP_IDMNotify = new(DMRP_IDMNotify_UUID);

    /// <summary>
    /// MS-DMRP: Disk Management Remote Protocol (IVolumeClient2 interface)
    /// </summary>
    private const string DMRP_IVolumeClient2_UUID = "4bdafc52-fe6a-11d2-93f8-00105a11164a";

    /// <summary>
    /// MS-DMRP: Disk Management Remote Protocol (IVolumeClient2 interface)
    /// </summary>
    public static readonly Guid DMRP_IVolumeClient2 = new(DMRP_IVolumeClient2_UUID);

    /// <summary>
    /// MS-DMRP: Disk Management Remote Protocol (IVolumeClient4 interface)
    /// </summary>
    private const string DMRP_IVolumeClient4_UUID = "deb01010-3a37-4d26-99df-e2bb6ae3ac61";

    /// <summary>
    /// MS-DMRP: Disk Management Remote Protocol (IVolumeClient4 interface)
    /// </summary>
    public static readonly Guid DMRP_IVolumeClient4 = new(DMRP_IVolumeClient4_UUID);

    /// <summary>
    /// MS-DMRP: Disk Management Remote Protocol (IVolumeClient3 interface)
    /// </summary>
    private const string DMRP_IVolumeClient3_UUID = "135698d2-3a37-4d26-99df-e2bb6ae3ac61";

    /// <summary>
    /// MS-DMRP: Disk Management Remote Protocol (IVolumeClient3 interface)
    /// </summary>
    public static readonly Guid DMRP_IVolumeClient3 = new(DMRP_IVolumeClient3_UUID);

    /// <summary>
    /// MS-DNSP: Domain Name Service (DNS) Server Management
    /// </summary>
    private const string DNSP_UUID = "50abc2a4-574d-40b3-9d66-ee4fd5fba076";

    /// <summary>
    /// MS-DNSP: Domain Name Service (DNS) Server Management
    /// </summary>
    public static readonly Guid DNSP = new(DNSP_UUID);

    /// <summary>
    /// MS-DRSR: Directory Replication Service (DRS) Remote Protocol (dsaop interface)
    /// </summary>
    private const string DRSR_dsaop_UUID = "7c44d7d4-31d5-424c-bd5e-2b3e1f323d22";

    /// <summary>
    /// MS-DRSR: Directory Replication Service (DRS) Remote Protocol (dsaop interface)
    /// </summary>
    public static readonly Guid DRSR_dsaop = new(DRSR_dsaop_UUID);

    /// <summary>
    /// MS-DRSR: Directory Replication Service (DRS) Remote Protocol (drsuapi interface)
    /// </summary>
    private const string DRSR_drsuapi_UUID = "e3514235-4b06-11d1-ab04-00c04fc2dcd2";

    /// <summary>
    /// MS-DRSR: Directory Replication Service (DRS) Remote Protocol (drsuapi interface)
    /// </summary>
    public static readonly Guid DRSR_drsuapi = new(DRSR_drsuapi_UUID);

    /// <summary>
    /// MS-DSSP: Directory Services Setup Remote Protocol
    /// </summary>
    private const string DSSP_UUID = "3919286a-b10c-11d0-9ba8-00c04fd92ef5";

    /// <summary>
    /// MS-DSSP: Directory Services Setup Remote Protocol
    /// </summary>
    public static readonly Guid DSSP = new(DSSP_UUID);

    /// <summary>
    /// MS-EFSR: Encrypting File System Remote (EFSRPC) Protocol (efsrpc interface)
    /// </summary>
    private const string EFSR_efsrpc_UUID = "df1941c5-fe89-4e79-bf10-463657acf44d";

    /// <summary>
    /// MS-EFSR: Encrypting File System Remote (EFSRPC) Protocol (efsrpc interface)
    /// </summary>
    public static readonly Guid EFSR_efsrpc = new(EFSR_efsrpc_UUID);

    /// <summary>
    /// MS-EFSR: Encrypting File System Remote (EFSRPC) Protocol (lsarpc interface)
    /// </summary>
    private const string EFSR_lsarpc_UUID = "c681d488-d850-11d0-8c52-00c04fd90f7e";

    /// <summary>
    /// MS-EFSR: Encrypting File System Remote (EFSRPC) Protocol (lsarpc interface)
    /// </summary>
    public static readonly Guid EFSR_lsarpc = new(EFSR_lsarpc_UUID);

    /// <summary>
    /// MS-EVEN: EventLog Remoting Protocol
    /// </summary>
    private const string EVEN_UUID = "82273fdc-e32a-18c3-3f78-827929dc23ea";

    /// <summary>
    /// MS-EVEN: EventLog Remoting Protocol
    /// </summary>
    public static readonly Guid EVEN = new(EVEN_UUID);

    /// <summary>
    /// MS-EVEN6: EventLog Remoting Protocol Version 6.0
    /// </summary>
    private const string EVEN6_UUID = "f6beaff7-1e19-4fbb-9f8f-b89e2018337c";

    /// <summary>
    /// MS-EVEN6: EventLog Remoting Protocol Version 6.0
    /// </summary>
    public static readonly Guid EVEN6 = new(EVEN6_UUID);

    /// <summary>
    /// MS-FASP: Firewall and Advanced Security Protocol
    /// </summary>
    private const string FASP_UUID = "6b5bdd1e-528c-422c-af8c-a4079be4fe48";

    /// <summary>
    /// MS-FASP: Firewall and Advanced Security Protocol
    /// </summary>
    public static readonly Guid FASP = new(FASP_UUID);

    /// <summary>
    /// MS-FAX: Fax Server and Client Remote Protocol (faxclient interface)
    /// </summary>
    private const string FAX_faxclient_UUID = "6099fc12-3eff-11d0-abd0-00c04fd91a4e";

    /// <summary>
    /// MS-FAX: Fax Server and Client Remote Protocol (faxclient interface)
    /// </summary>
    public static readonly Guid FAX_faxclient = new(FAX_faxclient_UUID);

    /// <summary>
    /// MS-FAX: Fax Server and Client Remote Protocol (sharedfax interface)
    /// </summary>
    private const string FAX_sharedfax_UUID = "ea0a3165-4834-11d2-a6f8-00c04fa346cc";

    /// <summary>
    /// MS-FAX: Fax Server and Client Remote Protocol (sharedfax interface)
    /// </summary>
    public static readonly Guid FAX_sharedfax = new(FAX_sharedfax_UUID);

    /// <summary>
    /// MS-FRS1: File Replication Service Protocol (NtFrsApi interface)
    /// </summary>
    private const string FRS1_NtFrsApi_UUID = "d049b186-814f-11d1-9a3c-00c04fc9b232";

    /// <summary>
    /// MS-FRS1: File Replication Service Protocol (NtFrsApi interface)
    /// </summary>
    public static readonly Guid FRS1_NtFrsApi = new(FRS1_NtFrsApi_UUID);

    /// <summary>
    /// MS-FRS1: File Replication Service Protocol (frsrpc interface)
    /// </summary>
    private const string FRS1_frsrpc_UUID = "f5cc59b4-4264-101a-8c59-08002b2f8426";

    /// <summary>
    /// MS-FRS1: File Replication Service Protocol (frsrpc interface)
    /// </summary>
    public static readonly Guid FRS1_frsrpc = new(FRS1_frsrpc_UUID);

    /// <summary>
    /// MS-FRS2: Distributed File System Replication Protocol
    /// </summary>
    private const string FRS2_UUID = "897e2e5f-93f3-4376-9c9c-fd2277495c27";

    /// <summary>
    /// MS-FRS2: Distributed File System Replication Protocol
    /// </summary>
    public static readonly Guid FRS2 = new(FRS2_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmFileManagementJob interface)
    /// </summary>
    private const string FSRM_IFsrmFileManagementJob_UUID = "0770687e-9f36-4d6f-8778-599d188461c9";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmFileManagementJob interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmFileManagementJob = new(FSRM_IFsrmFileManagementJob_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmActionCommand interface)
    /// </summary>
    private const string FSRM_IFsrmActionCommand_UUID = "12937789-e247-4917-9c20-f3ee9c7ee783";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmActionCommand interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmActionCommand = new(FSRM_IFsrmActionCommand_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmQuotaBase interface)
    /// </summary>
    private const string FSRM_IFsrmQuotaBase_UUID = "1568a795-3924-4118-b74b-68d8f0fa5daf";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmQuotaBase interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmQuotaBase = new(FSRM_IFsrmQuotaBase_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmStorageModuleDefinition interface)
    /// </summary>
    private const string FSRM_IFsrmStorageModuleDefinition_UUID = "15a81350-497d-4aba-80e9-d4dbcc5521fe";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmStorageModuleDefinition interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmStorageModuleDefinition = new(FSRM_IFsrmStorageModuleDefinition_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmMutableCollection interface)
    /// </summary>
    private const string FSRM_IFsrmMutableCollection_UUID = "1bb617b8-3886-49dc-af82-a6c90fa35dda";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmMutableCollection interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmMutableCollection = new(FSRM_IFsrmMutableCollection_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmFileScreenTemplate interface)
    /// </summary>
    private const string FSRM_IFsrmFileScreenTemplate_UUID = "205bebf8-dd93-452a-95a6-32b566b35828";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmFileScreenTemplate interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmFileScreenTemplate = new(FSRM_IFsrmFileScreenTemplate_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmObject interface)
    /// </summary>
    private const string FSRM_IFsrmObject_UUID = "22bcef93-4a3f-4183-89f9-2f8b8a628aee";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmObject interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmObject = new(FSRM_IFsrmObject_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmReportManager interface)
    /// </summary>
    private const string FSRM_IFsrmReportManager_UUID = "27b899fe-6ffa-4481-a184-d3daade8a02b";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmReportManager interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmReportManager = new(FSRM_IFsrmReportManager_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmActionReport interface)
    /// </summary>
    private const string FSRM_IFsrmActionReport_UUID = "2dbe63c4-b340-48a0-a5b0-158e07fc567e";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmActionReport interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmActionReport = new(FSRM_IFsrmActionReport_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmPropertyCondition interface)
    /// </summary>
    private const string FSRM_IFsrmPropertyCondition_UUID = "326af66f-2ac0-4f68-bf8c-4759f054fa29";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmPropertyCondition interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmPropertyCondition = new(FSRM_IFsrmPropertyCondition_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmQuota interface)
    /// </summary>
    private const string FSRM_IFsrmQuota_UUID = "377f739d-9647-4b8e-97d2-5ffce6d759cd";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmQuota interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmQuota = new(FSRM_IFsrmQuota_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmReportJob interface)
    /// </summary>
    private const string FSRM_IFsrmReportJob_UUID = "38e87280-715c-4c7d-a280-ea1651a19fef";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmReportJob interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmReportJob = new(FSRM_IFsrmReportJob_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmDerivedObjectsResult interface)
    /// </summary>
    private const string FSRM_IFsrmDerivedObjectsResult_UUID = "39322a2d-38ee-4d0d-8095-421a80849a82";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmDerivedObjectsResult interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmDerivedObjectsResult = new(FSRM_IFsrmDerivedObjectsResult_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmQuotaTemplateManager interface)
    /// </summary>
    private const string FSRM_IFsrmQuotaTemplateManager_UUID = "4173ac41-172d-4d52-963c-fdc7e415f717";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmQuotaTemplateManager interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmQuotaTemplateManager = new(FSRM_IFsrmQuotaTemplateManager_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmFileGroupManager interface)
    /// </summary>
    private const string FSRM_IFsrmFileGroupManager_UUID = "426677d5-018c-485c-8a51-20b86d00bdc4";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmFileGroupManager interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmFileGroupManager = new(FSRM_IFsrmFileGroupManager_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmQuotaObject interface)
    /// </summary>
    private const string FSRM_IFsrmQuotaObject_UUID = "42dc3511-61d5-48ae-b6dc-59fc00c0a8d6";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmQuotaObject interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmQuotaObject = new(FSRM_IFsrmQuotaObject_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmPropertyDefinition2 interface)
    /// </summary>
    private const string FSRM_IFsrmPropertyDefinition2_UUID = "47782152-d16c-4229-b4e1-0ddfe308b9f6";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmPropertyDefinition2 interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmPropertyDefinition2 = new(FSRM_IFsrmPropertyDefinition2_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmQuotaManagerEx interface)
    /// </summary>
    private const string FSRM_IFsrmQuotaManagerEx_UUID = "4846cb01-d430-494f-abb4-b1054999fb09";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmQuotaManagerEx interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmQuotaManagerEx = new(FSRM_IFsrmQuotaManagerEx_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmProperty interface)
    /// </summary>
    private const string FSRM_IFsrmProperty_UUID = "4a73fee4-4102-4fcc-9ffb-38614f9ee768";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmProperty interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmProperty = new(FSRM_IFsrmProperty_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmActionEventLog interface)
    /// </summary>
    private const string FSRM_IFsrmActionEventLog_UUID = "4c8f96c3-5d94-4f37-a4f4-f56ab463546f";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmActionEventLog interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmActionEventLog = new(FSRM_IFsrmActionEventLog_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmPipelineModuleDefinition interface)
    /// </summary>
    private const string FSRM_IFsrmPipelineModuleDefinition_UUID = "515c1277-2c81-440e-8fcf-367921ed4f59";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmPipelineModuleDefinition interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmPipelineModuleDefinition = new(FSRM_IFsrmPipelineModuleDefinition_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmFileScreen interface)
    /// </summary>
    private const string FSRM_IFsrmFileScreen_UUID = "5f6325d3-ce88-4733-84c1-2d6aefc5ea07";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmFileScreen interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmFileScreen = new(FSRM_IFsrmFileScreen_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmReportScheduler interface)
    /// </summary>
    private const string FSRM_IFsrmReportScheduler_UUID = "6879caf9-6617-4484-8719-71c3d8645f94";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmReportScheduler interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmReportScheduler = new(FSRM_IFsrmReportScheduler_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmAction interface)
    /// </summary>
    private const string FSRM_IFsrmAction_UUID = "6cd6408a-ae60-463b-9ef1-e117534d69dc";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmAction interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmAction = new(FSRM_IFsrmAction_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmPathMapper interface)
    /// </summary>
    private const string FSRM_IFsrmPathMapper_UUID = "6f4dbfff-6920-4821-a6c3-b7e94c1fd60c";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmPathMapper interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmPathMapper = new(FSRM_IFsrmPathMapper_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmActionEmail2 interface)
    /// </summary>
    private const string FSRM_IFsrmActionEmail2_UUID = "8276702f-2532-4839-89bf-4872609a2ea4";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmActionEmail2 interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmActionEmail2 = new(FSRM_IFsrmActionEmail2_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmQuotaManager interface)
    /// </summary>
    private const string FSRM_IFsrmQuotaManager_UUID = "8bb68c7d-19d8-4ffb-809e-be4fc1734014";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmQuotaManager interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmQuotaManager = new(FSRM_IFsrmQuotaManager_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmFileGroup interface)
    /// </summary>
    private const string FSRM_IFsrmFileGroup_UUID = "8dd04909-0e34-4d55-afaa-89e1f1a1bbb9";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmFileGroup interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmFileGroup = new(FSRM_IFsrmFileGroup_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmCommittableCollection interface)
    /// </summary>
    private const string FSRM_IFsrmCommittableCollection_UUID = "96deb3b5-8b91-4a2a-9d93-80a35d8aa847";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmCommittableCollection interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmCommittableCollection = new(FSRM_IFsrmCommittableCollection_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmQuotaTemplateImported interface)
    /// </summary>
    private const string FSRM_IFsrmQuotaTemplateImported_UUID = "9a2bf113-a329-44cc-809a-5c00fce8da40";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmQuotaTemplateImported interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmQuotaTemplateImported = new(FSRM_IFsrmQuotaTemplateImported_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmQuotaTemplate interface)
    /// </summary>
    private const string FSRM_IFsrmQuotaTemplate_UUID = "a2efab31-295e-46bb-b976-e86d58b52e8b";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmQuotaTemplate interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmQuotaTemplate = new(FSRM_IFsrmQuotaTemplate_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmFileGroupImported interface)
    /// </summary>
    private const string FSRM_IFsrmFileGroupImported_UUID = "ad55f10b-5f11-4be7-94ef-d9ee2e470ded";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmFileGroupImported interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmFileGroupImported = new(FSRM_IFsrmFileGroupImported_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmClassificationRule interface)
    /// </summary>
    private const string FSRM_IFsrmClassificationRule_UUID = "afc052c2-5315-45ab-841b-c6db0e120148";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmClassificationRule interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmClassificationRule = new(FSRM_IFsrmClassificationRule_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmClassifierModuleDefinition interface)
    /// </summary>
    private const string FSRM_IFsrmClassifierModuleDefinition_UUID = "bb36ea26-6318-4b8c-8592-f72dd602e7a5";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmClassifierModuleDefinition interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmClassifierModuleDefinition = new(FSRM_IFsrmClassifierModuleDefinition_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmFileScreenException interface)
    /// </summary>
    private const string FSRM_IFsrmFileScreenException_UUID = "bee7ce02-df77-4515-9389-78f01c5afc1a";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmFileScreenException interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmFileScreenException = new(FSRM_IFsrmFileScreenException_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmRule interface)
    /// </summary>
    private const string FSRM_IFsrmRule_UUID = "cb0df960-16f5-4495-9079-3f9360d831df";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmRule interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmRule = new(FSRM_IFsrmRule_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmFileScreenTemplateManager interface)
    /// </summary>
    private const string FSRM_IFsrmFileScreenTemplateManager_UUID = "cfe36cba-1949-4e74-a14f-f1d580ceaf13";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmFileScreenTemplateManager interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmFileScreenTemplateManager = new(FSRM_IFsrmFileScreenTemplateManager_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmClassificationManager interface)
    /// </summary>
    private const string FSRM_IFsrmClassificationManager_UUID = "d2dc89da-ee91-48a0-85d8-cc72a56f7d04";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmClassificationManager interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmClassificationManager = new(FSRM_IFsrmClassificationManager_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmActionEmail interface)
    /// </summary>
    private const string FSRM_IFsrmActionEmail_UUID = "d646567d-26ae-4caa-9f84-4e0aad207fca";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmActionEmail interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmActionEmail = new(FSRM_IFsrmActionEmail_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmReport interface)
    /// </summary>
    private const string FSRM_IFsrmReport_UUID = "d8cc81d9-46b8-4fa4-bfa5-4aa9dec9b638";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmReport interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmReport = new(FSRM_IFsrmReport_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmFileScreenTemplateImported interface)
    /// </summary>
    private const string FSRM_IFsrmFileScreenTemplateImported_UUID = "e1010359-3e5d-4ecd-9fe4-ef48622fdf30";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmFileScreenTemplateImported interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmFileScreenTemplateImported = new(FSRM_IFsrmFileScreenTemplateImported_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmPropertyDefinitionValue interface)
    /// </summary>
    private const string FSRM_IFsrmPropertyDefinitionValue_UUID = "e946d148-bd67-4178-8e22-1c44925ed710";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmPropertyDefinitionValue interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmPropertyDefinitionValue = new(FSRM_IFsrmPropertyDefinitionValue_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmPropertyDefinition interface)
    /// </summary>
    private const string FSRM_IFsrmPropertyDefinition_UUID = "ede0150f-e9a3-419c-877c-01fe5d24c5d3";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmPropertyDefinition interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmPropertyDefinition = new(FSRM_IFsrmPropertyDefinition_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmFileManagementJobManager interface)
    /// </summary>
    private const string FSRM_IFsrmFileManagementJobManager_UUID = "ee321ecb-d95e-48e9-907c-c7685a013235";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmFileManagementJobManager interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmFileManagementJobManager = new(FSRM_IFsrmFileManagementJobManager_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmFileScreenBase interface)
    /// </summary>
    private const string FSRM_IFsrmFileScreenBase_UUID = "f3637e80-5b22-4a2b-a637-bbb642b41cfc";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmFileScreenBase interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmFileScreenBase = new(FSRM_IFsrmFileScreenBase_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmSetting interface)
    /// </summary>
    private const string FSRM_IFsrmSetting_UUID = "f411d4fd-14be-4260-8c40-03b7c95e608a";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmSetting interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmSetting = new(FSRM_IFsrmSetting_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmCollection interface)
    /// </summary>
    private const string FSRM_IFsrmCollection_UUID = "f76fbf3b-8ddd-4b42-b05a-cb1c3ff1fee8";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmCollection interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmCollection = new(FSRM_IFsrmCollection_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmAutoApplyQuota interface)
    /// </summary>
    private const string FSRM_IFsrmAutoApplyQuota_UUID = "f82e5729-6aba-4740-bfc7-c7f58f75fb7b";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmAutoApplyQuota interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmAutoApplyQuota = new(FSRM_IFsrmAutoApplyQuota_UUID);

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmFileScreenManager interface)
    /// </summary>
    private const string FSRM_IFsrmFileScreenManager_UUID = "ff4fa04e-5a94-4bda-a3a0-d5b4d3c52eba";

    /// <summary>
    /// MS-FSRM: File Server Resource Manager Protocol (IFsrmFileScreenManager interface)
    /// </summary>
    public static readonly Guid FSRM_IFsrmFileScreenManager = new(FSRM_IFsrmFileScreenManager_UUID);

    /// <summary>
    /// MS-FSRVP: File Server Remote VSS Protocol
    /// </summary>
    private const string FSRVP_UUID = "a8e0653c-2744-4389-a61d-7373df8b2292";

    /// <summary>
    /// MS-FSRVP: File Server Remote VSS Protocol
    /// </summary>
    public static readonly Guid FSRVP = new(FSRVP_UUID);

    /// <summary>
    /// MS-GKDI: Group Key Distribution Protocol
    /// </summary>
    private const string GKDI_UUID = "b9785960-524f-11df-8b6d-83dcded72085";

    /// <summary>
    /// MS-GKDI: Group Key Distribution Protocol
    /// </summary>
    public static readonly Guid GKDI = new(GKDI_UUID);

    /// <summary>
    /// MS-ICPR: ICertPassage Remote Protocol
    /// </summary>
    private const string ICPR_UUID = "91ae6020-9e3c-11cf-8d7c-00aa00c091be";

    /// <summary>
    /// MS-ICPR: ICertPassage Remote Protocol
    /// </summary>
    public static readonly Guid ICPR = new(ICPR_UUID);

    /// <summary>
    /// MS-IISS: Internet Information Services (IIS) ServiceControl
    /// </summary>
    private const string IISS_UUID = "e8fb8620-588f-11d2-9d61-00c04f79c5fe";

    /// <summary>
    /// MS-IISS: Internet Information Services (IIS) ServiceControl
    /// </summary>
    public static readonly Guid IISS = new(IISS_UUID);

    /// <summary>
    /// MS-IMSA: Internet Information Services (IIS) IMSAdminBaseW (IMSAdminBase3W interface)
    /// </summary>
    private const string IMSA_IMSAdminBase3W_UUID = "f612954d-3b0b-4c56-9563-227b7be624b4";

    /// <summary>
    /// MS-IMSA: Internet Information Services (IIS) IMSAdminBaseW (IMSAdminBase3W interface)
    /// </summary>
    public static readonly Guid IMSA_IMSAdminBase3W = new(IMSA_IMSAdminBase3W_UUID);

    /// <summary>
    /// MS-IMSA: Internet Information Services (IIS) IMSAdminBaseW (IMSAdminBase2W interface)
    /// </summary>
    private const string IMSA_IMSAdminBase2W_UUID = "8298d101-f992-43b7-8eca-5052d885b995";

    /// <summary>
    /// MS-IMSA: Internet Information Services (IIS) IMSAdminBaseW (IMSAdminBase2W interface)
    /// </summary>
    public static readonly Guid IMSA_IMSAdminBase2W = new(IMSA_IMSAdminBase2W_UUID);

    /// <summary>
    /// MS-IMSA: Internet Information Services (IIS) IMSAdminBaseW (IWamAdmin2 interface)
    /// </summary>
    private const string IMSA_IWamAdmin2_UUID = "29822ab8-f302-11d0-9953-00c04fd919c1";

    /// <summary>
    /// MS-IMSA: Internet Information Services (IIS) IMSAdminBaseW (IWamAdmin2 interface)
    /// </summary>
    public static readonly Guid IMSA_IWamAdmin2 = new(IMSA_IWamAdmin2_UUID);

    /// <summary>
    /// MS-IMSA: Internet Information Services (IIS) IMSAdminBaseW (IMSAdminBaseW interface)
    /// </summary>
    private const string IMSA_IMSAdminBaseW_UUID = "70b51430-b6ca-11d0-b9b9-00a0c922e750";

    /// <summary>
    /// MS-IMSA: Internet Information Services (IIS) IMSAdminBaseW (IMSAdminBaseW interface)
    /// </summary>
    public static readonly Guid IMSA_IMSAdminBaseW = new(IMSA_IMSAdminBaseW_UUID);

    /// <summary>
    /// MS-IMSA: Internet Information Services (IIS) IMSAdminBaseW (IWamAdmin interface)
    /// </summary>
    private const string IMSA_IWamAdmin_UUID = "29822ab7-f302-11d0-9953-00c04fd919c1";

    /// <summary>
    /// MS-IMSA: Internet Information Services (IIS) IMSAdminBaseW (IWamAdmin interface)
    /// </summary>
    public static readonly Guid IMSA_IWamAdmin = new(IMSA_IWamAdmin_UUID);

    /// <summary>
    /// MS-IMSA: Internet Information Services (IIS) IMSAdminBaseW (IIISCertObj interface)
    /// </summary>
    private const string IMSA_IIISCertObj_UUID = "bd0c73bc-805b-4043-9c30-9a28d64dd7d2";

    /// <summary>
    /// MS-IMSA: Internet Information Services (IIS) IMSAdminBaseW (IIISCertObj interface)
    /// </summary>
    public static readonly Guid IMSA_IIISCertObj = new(IMSA_IIISCertObj_UUID);

    /// <summary>
    /// MS-IMSA: Internet Information Services (IIS) IMSAdminBaseW (IIISApplicationAdmin interface)
    /// </summary>
    private const string IMSA_IIISApplicationAdmin_UUID = "7c4e1804-e342-483d-a43e-a850cfcc8d18";

    /// <summary>
    /// MS-IMSA: Internet Information Services (IIS) IMSAdminBaseW (IIISApplicationAdmin interface)
    /// </summary>
    public static readonly Guid IMSA_IIISApplicationAdmin = new(IMSA_IIISApplicationAdmin_UUID);

    /// <summary>
    /// MS-IOI: IManagedObject Interface Protocol (IRemoteDispatch interface)
    /// </summary>
    private const string IOI_IRemoteDispatch_UUID = "6619a740-8154-43be-a186-0319578e02db";

    /// <summary>
    /// MS-IOI: IManagedObject Interface Protocol (IRemoteDispatch interface)
    /// </summary>
    public static readonly Guid IOI_IRemoteDispatch = new(IOI_IRemoteDispatch_UUID);

    /// <summary>
    /// MS-IOI: IManagedObject Interface Protocol (IServicedComponentInfo interface)
    /// </summary>
    private const string IOI_IServicedComponentInfo_UUID = "8165b19e-8d3a-4d0b-80c8-97de310db583";

    /// <summary>
    /// MS-IOI: IManagedObject Interface Protocol (IServicedComponentInfo interface)
    /// </summary>
    public static readonly Guid IOI_IServicedComponentInfo = new(IOI_IServicedComponentInfo_UUID);

    /// <summary>
    /// MS-IOI: IManagedObject Interface Protocol (IManagedObject interface)
    /// </summary>
    private const string IOI_IManagedObject_UUID = "c3fcc19e-a970-11d2-8b5a-00a0c9b7c9c4";

    /// <summary>
    /// MS-IOI: IManagedObject Interface Protocol (IManagedObject interface)
    /// </summary>
    public static readonly Guid IOI_IManagedObject = new(IOI_IManagedObject_UUID);

    /// <summary>
    /// MS-IRP: Internet Information Services (IIS) Inetinfo Remote Protocol
    /// </summary>
    private const string IRP_UUID = "82ad4280-036b-11cf-972c-00aa006887b0";

    /// <summary>
    /// MS-IRP: Internet Information Services (IIS) Inetinfo Remote Protocol
    /// </summary>
    public static readonly Guid IRP = new(IRP_UUID);

    /// <summary>
    /// MS-LREC: Live Remote Event Capture (LREC) Protocol
    /// </summary>
    private const string LREC_UUID = "22e5386d-8b12-4bf0-b0ec-6a1ea419e366";

    /// <summary>
    /// MS-LREC: Live Remote Event Capture (LREC) Protocol
    /// </summary>
    public static readonly Guid LREC = new(LREC_UUID);

    /// <summary>
    /// MS-LSAT: Local Security Authority (Translation Methods) Remote Protocol
    /// </summary>
    /// <remarks>The UUID is the same as MS-LSAD.</remarks>
    private const string LSAT_UUID = "12345778-1234-abcd-ef00-0123456789ab";

    /// <summary>
    /// MS-LSAT: Local Security Authority (Translation Methods) Remote Protocol
    /// </summary>
    public static readonly Guid LSAT = new(LSAT_UUID);

    /// <summary>
    /// MS-LSAD: Local Security Authority (Domain Policy) Remote Protocol
    /// </summary>
    /// <remarks>The UUID is the same as MS-LSAT.</remarks>
    private const string LSAD_UUID = "12345778-1234-abcd-ef00-0123456789ab";

    /// <summary>
    /// MS-LSAD: Local Security Authority (Domain Policy) Remote Protocol
    /// </summary>
    public static readonly Guid LSAD = new(LSAD_UUID);

    /// <summary>
    /// MS-MQDS: Message Queuing (MSMQ): Directory Service Protocol (dscomm2 interface)
    /// </summary>
    private const string MQDS_dscomm2_UUID = "708cca10-9569-11d1-b2a5-0060977d8118";

    /// <summary>
    /// MS-MQDS: Message Queuing (MSMQ): Directory Service Protocol (dscomm2 interface)
    /// </summary>
    public static readonly Guid MQDS_dscomm2 = new(MQDS_dscomm2_UUID);

    /// <summary>
    /// MS-MQDS: Message Queuing (MSMQ): Directory Service Protocol (dscomm interface)
    /// </summary>
    private const string MQDS_dscomm_UUID = "77df7a80-f298-11d0-8358-00a024c480a8";

    /// <summary>
    /// MS-MQDS: Message Queuing (MSMQ): Directory Service Protocol (dscomm interface)
    /// </summary>
    public static readonly Guid MQDS_dscomm = new(MQDS_dscomm_UUID);

    /// <summary>
    /// MS-MQMP: Message Queuing (MSMQ): Queue Manager Client Protocol (qmcomm2 interface)
    /// </summary>
    private const string MQMP_qmcomm2_UUID = "76d12b80-3467-11d3-91ff-0090272f9ea3";

    /// <summary>
    /// MS-MQMP: Message Queuing (MSMQ): Queue Manager Client Protocol (qmcomm2 interface)
    /// </summary>
    public static readonly Guid MQMP_qmcomm2 = new(MQMP_qmcomm2_UUID);

    /// <summary>
    /// MS-MQMP: Message Queuing (MSMQ): Queue Manager Client Protocol (qmcomm interface)
    /// </summary>
    private const string MQMP_qmcomm_UUID = "fdb3a030-065f-11d1-bb9b-00a024ea5525";

    /// <summary>
    /// MS-MQMP: Message Queuing (MSMQ): Queue Manager Client Protocol (qmcomm interface)
    /// </summary>
    public static readonly Guid MQMP_qmcomm = new(MQMP_qmcomm_UUID);

    /// <summary>
    /// MS-MQMR: Message Queuing (MSMQ): Queue Manager Management Protocol
    /// </summary>
    private const string MQMR_UUID = "41208ee0-e970-11d1-9b9e-00e02c064c39";

    /// <summary>
    /// MS-MQMR: Message Queuing (MSMQ): Queue Manager Management Protocol
    /// </summary>
    public static readonly Guid MQMR = new(MQMR_UUID);

    /// <summary>
    /// MS-MQQP: Message Queuing (MSMQ): Queue Manager to Queue Manager Protocol
    /// </summary>
    private const string MQQP_UUID = "1088a980-eae5-11d0-8d9b-00a02453c337";

    /// <summary>
    /// MS-MQQP: Message Queuing (MSMQ): Queue Manager to Queue Manager Protocol
    /// </summary>
    public static readonly Guid MQQP = new(MQQP_UUID);

    /// <summary>
    /// MS-MQRR: Message Queuing (MSMQ): Queue Manager Remote Read Protocol
    /// </summary>
    private const string MQRR_UUID = "1a9134dd-7b39-45ba-ad88-44d01ca47f28";

    /// <summary>
    /// MS-MQRR: Message Queuing (MSMQ): Queue Manager Remote Read Protocol
    /// </summary>
    public static readonly Guid MQRR = new(MQRR_UUID);

    /// <summary>
    /// MS-MSRP: Messenger Service Remote Protocol (msgsvc interface)
    /// </summary>
    private const string MSRP_msgsvc_UUID = "17fdd703-1827-4e34-79d4-24a55c53bb37";

    /// <summary>
    /// MS-MSRP: Messenger Service Remote Protocol (msgsvc interface)
    /// </summary>
    public static readonly Guid MSRP_msgsvc = new(MSRP_msgsvc_UUID);

    /// <summary>
    /// MS-MSRP: Messenger Service Remote Protocol (msgsvcsend interface)
    /// </summary>
    private const string MSRP_msgsvcsend_UUID = "5a7b91f8-ff00-11d0-a9b2-00c04fb6e6fc";

    /// <summary>
    /// MS-MSRP: Messenger Service Remote Protocol (msgsvcsend interface)
    /// </summary>
    public static readonly Guid MSRP_msgsvcsend = new(MSRP_msgsvcsend_UUID);

    /// <summary>
    /// MS-NRPC: Netlogon Remote Protocol
    /// </summary>
    private const string NRPC_UUID = "12345678-1234-abcd-ef00-01234567cffb";

    /// <summary>
    /// MS-NRPC: Netlogon Remote Protocol
    /// </summary>
    public static readonly Guid NRPC = new(NRPC_UUID);

    /// <summary>
    /// MS-NSPI: Name Service Provider Interface (NSPI) Protocol
    /// </summary>
    private const string NSPI_UUID = "f5cc5a18-4264-101a-8c59-08002b2f8426";

    /// <summary>
    /// MS-NSPI: Name Service Provider Interface (NSPI) Protocol
    /// </summary>
    public static readonly Guid NSPI = new(NSPI_UUID);

    /// <summary>
    /// MS-OAUT: OLE Automation Protocol (IDispatch interface)
    /// </summary>
    private const string OAUT_IDispatch_UUID = "00020400-0000-0000-c000-000000000046";

    /// <summary>
    /// MS-OAUT: OLE Automation Protocol (IDispatch interface)
    /// </summary>
    public static readonly Guid OAUT_IDispatch = new(OAUT_IDispatch_UUID);

    /// <summary>
    /// MS-OAUT: OLE Automation Protocol (ITypeInfo interface)
    /// </summary>
    private const string OAUT_ITypeInfo_UUID = "00020401-0000-0000-c000-000000000046";

    /// <summary>
    /// MS-OAUT: OLE Automation Protocol (ITypeInfo interface)
    /// </summary>
    public static readonly Guid OAUT_ITypeInfo = new(OAUT_ITypeInfo_UUID);

    /// <summary>
    /// MS-OAUT: OLE Automation Protocol (ITypeLib interface)
    /// </summary>
    private const string OAUT_ITypeLib_UUID = "00020402-0000-0000-c000-000000000046";

    /// <summary>
    /// MS-OAUT: OLE Automation Protocol (ITypeLib interface)
    /// </summary>
    public static readonly Guid OAUT_ITypeLib = new(OAUT_ITypeLib_UUID);

    /// <summary>
    /// MS-OAUT: OLE Automation Protocol (ITypeComp interface)
    /// </summary>
    private const string OAUT_ITypeComp_UUID = "00020403-0000-0000-c000-000000000046";

    /// <summary>
    /// MS-OAUT: OLE Automation Protocol (ITypeComp interface)
    /// </summary>
    public static readonly Guid OAUT_ITypeComp = new(OAUT_ITypeComp_UUID);

    /// <summary>
    /// MS-OAUT: OLE Automation Protocol (IEnumVARIANT interface)
    /// </summary>
    private const string OAUT_IEnumVARIANT_UUID = "00020404-0000-0000-c000-000000000046";

    /// <summary>
    /// MS-OAUT: OLE Automation Protocol (IEnumVARIANT interface)
    /// </summary>
    public static readonly Guid OAUT_IEnumVARIANT = new(OAUT_IEnumVARIANT_UUID);

    /// <summary>
    /// MS-OAUT: OLE Automation Protocol (ITypeLib2 interface)
    /// </summary>
    private const string OAUT_ITypeLib2_UUID = "00020411-0000-0000-c000-000000000046";

    /// <summary>
    /// MS-OAUT: OLE Automation Protocol (ITypeLib2 interface)
    /// </summary>
    public static readonly Guid OAUT_ITypeLib2 = new(OAUT_ITypeLib2_UUID);

    /// <summary>
    /// MS-OAUT: OLE Automation Protocol (ITypeInfo2 interface)
    /// </summary>
    private const string OAUT_ITypeInfo2_UUID = "00020412-0000-0000-c000-000000000046";

    /// <summary>
    /// MS-OAUT: OLE Automation Protocol (ITypeInfo2 interface)
    /// </summary>
    public static readonly Guid OAUT_ITypeInfo2 = new(OAUT_ITypeInfo2_UUID);

    /// <summary>
    /// MS-OCSPA: Microsoft OCSP Administration Protocol
    /// </summary>
    private const string OCSPA_UUID = "784b693d-95f3-420b-8126-365c098659f2";

    /// <summary>
    /// MS-OCSPA: Microsoft OCSP Administration Protocol
    /// </summary>
    public static readonly Guid OCSPA = new(OCSPA_UUID);

    /// <summary>
    /// MS-OXABREF: Microsoft Exchange: Address Book Name Service Provider Interface (NSPI) Referral Protocol
    /// </summary>
    private const string OXABREF_UUID = "1544f5e0-613c-11d1-93df-00c04fd7bd09";

    /// <summary>
    /// MS-OXABREF: Microsoft Exchange: Address Book Name Service Provider Interface (NSPI) Referral Protocol
    /// </summary>
    public static readonly Guid OXABREF = new(OXABREF_UUID);

    /// <summary>
    /// MS-OXCRPC: Microsoft Exchange: Wire Protocol Format (emsmdb interface)
    /// </summary>
    private const string OXCRPC_emsmdb_UUID = "a4f1db00-ca47-1067-b31f-00dd010662da";

    /// <summary>
    /// MS-OXCRPC: Microsoft Exchange: Wire Protocol Format (emsmdb interface)
    /// </summary>
    public static readonly Guid OXCRPC_emsmdb = new(OXCRPC_emsmdb_UUID);

    /// <summary>
    /// MS-OXCRPC: Microsoft Exchange: Wire Protocol Format (asyncemsmdb interface)
    /// </summary>
    private const string OXCRPC_asyncemsmdb_UUID = "5261574a-4572-206e-b268-6b199213b4e4";

    /// <summary>
    /// MS-OXCRPC: Microsoft Exchange: Wire Protocol Format (asyncemsmdb interface)
    /// </summary>
    public static readonly Guid OXCRPC_asyncemsmdb = new(OXCRPC_asyncemsmdb_UUID);

    /// <summary>
    /// MS-PAN: Print System Asynchronous Notification Protocol (IRPCRemoteObject interface)
    /// </summary>
    private const string PAN_IRPCRemoteObject_UUID = "ae33069b-a2a8-46ee-a235-ddfd339be281";

    /// <summary>
    /// MS-PAN: Print System Asynchronous Notification Protocol (IRPCRemoteObject interface)
    /// </summary>
    public static readonly Guid PAN_IRPCRemoteObject = new(PAN_IRPCRemoteObject_UUID);

    /// <summary>
    /// MS-PAN: Print System Asynchronous Notification Protocol (IRPCAsyncNotify interface)
    /// </summary>
    private const string PAN_IRPCAsyncNotify_UUID = "0b6edbfa-4a24-4fc6-8a23-942b1eca65d1";

    /// <summary>
    /// MS-PAN: Print System Asynchronous Notification Protocol (IRPCAsyncNotify interface)
    /// </summary>
    public static readonly Guid PAN_IRPCAsyncNotify = new(PAN_IRPCAsyncNotify_UUID);

    /// <summary>
    /// MS-PAR: Print System Asynchronous Remote Protocol
    /// </summary>
    private const string PAR_UUID = "76f03f96-cdfd-44fc-a22c-64950a001209";

    /// <summary>
    /// MS-PAR: Print System Asynchronous Remote Protocol
    /// </summary>
    public static readonly Guid PAR = new(PAR_UUID);

    /// <summary>
    /// MS-PCQ: Performance Counter Query Protocol
    /// </summary>
    private const string PCQ_UUID = "da5a86c5-12c2-4943-ab30-7f74a813d853";

    /// <summary>
    /// MS-PCQ: Performance Counter Query Protocol
    /// </summary>
    public static readonly Guid PCQ = new(PCQ_UUID);

    /// <summary>
    /// MS-PLA: Performance Logs and Alerts Protocol (ITraceDataProviderCollection interface)
    /// </summary>
    private const string PLA_ITraceDataProviderCollection_UUID = "03837510-098b-11d8-9414-505054503030";

    /// <summary>
    /// MS-PLA: Performance Logs and Alerts Protocol (ITraceDataProviderCollection interface)
    /// </summary>
    public static readonly Guid PLA_ITraceDataProviderCollection = new(PLA_ITraceDataProviderCollection_UUID);

    /// <summary>
    /// MS-PLA: Performance Logs and Alerts Protocol (IFolderAction interface)
    /// </summary>
    private const string PLA_IFolderAction_UUID = "03837543-098b-11d8-9414-505054503030";

    /// <summary>
    /// MS-PLA: Performance Logs and Alerts Protocol (IFolderAction interface)
    /// </summary>
    public static readonly Guid PLA_IFolderAction = new(PLA_IFolderAction_UUID);

    /// <summary>
    /// MS-PLA: Performance Logs and Alerts Protocol (IValueMapItem interface)
    /// </summary>
    private const string PLA_IValueMapItem_UUID = "03837533-098b-11d8-9414-505054503030";

    /// <summary>
    /// MS-PLA: Performance Logs and Alerts Protocol (IValueMapItem interface)
    /// </summary>
    public static readonly Guid PLA_IValueMapItem = new(PLA_IValueMapItem_UUID);

    /// <summary>
    /// MS-PLA: Performance Logs and Alerts Protocol (03837541 interface)
    /// </summary>
    private const string PLA_03837541_UUID = "03837541-098b-11d8-9414-505054503030";

    /// <summary>
    /// MS-PLA: Performance Logs and Alerts Protocol (03837541 interface)
    /// </summary>
    public static readonly Guid PLA_03837541 = new(PLA_03837541_UUID);

    /// <summary>
    /// MS-PLA: Performance Logs and Alerts Protocol (IFolderActionCollection interface)
    /// </summary>
    private const string PLA_IFolderActionCollection_UUID = "03837544-098b-11d8-9414-505054503030";

    /// <summary>
    /// MS-PLA: Performance Logs and Alerts Protocol (IFolderActionCollection interface)
    /// </summary>
    public static readonly Guid PLA_IFolderActionCollection = new(PLA_IFolderActionCollection_UUID);

    /// <summary>
    /// MS-PLA: Performance Logs and Alerts Protocol (IDataCollectorSetCollection interface)
    /// </summary>
    private const string PLA_IDataCollectorSetCollection_UUID = "03837524-098b-11d8-9414-505054503030";

    /// <summary>
    /// MS-PLA: Performance Logs and Alerts Protocol (IDataCollectorSetCollection interface)
    /// </summary>
    public static readonly Guid PLA_IDataCollectorSetCollection = new(PLA_IDataCollectorSetCollection_UUID);

    /// <summary>
    /// MS-PLA: Performance Logs and Alerts Protocol (ISchedule interface)
    /// </summary>
    private const string PLA_ISchedule_UUID = "0383753a-098b-11d8-9414-505054503030";

    /// <summary>
    /// MS-PLA: Performance Logs and Alerts Protocol (ISchedule interface)
    /// </summary>
    public static readonly Guid PLA_ISchedule = new(PLA_ISchedule_UUID);

    /// <summary>
    /// MS-PLA: Performance Logs and Alerts Protocol (IValueMap interface)
    /// </summary>
    private const string PLA_IValueMap_UUID = "03837534-098b-11d8-9414-505054503030";

    /// <summary>
    /// MS-PLA: Performance Logs and Alerts Protocol (IValueMap interface)
    /// </summary>
    public static readonly Guid PLA_IValueMap = new(PLA_IValueMap_UUID);

    /// <summary>
    /// MS-PLA: Performance Logs and Alerts Protocol (ITraceDataCollector interface)
    /// </summary>
    private const string PLA_ITraceDataCollector_UUID = "0383750b-098b-11d8-9414-505054503030";

    /// <summary>
    /// MS-PLA: Performance Logs and Alerts Protocol (ITraceDataCollector interface)
    /// </summary>
    public static readonly Guid PLA_ITraceDataCollector = new(PLA_ITraceDataCollector_UUID);

    /// <summary>
    /// MS-PLA: Performance Logs and Alerts Protocol (IApiTracingDataCollector interface)
    /// </summary>
    private const string PLA_IApiTracingDataCollector_UUID = "0383751a-098b-11d8-9414-505054503030";

    /// <summary>
    /// MS-PLA: Performance Logs and Alerts Protocol (IApiTracingDataCollector interface)
    /// </summary>
    public static readonly Guid PLA_IApiTracingDataCollector = new(PLA_IApiTracingDataCollector_UUID);

    /// <summary>
    /// MS-PLA: Performance Logs and Alerts Protocol (ITraceDataProvider interface)
    /// </summary>
    private const string PLA_ITraceDataProvider_UUID = "03837512-098b-11d8-9414-505054503030";

    /// <summary>
    /// MS-PLA: Performance Logs and Alerts Protocol (ITraceDataProvider interface)
    /// </summary>
    public static readonly Guid PLA_ITraceDataProvider = new(PLA_ITraceDataProvider_UUID);

    /// <summary>
    /// MS-PLA: Performance Logs and Alerts Protocol (IScheduleCollection interface)
    /// </summary>
    private const string PLA_IScheduleCollection_UUID = "0383753d-098b-11d8-9414-505054503030";

    /// <summary>
    /// MS-PLA: Performance Logs and Alerts Protocol (IScheduleCollection interface)
    /// </summary>
    public static readonly Guid PLA_IScheduleCollection = new(PLA_IScheduleCollection_UUID);

    /// <summary>
    /// MS-PLA: Performance Logs and Alerts Protocol (IPerformanceCounterDataCollector interface)
    /// </summary>
    private const string PLA_IPerformanceCounterDataCollector_UUID = "03837506-098b-11d8-9414-505054503030";

    /// <summary>
    /// MS-PLA: Performance Logs and Alerts Protocol (IPerformanceCounterDataCollector interface)
    /// </summary>
    public static readonly Guid PLA_IPerformanceCounterDataCollector = new(PLA_IPerformanceCounterDataCollector_UUID);

    /// <summary>
    /// MS-PLA: Performance Logs and Alerts Protocol (IDataCollectorSet interface)
    /// </summary>
    private const string PLA_IDataCollectorSet_UUID = "03837520-098b-11d8-9414-505054503030";

    /// <summary>
    /// MS-PLA: Performance Logs and Alerts Protocol (IDataCollectorSet interface)
    /// </summary>
    public static readonly Guid PLA_IDataCollectorSet = new(PLA_IDataCollectorSet_UUID);

    /// <summary>
    /// MS-PLA: Performance Logs and Alerts Protocol (IDataCollector interface)
    /// </summary>
    private const string PLA_IDataCollector_UUID = "038374ff-098b-11d8-9414-505054503030";

    /// <summary>
    /// MS-PLA: Performance Logs and Alerts Protocol (IDataCollector interface)
    /// </summary>
    public static readonly Guid PLA_IDataCollector = new(PLA_IDataCollector_UUID);

    /// <summary>
    /// MS-PLA: Performance Logs and Alerts Protocol (IConfigurationDataCollector interface)
    /// </summary>
    private const string PLA_IConfigurationDataCollector_UUID = "03837514-098b-11d8-9414-505054503030";

    /// <summary>
    /// MS-PLA: Performance Logs and Alerts Protocol (IConfigurationDataCollector interface)
    /// </summary>
    public static readonly Guid PLA_IConfigurationDataCollector = new(PLA_IConfigurationDataCollector_UUID);

    /// <summary>
    /// MS-PLA: Performance Logs and Alerts Protocol (IDataCollectorCollection interface)
    /// </summary>
    private const string PLA_IDataCollectorCollection_UUID = "03837502-098b-11d8-9414-505054503030";

    /// <summary>
    /// MS-PLA: Performance Logs and Alerts Protocol (IDataCollectorCollection interface)
    /// </summary>
    public static readonly Guid PLA_IDataCollectorCollection = new(PLA_IDataCollectorCollection_UUID);

    /// <summary>
    /// MS-PLA: Performance Logs and Alerts Protocol (IAlertDataCollector interface)
    /// </summary>
    private const string PLA_IAlertDataCollector_UUID = "03837516-098b-11d8-9414-505054503030";

    /// <summary>
    /// MS-PLA: Performance Logs and Alerts Protocol (IAlertDataCollector interface)
    /// </summary>
    public static readonly Guid PLA_IAlertDataCollector = new(PLA_IAlertDataCollector_UUID);

    /// <summary>
    /// MS-RAA: Remote Authorization API Protocol
    /// </summary>
    private const string RAA_UUID = "0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7";

    /// <summary>
    /// MS-RAA: Remote Authorization API Protocol
    /// </summary>
    public static readonly Guid RAA = new(RAA_UUID);

    /// <summary>
    /// MS-RAI: Remote Assistance Initiation Protocol (IRASrv interface)
    /// </summary>
    private const string RAI_IRASrv_UUID = "f120a684-b926-447f-9df4-c966cb785648";

    /// <summary>
    /// MS-RAI: Remote Assistance Initiation Protocol (IRASrv interface)
    /// </summary>
    public static readonly Guid RAI_IRASrv = new(RAI_IRASrv_UUID);

    /// <summary>
    /// MS-RAI: Remote Assistance Initiation Protocol (PCHService interface)
    /// </summary>
    private const string RAI_PCHService_UUID = "833e4010-aff7-4ac3-aac2-9f24c1457bce";

    /// <summary>
    /// MS-RAI: Remote Assistance Initiation Protocol (PCHService interface)
    /// </summary>
    public static readonly Guid RAI_PCHService = new(RAI_PCHService_UUID);

    /// <summary>
    /// MS-RAI: Remote Assistance Initiation Protocol (IPCHService interface)
    /// </summary>
    private const string RAI_IPCHService_UUID = "833e4200-aff7-4ac3-aac2-9f24c1457bce";

    /// <summary>
    /// MS-RAI: Remote Assistance Initiation Protocol (IPCHService interface)
    /// </summary>
    public static readonly Guid RAI_IPCHService = new(RAI_IPCHService_UUID);

    /// <summary>
    /// MS-RAI: Remote Assistance Initiation Protocol (RASrv interface)
    /// </summary>
    private const string RAI_RASrv_UUID = "3c3a70a7-a468-49b9-8ada-28e11fccad5d";

    /// <summary>
    /// MS-RAI: Remote Assistance Initiation Protocol (RASrv interface)
    /// </summary>
    public static readonly Guid RAI_RASrv = new(RAI_RASrv_UUID);

    /// <summary>
    /// MS-RAI: Remote Assistance Initiation Protocol (IPCHCollection interface)
    /// </summary>
    private const string RAI_IPCHCollection_UUID = "833e4100-aff7-4ac3-aac2-9f24c1457bce";

    /// <summary>
    /// MS-RAI: Remote Assistance Initiation Protocol (IPCHCollection interface)
    /// </summary>
    public static readonly Guid RAI_IPCHCollection = new(RAI_IPCHCollection_UUID);

    /// <summary>
    /// MS-RAI: Remote Assistance Initiation Protocol (ISAFSession interface)
    /// </summary>
    private const string RAI_ISAFSession_UUID = "833e41aa-aff7-4ac3-aac2-9f24c1457bce";

    /// <summary>
    /// MS-RAI: Remote Assistance Initiation Protocol (ISAFSession interface)
    /// </summary>
    public static readonly Guid RAI_ISAFSession = new(RAI_ISAFSession_UUID);

    /// <summary>
    /// MS-RAINPS: Remote Administrative Interface: NPS (IIASDataStoreComServer2 interface)
    /// </summary>
    private const string RAINPS_IIASDataStoreComServer2_UUID = "c323be28-e546-4c23-a81b-d6ad8d8fac7b";

    /// <summary>
    /// MS-RAINPS: Remote Administrative Interface: NPS (IIASDataStoreComServer2 interface)
    /// </summary>
    public static readonly Guid RAINPS_IIASDataStoreComServer2 = new(RAINPS_IIASDataStoreComServer2_UUID);

    /// <summary>
    /// MS-RAINPS: Remote Administrative Interface: NPS (IIASDataStoreComServer interface)
    /// </summary>
    private const string RAINPS_IIASDataStoreComServer_UUID = "83e05bd5-aec1-4e58-ae50-e819c7296f67";

    /// <summary>
    /// MS-RAINPS: Remote Administrative Interface: NPS (IIASDataStoreComServer interface)
    /// </summary>
    public static readonly Guid RAINPS_IIASDataStoreComServer = new(RAINPS_IIASDataStoreComServer_UUID);

    /// <summary>
    /// MS-RAIW: Remote Administrative Interface: WINS (winsif interface)
    /// </summary>
    private const string RAIW_winsif_UUID = "45f52c28-7f9f-101a-b52b-08002b2efabe";

    /// <summary>
    /// MS-RAIW: Remote Administrative Interface: WINS (winsif interface)
    /// </summary>
    public static readonly Guid RAIW_winsif = new(RAIW_winsif_UUID);

    /// <summary>
    /// MS-RAIW: Remote Administrative Interface: WINS (winsi2 interface)
    /// </summary>
    private const string RAIW_winsi2_UUID = "811109bf-a4e1-11d1-ab54-00a0c91e9b45";

    /// <summary>
    /// MS-RAIW: Remote Administrative Interface: WINS (winsi2 interface)
    /// </summary>
    public static readonly Guid RAIW_winsi2 = new(RAIW_winsi2_UUID);

    /// <summary>
    /// MS-RPCL: Remote Procedure Call Location Services Extensions
    /// </summary>
    private const string RPCL_UUID = "e33c0cc4-0482-101a-bc0c-02608c6ba218";

    /// <summary>
    /// MS-RPCL: Remote Procedure Call Location Services Extensions
    /// </summary>
    public static readonly Guid RPCL = new(RPCL_UUID);

    /// <summary>
    /// MS-RPRN: Print System Remote Protocol
    /// </summary>
    private const string RPRN_UUID = "12345678-1234-abcd-ef00-0123456789ab";

    /// <summary>
    /// MS-RPRN: Print System Remote Protocol
    /// </summary>
    public static readonly Guid RPRN = new(RPRN_UUID);

    /// <summary>
    /// MS-RRASM: Routing and Remote Access Server (RRAS) Management Protocol (rasrpc interface)
    /// </summary>
    private const string RRASM_rasrpc_UUID = "20610036-fa22-11cf-9823-00a0c911e5df";

    /// <summary>
    /// MS-RRASM: Routing and Remote Access Server (RRAS) Management Protocol (rasrpc interface)
    /// </summary>
    public static readonly Guid RRASM_rasrpc = new(RRASM_rasrpc_UUID);

    /// <summary>
    /// MS-RRASM: Routing and Remote Access Server (RRAS) Management Protocol (IRemoteSstpCertCheck interface)
    /// </summary>
    private const string RRASM_IRemoteSstpCertCheck_UUID = "5ff9bdf6-bd91-4d8b-a614-d6317acc8dd8";

    /// <summary>
    /// MS-RRASM: Routing and Remote Access Server (RRAS) Management Protocol (IRemoteSstpCertCheck interface)
    /// </summary>
    public static readonly Guid RRASM_IRemoteSstpCertCheck = new(RRASM_IRemoteSstpCertCheck_UUID);

    /// <summary>
    /// MS-RRASM: Routing and Remote Access Server (RRAS) Management Protocol (IRemoteIPV6Config interface)
    /// </summary>
    private const string RRASM_IRemoteIPV6Config_UUID = "6139d8a4-e508-4ebb-bac7-d7f275145897";

    /// <summary>
    /// MS-RRASM: Routing and Remote Access Server (RRAS) Management Protocol (IRemoteIPV6Config interface)
    /// </summary>
    public static readonly Guid RRASM_IRemoteIPV6Config = new(RRASM_IRemoteIPV6Config_UUID);

    /// <summary>
    /// MS-RRASM: Routing and Remote Access Server (RRAS) Management Protocol (IRemoteNetworkConfig interface)
    /// </summary>
    private const string RRASM_IRemoteNetworkConfig_UUID = "66a2db1b-d706-11d0-a37b-00c04fc9da04";

    /// <summary>
    /// MS-RRASM: Routing and Remote Access Server (RRAS) Management Protocol (IRemoteNetworkConfig interface)
    /// </summary>
    public static readonly Guid RRASM_IRemoteNetworkConfig = new(RRASM_IRemoteNetworkConfig_UUID);

    /// <summary>
    /// MS-RRASM: Routing and Remote Access Server (RRAS) Management Protocol (IRemoteRouterRestart interface)
    /// </summary>
    private const string RRASM_IRemoteRouterRestart_UUID = "66a2db20-d706-11d0-a37b-00c04fc9da04";

    /// <summary>
    /// MS-RRASM: Routing and Remote Access Server (RRAS) Management Protocol (IRemoteRouterRestart interface)
    /// </summary>
    public static readonly Guid RRASM_IRemoteRouterRestart = new(RRASM_IRemoteRouterRestart_UUID);

    /// <summary>
    /// MS-RRASM: Routing and Remote Access Server (RRAS) Management Protocol (IRemoteSetDnsConfig interface)
    /// </summary>
    private const string RRASM_IRemoteSetDnsConfig_UUID = "66a2db21-d706-11d0-a37b-00c04fc9da04";

    /// <summary>
    /// MS-RRASM: Routing and Remote Access Server (RRAS) Management Protocol (IRemoteSetDnsConfig interface)
    /// </summary>
    public static readonly Guid RRASM_IRemoteSetDnsConfig = new(RRASM_IRemoteSetDnsConfig_UUID);

    /// <summary>
    /// MS-RRASM: Routing and Remote Access Server (RRAS) Management Protocol (IRemoteICFICSConfig interface)
    /// </summary>
    private const string RRASM_IRemoteICFICSConfig_UUID = "66a2db22-d706-11d0-a37b-00c04fc9da04";

    /// <summary>
    /// MS-RRASM: Routing and Remote Access Server (RRAS) Management Protocol (IRemoteICFICSConfig interface)
    /// </summary>
    public static readonly Guid RRASM_IRemoteICFICSConfig = new(RRASM_IRemoteICFICSConfig_UUID);

    /// <summary>
    /// MS-RRASM: Routing and Remote Access Server (RRAS) Management Protocol (IRemoteStringIdConfig interface)
    /// </summary>
    private const string RRASM_IRemoteStringIdConfig_UUID = "67e08fc2-2984-4b62-b92e-fc1aae64bbbb";

    /// <summary>
    /// MS-RRASM: Routing and Remote Access Server (RRAS) Management Protocol (IRemoteStringIdConfig interface)
    /// </summary>
    public static readonly Guid RRASM_IRemoteStringIdConfig = new(RRASM_IRemoteStringIdConfig_UUID);

    /// <summary>
    /// MS-RRASM: Routing and Remote Access Server (RRAS) Management Protocol (dimsvc interface)
    /// </summary>
    private const string RRASM_dimsvc_UUID = "8f09f000-b7ed-11ce-bbd2-00001a181cad";

    /// <summary>
    /// MS-RRASM: Routing and Remote Access Server (RRAS) Management Protocol (dimsvc interface)
    /// </summary>
    public static readonly Guid RRASM_dimsvc = new(RRASM_dimsvc_UUID);

    /// <summary>
    /// MS-RRP: Windows Remote Registry Protocol
    /// </summary>
    private const string RRP_UUID = "338cd001-2244-31f1-aaaa-900038001003";

    /// <summary>
    /// MS-RRP: Windows Remote Registry Protocol
    /// </summary>
    public static readonly Guid RRP = new(RRP_UUID);

    /// <summary>
    /// MS-RSMP: Removable Storage Manager (RSM) Remote Protocol (INtmsObjectManagement3 interface)
    /// </summary>
    private const string RSMP_INtmsObjectManagement3_UUID = "3bbed8d9-2c9a-4b21-8936-acb2f995be6c";

    /// <summary>
    /// MS-RSMP: Removable Storage Manager (RSM) Remote Protocol (INtmsObjectManagement3 interface)
    /// </summary>
    public static readonly Guid RSMP_INtmsObjectManagement3 = new(RSMP_INtmsObjectManagement3_UUID);

    /// <summary>
    /// MS-RSMP: Removable Storage Manager (RSM) Remote Protocol (INtmsSession1 interface)
    /// </summary>
    private const string RSMP_INtmsSession1_UUID = "8da03f40-3419-11d1-8fb1-00a024cb6019";

    /// <summary>
    /// MS-RSMP: Removable Storage Manager (RSM) Remote Protocol (INtmsSession1 interface)
    /// </summary>
    public static readonly Guid RSMP_INtmsSession1 = new(RSMP_INtmsSession1_UUID);

    /// <summary>
    /// MS-RSMP: Removable Storage Manager (RSM) Remote Protocol (CNtmsSvr interface)
    /// </summary>
    private const string RSMP_CNtmsSvr_UUID = "d61a27c6-8f53-11d0-bfa0-00a024151983";

    /// <summary>
    /// MS-RSMP: Removable Storage Manager (RSM) Remote Protocol (CNtmsSvr interface)
    /// </summary>
    public static readonly Guid RSMP_CNtmsSvr = new(RSMP_CNtmsSvr_UUID);

    /// <summary>
    /// MS-RSMP: Removable Storage Manager (RSM) Remote Protocol (IMessenger interface)
    /// </summary>
    private const string RSMP_IMessenger_UUID = "081e7188-c080-4ff3-9238-29f66d6cabfd";

    /// <summary>
    /// MS-RSMP: Removable Storage Manager (RSM) Remote Protocol (IMessenger interface)
    /// </summary>
    public static readonly Guid RSMP_IMessenger = new(RSMP_IMessenger_UUID);

    /// <summary>
    /// MS-RSMP: Removable Storage Manager (RSM) Remote Protocol (INtmsObjectManagement2 interface)
    /// </summary>
    private const string RSMP_INtmsObjectManagement2_UUID = "895a2c86-270d-489d-a6c0-dc2a9b35280e";

    /// <summary>
    /// MS-RSMP: Removable Storage Manager (RSM) Remote Protocol (INtmsObjectManagement2 interface)
    /// </summary>
    public static readonly Guid RSMP_INtmsObjectManagement2 = new(RSMP_INtmsObjectManagement2_UUID);

    /// <summary>
    /// MS-RSMP: Removable Storage Manager (RSM) Remote Protocol (INtmsMediaServices1 interface)
    /// </summary>
    private const string RSMP_INtmsMediaServices1_UUID = "d02e4be0-3419-11d1-8fb1-00a024cb6019";

    /// <summary>
    /// MS-RSMP: Removable Storage Manager (RSM) Remote Protocol (INtmsMediaServices1 interface)
    /// </summary>
    public static readonly Guid RSMP_INtmsMediaServices1 = new(RSMP_INtmsMediaServices1_UUID);

    /// <summary>
    /// MS-RSMP: Removable Storage Manager (RSM) Remote Protocol (INtmsLibraryControl2 interface)
    /// </summary>
    private const string RSMP_INtmsLibraryControl2_UUID = "db90832f-6910-4d46-9f5e-9fd6bfa73903";

    /// <summary>
    /// MS-RSMP: Removable Storage Manager (RSM) Remote Protocol (INtmsLibraryControl2 interface)
    /// </summary>
    public static readonly Guid RSMP_INtmsLibraryControl2 = new(RSMP_INtmsLibraryControl2_UUID);

    /// <summary>
    /// MS-RSMP: Removable Storage Manager (RSM) Remote Protocol (INtmsLibraryControl1 interface)
    /// </summary>
    private const string RSMP_INtmsLibraryControl1_UUID = "4e934f30-341a-11d1-8fb1-00a024cb6019";

    /// <summary>
    /// MS-RSMP: Removable Storage Manager (RSM) Remote Protocol (INtmsLibraryControl1 interface)
    /// </summary>
    public static readonly Guid RSMP_INtmsLibraryControl1 = new(RSMP_INtmsLibraryControl1_UUID);

    /// <summary>
    /// MS-RSMP: Removable Storage Manager (RSM) Remote Protocol (IClientSink interface)
    /// </summary>
    private const string RSMP_IClientSink_UUID = "879c8bbe-41b0-11d1-be11-00c04fb6bf70";

    /// <summary>
    /// MS-RSMP: Removable Storage Manager (RSM) Remote Protocol (IClientSink interface)
    /// </summary>
    public static readonly Guid RSMP_IClientSink = new(RSMP_IClientSink_UUID);

    /// <summary>
    /// MS-RSMP: Removable Storage Manager (RSM) Remote Protocol (INtmsObjectInfo1 interface)
    /// </summary>
    private const string RSMP_INtmsObjectInfo1_UUID = "69ab7050-3059-11d1-8faf-00a024cb6019";

    /// <summary>
    /// MS-RSMP: Removable Storage Manager (RSM) Remote Protocol (INtmsObjectInfo1 interface)
    /// </summary>
    public static readonly Guid RSMP_INtmsObjectInfo1 = new(RSMP_INtmsObjectInfo1_UUID);

    /// <summary>
    /// MS-RSMP: Removable Storage Manager (RSM) Remote Protocol (IRobustNtmsMediaServices1 interface)
    /// </summary>
    private const string RSMP_IRobustNtmsMediaServices1_UUID = "7d07f313-a53f-459a-bb12-012c15b1846e";

    /// <summary>
    /// MS-RSMP: Removable Storage Manager (RSM) Remote Protocol (IRobustNtmsMediaServices1 interface)
    /// </summary>
    public static readonly Guid RSMP_IRobustNtmsMediaServices1 = new(RSMP_IRobustNtmsMediaServices1_UUID);

    /// <summary>
    /// MS-RSMP: Removable Storage Manager (RSM) Remote Protocol (INtmsNotifySink interface)
    /// </summary>
    private const string RSMP_INtmsNotifySink_UUID = "bb39332c-bfee-4380-ad8a-badc8aff5bb6";

    /// <summary>
    /// MS-RSMP: Removable Storage Manager (RSM) Remote Protocol (INtmsNotifySink interface)
    /// </summary>
    public static readonly Guid RSMP_INtmsNotifySink = new(RSMP_INtmsNotifySink_UUID);

    /// <summary>
    /// MS-RSMP: Removable Storage Manager (RSM) Remote Protocol (INtmsObjectManagement1 interface)
    /// </summary>
    private const string RSMP_INtmsObjectManagement1_UUID = "b057dc50-3059-11d1-8faf-00a024cb6019";

    /// <summary>
    /// MS-RSMP: Removable Storage Manager (RSM) Remote Protocol (INtmsObjectManagement1 interface)
    /// </summary>
    public static readonly Guid RSMP_INtmsObjectManagement1 = new(RSMP_INtmsObjectManagement1_UUID);

    /// <summary>
    /// MS-RSP: Remote Shutdown Protocol (InitShutdown interface)
    /// </summary>
    private const string RSP_InitShutdown_UUID = "894de0c0-0d55-11d3-a322-00c04fa321a1";

    /// <summary>
    /// MS-RSP: Remote Shutdown Protocol (InitShutdown interface)
    /// </summary>
    public static readonly Guid RSP_InitShutdown = new(RSP_InitShutdown_UUID);

    /// <summary>
    /// MS-RSP: Remote Shutdown Protocol (WindowsShutdown interface)
    /// </summary>
    private const string RSP_WindowsShutdown_UUID = "d95afe70-a6d5-4259-822e-2c84da1ddb0d";

    /// <summary>
    /// MS-RSP: Remote Shutdown Protocol (WindowsShutdown interface)
    /// </summary>
    public static readonly Guid RSP_WindowsShutdown = new(RSP_WindowsShutdown_UUID);

    /// <summary>
    /// MS-SAMR: Security Account Manager (SAM) Remote Protocol (Client-to-Server)
    /// </summary>
    private const string SAMR_UUID = "12345778-1234-abcd-ef00-0123456789ac";

    /// <summary>
    /// MS-SAMR: Security Account Manager (SAM) Remote Protocol (Client-to-Server)
    /// </summary>
    public static readonly Guid SAMR = new(SAMR_UUID);

    /// <summary>
    /// MS-SCMP: Shadow Copy Management Protocol (IVssEnumMgmtObject interface)
    /// </summary>
    private const string SCMP_IVssEnumMgmtObject_UUID = "01954e6b-9254-4e6e-808c-c9e05d007696";

    /// <summary>
    /// MS-SCMP: Shadow Copy Management Protocol (IVssEnumMgmtObject interface)
    /// </summary>
    public static readonly Guid SCMP_IVssEnumMgmtObject = new(SCMP_IVssEnumMgmtObject_UUID);

    /// <summary>
    /// MS-SCMP: Shadow Copy Management Protocol (IVssSnapshotMgmt interface)
    /// </summary>
    private const string SCMP_IVssSnapshotMgmt_UUID = "fa7df749-66e7-4986-a27f-e2f04ae53772";

    /// <summary>
    /// MS-SCMP: Shadow Copy Management Protocol (IVssSnapshotMgmt interface)
    /// </summary>
    public static readonly Guid SCMP_IVssSnapshotMgmt = new(SCMP_IVssSnapshotMgmt_UUID);

    /// <summary>
    /// MS-SCMP: Shadow Copy Management Protocol (IVssDifferentialSoftwareSnapshotMgmt interface)
    /// </summary>
    private const string SCMP_IVssDifferentialSoftwareSnapshotMgmt_UUID = "214a0f28-b737-4026-b847-4f9e37d79529";

    /// <summary>
    /// MS-SCMP: Shadow Copy Management Protocol (IVssDifferentialSoftwareSnapshotMgmt interface)
    /// </summary>
    public static readonly Guid SCMP_IVssDifferentialSoftwareSnapshotMgmt = new(SCMP_IVssDifferentialSoftwareSnapshotMgmt_UUID);

    /// <summary>
    /// MS-SCMP: Shadow Copy Management Protocol (IVssEnumObject interface)
    /// </summary>
    private const string SCMP_IVssEnumObject_UUID = "ae1c7110-2f60-11d3-8a39-00c04f72d8e3";

    /// <summary>
    /// MS-SCMP: Shadow Copy Management Protocol (IVssEnumObject interface)
    /// </summary>
    public static readonly Guid SCMP_IVssEnumObject = new(SCMP_IVssEnumObject_UUID);

    /// <summary>
    /// MS-SCMR: Service Control Manager Remote Protocol
    /// </summary>
    private const string SCMR_UUID = "367abb81-9844-35f1-ad32-98f038001003";

    /// <summary>
    /// MS-SCMR: Service Control Manager Remote Protocol
    /// </summary>
    public static readonly Guid SCMR = new(SCMR_UUID);

    /// <summary>
    /// MS-SRVS: Server Service Remote Protocol
    /// </summary>
    private const string SRVS_UUID = "4b324fc8-1670-01d3-1278-5a47bf6ee188";

    /// <summary>
    /// MS-SRVS: Server Service Remote Protocol
    /// </summary>
    public static readonly Guid SRVS = new(SRVS_UUID);

    /// <summary>
    /// MS-SWN: Service Witness Protocol
    /// </summary>
    private const string SWN_UUID = "ccd8c074-d0e5-4a40-92b4-d074faa6ba28";

    /// <summary>
    /// MS-SWN: Service Witness Protocol
    /// </summary>
    public static readonly Guid SWN = new(SWN_UUID);

    /// <summary>
    /// MS-TPMVSC: Trusted Platform Module (TPM) Virtual Smart Card Management Protocol (ITpmVirtualSmartCardManagerStatusCallback interface)
    /// </summary>
    private const string TPMVSC_ITpmVirtualSmartCardManagerStatusCallback_UUID = "1a1bb35f-abb8-451c-a1ae-33d98f1bef4a";

    /// <summary>
    /// MS-TPMVSC: Trusted Platform Module (TPM) Virtual Smart Card Management Protocol (ITpmVirtualSmartCardManagerStatusCallback interface)
    /// </summary>
    public static readonly Guid TPMVSC_ITpmVirtualSmartCardManagerStatusCallback = new(TPMVSC_ITpmVirtualSmartCardManagerStatusCallback_UUID);

    /// <summary>
    /// MS-TPMVSC: Trusted Platform Module (TPM) Virtual Smart Card Management Protocol (ITpmVirtualSmartCardManager2 interface)
    /// </summary>
    private const string TPMVSC_ITpmVirtualSmartCardManager2_UUID = "fdf8a2b9-02de-47f4-bc26-aa85ab5e5267";

    /// <summary>
    /// MS-TPMVSC: Trusted Platform Module (TPM) Virtual Smart Card Management Protocol (ITpmVirtualSmartCardManager2 interface)
    /// </summary>
    public static readonly Guid TPMVSC_ITpmVirtualSmartCardManager2 = new(TPMVSC_ITpmVirtualSmartCardManager2_UUID);

    /// <summary>
    /// MS-TPMVSC: Trusted Platform Module (TPM) Virtual Smart Card Management Protocol (ITpmVirtualSmartCardManager interface)
    /// </summary>
    private const string TPMVSC_ITpmVirtualSmartCardManager_UUID = "112b1dff-d9dc-41f7-869f-d67fee7cb591";

    /// <summary>
    /// MS-TPMVSC: Trusted Platform Module (TPM) Virtual Smart Card Management Protocol (ITpmVirtualSmartCardManager interface)
    /// </summary>
    public static readonly Guid TPMVSC_ITpmVirtualSmartCardManager = new(TPMVSC_ITpmVirtualSmartCardManager_UUID);

    /// <summary>
    /// MS-TPMVSC: Trusted Platform Module (TPM) Virtual Smart Card Management Protocol (ITpmVirtualSmartCardManager3 interface)
    /// </summary>
    private const string TPMVSC_ITpmVirtualSmartCardManager3_UUID = "3c745a97-f375-4150-be17-5950f694c699";

    /// <summary>
    /// MS-TPMVSC: Trusted Platform Module (TPM) Virtual Smart Card Management Protocol (ITpmVirtualSmartCardManager3 interface)
    /// </summary>
    public static readonly Guid TPMVSC_ITpmVirtualSmartCardManager3 = new(TPMVSC_ITpmVirtualSmartCardManager3_UUID);

    /// <summary>
    /// MS-TRP: Telephony Remote Protocol (remotesp interface)
    /// </summary>
    private const string TRP_remotesp_UUID = "2f5f6521-ca47-1068-b319-00dd010662db";

    /// <summary>
    /// MS-TRP: Telephony Remote Protocol (remotesp interface)
    /// </summary>
    public static readonly Guid TRP_remotesp = new(TRP_remotesp_UUID);

    /// <summary>
    /// MS-TRP: Telephony Remote Protocol (tapsrv interface)
    /// </summary>
    private const string TRP_tapsrv_UUID = "2f5f6520-ca46-1067-b319-00dd010662da";

    /// <summary>
    /// MS-TRP: Telephony Remote Protocol (tapsrv interface)
    /// </summary>
    public static readonly Guid TRP_tapsrv = new(TRP_tapsrv_UUID);

    /// <summary>
    /// MS-TSCH: Task Scheduler Service Remoting Protocol (atsvc interface)
    /// </summary>
    private const string TSCH_ATSvc_UUID = "1ff70682-0a51-30e8-076d-740be8cee98b";

    /// <summary>
    /// MS-TSCH: Task Scheduler Service Remoting Protocol (atsvc interface)
    /// </summary>
    public static readonly Guid TSCH_ATSvc = new(TSCH_ATSvc_UUID);

    /// <summary>
    /// MS-TSCH: Task Scheduler Service Remoting Protocol (sasec interface)
    /// </summary>
    private const string TSCH_SASec_UUID = "378e52b0-c0a9-11cf-822d-00aa0051e40f";

    /// <summary>
    /// MS-TSCH: Task Scheduler Service Remoting Protocol (sasec interface)
    /// </summary>
    public static readonly Guid TSCH_SASec = new(TSCH_SASec_UUID);

    /// <summary>
    /// MS-TSCH: Task Scheduler Service Remoting Protocol (ITaskSchedulerService interface)
    /// </summary>
    private const string TSCH_ITaskSchedulerService_UUID = "86d35949-83c9-4044-b424-db363231fd0c";

    /// <summary>
    /// MS-TSCH: Task Scheduler Service Remoting Protocol (ITaskSchedulerService interface)
    /// </summary>
    public static readonly Guid TSCH_ITaskSchedulerService = new(TSCH_ITaskSchedulerService_UUID);

    /// <summary>
    /// MS-TSGU: Terminal Services Gateway Server Protocol
    /// </summary>
    private const string TSGU_UUID = "44e265dd-7daf-42cd-8560-3cdb6e7a2729";

    /// <summary>
    /// MS-TSGU: Terminal Services Gateway Server Protocol
    /// </summary>
    public static readonly Guid TSGU = new(TSGU_UUID);

    /// <summary>
    /// MS-TSRAP: Telnet Server Remote Administration Protocol
    /// </summary>
    private const string TSRAP_UUID = "034634fd-ba3f-11d1-856a-00a0c944138c";

    /// <summary>
    /// MS-TSRAP: Telnet Server Remote Administration Protocol
    /// </summary>
    public static readonly Guid TSRAP = new(TSRAP_UUID);

    /// <summary>
    /// MS-TSTS: Terminal Services Terminal Server Runtime Interface Protocol (RCMListener interface)
    /// </summary>
    private const string TSTS_RCMListener_UUID = "497d95a6-2d27-4bf5-9bbd-a6046957133c";

    /// <summary>
    /// MS-TSTS: Terminal Services Terminal Server Runtime Interface Protocol (RCMListener interface)
    /// </summary>
    public static readonly Guid TSTS_RCMListener = new(TSTS_RCMListener_UUID);

    /// <summary>
    /// MS-TSTS: Terminal Services Terminal Server Runtime Interface Protocol (TermSrvNotification interface)
    /// </summary>
    private const string TSTS_TermSrvNotification_UUID = "11899a43-2b68-4a76-92e3-a3d6ad8c26ce";

    /// <summary>
    /// MS-TSTS: Terminal Services Terminal Server Runtime Interface Protocol (TermSrvNotification interface)
    /// </summary>
    public static readonly Guid TSTS_TermSrvNotification = new(TSTS_TermSrvNotification_UUID);

    /// <summary>
    /// MS-TSTS: Terminal Services Terminal Server Runtime Interface Protocol (IcaApi interface)
    /// </summary>
    private const string TSTS_IcaApi_UUID = "5ca4a760-ebb1-11cf-8611-00a0245420ed";

    /// <summary>
    /// MS-TSTS: Terminal Services Terminal Server Runtime Interface Protocol (IcaApi interface)
    /// </summary>
    public static readonly Guid TSTS_IcaApi = new(TSTS_IcaApi_UUID);

    /// <summary>
    /// MS-TSTS: Terminal Services Terminal Server Runtime Interface Protocol (RCMPublic interface)
    /// </summary>
    private const string TSTS_RCMPublic_UUID = "bde95fdf-eee0-45de-9e12-e5a61cd0d4fe";

    /// <summary>
    /// MS-TSTS: Terminal Services Terminal Server Runtime Interface Protocol (RCMPublic interface)
    /// </summary>
    public static readonly Guid TSTS_RCMPublic = new(TSTS_RCMPublic_UUID);

    /// <summary>
    /// MS-TSTS: Terminal Services Terminal Server Runtime Interface Protocol (TermSrvSession interface)
    /// </summary>
    private const string TSTS_TermSrvSession_UUID = "484809d6-4239-471b-b5bc-61df8c23ac48";

    /// <summary>
    /// MS-TSTS: Terminal Services Terminal Server Runtime Interface Protocol (TermSrvSession interface)
    /// </summary>
    public static readonly Guid TSTS_TermSrvSession = new(TSTS_TermSrvSession_UUID);

    /// <summary>
    /// MS-TSTS: Terminal Services Terminal Server Runtime Interface Protocol (TermSrvEnumeration interface)
    /// </summary>
    private const string TSTS_TermSrvEnumeration_UUID = "88143fd0-c28d-4b2b-8fef-8d882f6a9390";

    /// <summary>
    /// MS-TSTS: Terminal Services Terminal Server Runtime Interface Protocol (TermSrvEnumeration interface)
    /// </summary>
    public static readonly Guid TSTS_TermSrvEnumeration = new(TSTS_TermSrvEnumeration_UUID);

    /// <summary>
    /// MS-TSTS: Terminal Services Terminal Server Runtime Interface Protocol (TSVIPPublic interface)
    /// </summary>
    private const string TSTS_TSVIPPublic_UUID = "53b46b02-c73b-4a3e-8dee-b16b80672fc0";

    /// <summary>
    /// MS-TSTS: Terminal Services Terminal Server Runtime Interface Protocol (TSVIPPublic interface)
    /// </summary>
    public static readonly Guid TSTS_TSVIPPublic = new(TSTS_TSVIPPublic_UUID);

    /// <summary>
    /// MS-TSTS: Terminal Services Terminal Server Runtime Interface Protocol (SessEnvPublicRpc interface)
    /// </summary>
    private const string TSTS_SessEnvPublicRpc_UUID = "1257b580-ce2f-4109-82d6-a9459d0bf6bc";

    /// <summary>
    /// MS-TSTS: Terminal Services Terminal Server Runtime Interface Protocol (SessEnvPublicRpc interface)
    /// </summary>
    public static readonly Guid TSTS_SessEnvPublicRpc = new(TSTS_SessEnvPublicRpc_UUID);

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IWindowsDriverUpdate4 interface)
    /// </summary>
    private const string UAMG_IWindowsDriverUpdate4_UUID = "004c6a2b-0c19-4c69-9f5c-a269b2560db9";

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IWindowsDriverUpdate4 interface)
    /// </summary>
    public static readonly Guid UAMG_IWindowsDriverUpdate4 = new(UAMG_IWindowsDriverUpdate4_UUID);

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdateSearcher3 interface)
    /// </summary>
    private const string UAMG_IUpdateSearcher3_UUID = "04c6895d-eaf2-4034-97f3-311de9be413a";

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdateSearcher3 interface)
    /// </summary>
    public static readonly Guid UAMG_IUpdateSearcher3 = new(UAMG_IUpdateSearcher3_UUID);

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdateCollection interface)
    /// </summary>
    private const string UAMG_IUpdateCollection_UUID = "07f7438c-7709-4ca5-b518-91279288134e";

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdateCollection interface)
    /// </summary>
    public static readonly Guid UAMG_IUpdateCollection = new(UAMG_IUpdateCollection_UUID);

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdateServiceManager2 interface)
    /// </summary>
    private const string UAMG_IUpdateServiceManager2_UUID = "0bb8531d-7e8d-424f-986c-a0b8f60a3e7b";

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdateServiceManager2 interface)
    /// </summary>
    public static readonly Guid UAMG_IUpdateServiceManager2 = new(UAMG_IUpdateServiceManager2_UUID);

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IWindowsDriverUpdateEntryCollection interface)
    /// </summary>
    private const string UAMG_IWindowsDriverUpdateEntryCollection_UUID = "0d521700-a372-4bef-828b-3d00c10adebd";

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IWindowsDriverUpdateEntryCollection interface)
    /// </summary>
    public static readonly Guid UAMG_IWindowsDriverUpdateEntryCollection = new(UAMG_IWindowsDriverUpdateEntryCollection_UUID);

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdate3 interface)
    /// </summary>
    private const string UAMG_IUpdate3_UUID = "112eda6b-95b3-476f-9d90-aee82c6b8181";

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdate3 interface)
    /// </summary>
    public static readonly Guid UAMG_IUpdate3 = new(UAMG_IUpdate3_UUID);

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdate2 interface)
    /// </summary>
    private const string UAMG_IUpdate2_UUID = "144fe9b0-d23d-4a8b-8634-fb4457533b7a";

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdate2 interface)
    /// </summary>
    public static readonly Guid UAMG_IUpdate2 = new(UAMG_IUpdate2_UUID);

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdateService2 interface)
    /// </summary>
    private const string UAMG_IUpdateService2_UUID = "1518b460-6518-4172-940f-c75883b24ceb";

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdateService2 interface)
    /// </summary>
    public static readonly Guid UAMG_IUpdateService2 = new(UAMG_IUpdateService2_UUID);

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdateServiceManager interface)
    /// </summary>
    private const string UAMG_IUpdateServiceManager_UUID = "23857e3c-02ba-44a3-9423-b1c900805f37";

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdateServiceManager interface)
    /// </summary>
    public static readonly Guid UAMG_IUpdateServiceManager = new(UAMG_IUpdateServiceManager_UUID);

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdate4 interface)
    /// </summary>
    private const string UAMG_IUpdate4_UUID = "27e94b0d-5139-49a2-9a61-93522dc54652";

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdate4 interface)
    /// </summary>
    public static readonly Guid UAMG_IUpdate4 = new(UAMG_IUpdate4_UUID);

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (ICategoryCollection interface)
    /// </summary>
    private const string UAMG_ICategoryCollection_UUID = "3a56bfb8-576c-43f7-9335-fe4838fd7e37";

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (ICategoryCollection interface)
    /// </summary>
    public static readonly Guid UAMG_ICategoryCollection = new(UAMG_ICategoryCollection_UUID);

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdateIdentity interface)
    /// </summary>
    private const string UAMG_IUpdateIdentity_UUID = "46297823-9940-4c09-aed9-cd3ea6d05968";

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdateIdentity interface)
    /// </summary>
    public static readonly Guid UAMG_IUpdateIdentity = new(UAMG_IUpdateIdentity_UUID);

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IWindowsDriverUpdate3 interface)
    /// </summary>
    private const string UAMG_IWindowsDriverUpdate3_UUID = "49ebd502-4a96-41bd-9e3e-4c5057f4250c";

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IWindowsDriverUpdate3 interface)
    /// </summary>
    public static readonly Guid UAMG_IWindowsDriverUpdate3 = new(UAMG_IWindowsDriverUpdate3_UUID);

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IAutomaticUpdates2 interface)
    /// </summary>
    private const string UAMG_IAutomaticUpdates2_UUID = "4a2f5c31-cfd9-410e-b7fb-29a653973a0f";

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IAutomaticUpdates2 interface)
    /// </summary>
    public static readonly Guid UAMG_IAutomaticUpdates2 = new(UAMG_IAutomaticUpdates2_UUID);

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdateSearcher2 interface)
    /// </summary>
    private const string UAMG_IUpdateSearcher2_UUID = "4cbdcb2d-1589-4beb-bd1c-3e582ff0add0";

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdateSearcher2 interface)
    /// </summary>
    public static readonly Guid UAMG_IUpdateSearcher2 = new(UAMG_IUpdateSearcher2_UUID);

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdateExceptionCollection interface)
    /// </summary>
    private const string UAMG_IUpdateExceptionCollection_UUID = "503626a3-8e14-4729-9355-0fe664bd2321";

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdateExceptionCollection interface)
    /// </summary>
    public static readonly Guid UAMG_IUpdateExceptionCollection = new(UAMG_IUpdateExceptionCollection_UUID);

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdateDownloadContent interface)
    /// </summary>
    private const string UAMG_IUpdateDownloadContent_UUID = "54a2cb2d-9a0c-48b6-8a50-9abb69ee2d02";

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdateDownloadContent interface)
    /// </summary>
    public static readonly Guid UAMG_IUpdateDownloadContent = new(UAMG_IUpdateDownloadContent_UUID);

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IWindowsDriverUpdate2 interface)
    /// </summary>
    private const string UAMG_IWindowsDriverUpdate2_UUID = "615c4269-7a48-43bd-96b7-bf6ca27d6c3e";

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IWindowsDriverUpdate2 interface)
    /// </summary>
    public static readonly Guid UAMG_IWindowsDriverUpdate2 = new(UAMG_IWindowsDriverUpdate2_UUID);

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IAutomaticUpdates interface)
    /// </summary>
    private const string UAMG_IAutomaticUpdates_UUID = "673425bf-c082-4c7c-bdfd-569464b8e0ce";

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IAutomaticUpdates interface)
    /// </summary>
    public static readonly Guid UAMG_IAutomaticUpdates = new(UAMG_IAutomaticUpdates_UUID);

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdate interface)
    /// </summary>
    private const string UAMG_IUpdate_UUID = "6a92b07a-d821-4682-b423-5c805022cc4d";

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdate interface)
    /// </summary>
    public static readonly Guid UAMG_IUpdate = new(UAMG_IUpdate_UUID);

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IWindowsDriverUpdate5 interface)
    /// </summary>
    private const string UAMG_IWindowsDriverUpdate5_UUID = "70cf5c82-8642-42bb-9dbc-0cfd263c6c4f";

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IWindowsDriverUpdate5 interface)
    /// </summary>
    public static readonly Guid UAMG_IWindowsDriverUpdate5 = new(UAMG_IWindowsDriverUpdate5_UUID);

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (ISearchJob interface)
    /// </summary>
    private const string UAMG_ISearchJob_UUID = "7366ea16-7a1a-4ea2-b042-973d3e9cd99b";

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (ISearchJob interface)
    /// </summary>
    public static readonly Guid UAMG_ISearchJob = new(UAMG_ISearchJob_UUID);

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdateService interface)
    /// </summary>
    private const string UAMG_IUpdateService_UUID = "76b3b17e-aed6-4da5-85f0-83587f81abe3";

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdateService interface)
    /// </summary>
    public static readonly Guid UAMG_IUpdateService = new(UAMG_IUpdateService_UUID);

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IImageInformation interface)
    /// </summary>
    private const string UAMG_IImageInformation_UUID = "7c907864-346c-4aeb-8f3f-57da289f969f";

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IImageInformation interface)
    /// </summary>
    public static readonly Guid UAMG_IImageInformation = new(UAMG_IImageInformation_UUID);

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdateSession interface)
    /// </summary>
    private const string UAMG_IUpdateSession_UUID = "816858a4-260d-4260-933a-2585f1abc76b";

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdateSession interface)
    /// </summary>
    public static readonly Guid UAMG_IUpdateSession = new(UAMG_IUpdateSession_UUID);

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (ICategory interface)
    /// </summary>
    private const string UAMG_ICategory_UUID = "81ddc1b8-9d35-47a6-b471-5b80f519223b";

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (ICategory interface)
    /// </summary>
    public static readonly Guid UAMG_ICategory = new(UAMG_ICategory_UUID);

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IWindowsUpdateAgentInfo interface)
    /// </summary>
    private const string UAMG_IWindowsUpdateAgentInfo_UUID = "85713fa1-7796-4fa2-be3b-e2d6124dd373";

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IWindowsUpdateAgentInfo interface)
    /// </summary>
    public static readonly Guid UAMG_IWindowsUpdateAgentInfo = new(UAMG_IWindowsUpdateAgentInfo_UUID);

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdateSearcher interface)
    /// </summary>
    private const string UAMG_IUpdateSearcher_UUID = "8f45abf1-f9ae-4b95-a933-f0f66e5056ea";

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdateSearcher interface)
    /// </summary>
    public static readonly Guid UAMG_IUpdateSearcher = new(UAMG_IUpdateSearcher_UUID);

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdateSession3 interface)
    /// </summary>
    private const string UAMG_IUpdateSession3_UUID = "918efd1e-b5d8-4c90-8540-aeb9bdc56f9d";

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdateSession3 interface)
    /// </summary>
    public static readonly Guid UAMG_IUpdateSession3 = new(UAMG_IUpdateSession3_UUID);

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdateSession2 interface)
    /// </summary>
    private const string UAMG_IUpdateSession2_UUID = "91caf7b0-eb23-49ed-9937-c52d817f46f7";

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdateSession2 interface)
    /// </summary>
    public static readonly Guid UAMG_IUpdateSession2 = new(UAMG_IUpdateSession2_UUID);

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdateServiceCollection interface)
    /// </summary>
    private const string UAMG_IUpdateServiceCollection_UUID = "9b0353aa-0e52-44ff-b8b0-1f7fa0437f88";

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdateServiceCollection interface)
    /// </summary>
    public static readonly Guid UAMG_IUpdateServiceCollection = new(UAMG_IUpdateServiceCollection_UUID);

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdateException interface)
    /// </summary>
    private const string UAMG_IUpdateException_UUID = "a376dd5e-09d4-427f-af7c-fed5b6e1c1d6";

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdateException interface)
    /// </summary>
    public static readonly Guid UAMG_IUpdateException = new(UAMG_IUpdateException_UUID);

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdateHistoryEntryCollection interface)
    /// </summary>
    private const string UAMG_IUpdateHistoryEntryCollection_UUID = "a7f04f3c-a290-435b-aadf-a116c3357a5c";

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdateHistoryEntryCollection interface)
    /// </summary>
    public static readonly Guid UAMG_IUpdateHistoryEntryCollection = new(UAMG_IUpdateHistoryEntryCollection_UUID);

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IWindowsDriverUpdate interface)
    /// </summary>
    private const string UAMG_IWindowsDriverUpdate_UUID = "b383cd1a-5ce9-4504-9f63-764b1236f191";

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IWindowsDriverUpdate interface)
    /// </summary>
    public static readonly Guid UAMG_IWindowsDriverUpdate = new(UAMG_IWindowsDriverUpdate_UUID);

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdateDownloadContentCollection interface)
    /// </summary>
    private const string UAMG_IUpdateDownloadContentCollection_UUID = "bc5513c8-b3b8-4bf7-a4d4-361c0d8c88ba";

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdateDownloadContentCollection interface)
    /// </summary>
    public static readonly Guid UAMG_IUpdateDownloadContentCollection = new(UAMG_IUpdateDownloadContentCollection_UUID);

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdateHistoryEntry interface)
    /// </summary>
    private const string UAMG_IUpdateHistoryEntry_UUID = "be56a644-af0e-4e0e-a311-c1d8e695cbff";

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdateHistoryEntry interface)
    /// </summary>
    public static readonly Guid UAMG_IUpdateHistoryEntry = new(UAMG_IUpdateHistoryEntry_UUID);

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdate5 interface)
    /// </summary>
    private const string UAMG_IUpdate5_UUID = "c1c2f21a-d2f4-4902-b5c6-8a081c19a890";

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdate5 interface)
    /// </summary>
    public static readonly Guid UAMG_IUpdate5 = new(UAMG_IUpdate5_UUID);

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdateHistoryEntry2 interface)
    /// </summary>
    private const string UAMG_IUpdateHistoryEntry2_UUID = "c2bfb780-4539-4132-ab8c-0a8772013ab6";

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdateHistoryEntry2 interface)
    /// </summary>
    public static readonly Guid UAMG_IUpdateHistoryEntry2 = new(UAMG_IUpdateHistoryEntry2_UUID);

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdateDownloadContent2 interface)
    /// </summary>
    private const string UAMG_IUpdateDownloadContent2_UUID = "c97ad11b-f257-420b-9d9f-377f733f6f68";

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdateDownloadContent2 interface)
    /// </summary>
    public static readonly Guid UAMG_IUpdateDownloadContent2 = new(UAMG_IUpdateDownloadContent2_UUID);

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (ISearchResult interface)
    /// </summary>
    private const string UAMG_ISearchResult_UUID = "d40cff62-e08c-4498-941a-01e25f0fd33c";

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (ISearchResult interface)
    /// </summary>
    public static readonly Guid UAMG_ISearchResult = new(UAMG_ISearchResult_UUID);

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IInstallationBehavior interface)
    /// </summary>
    private const string UAMG_IInstallationBehavior_UUID = "d9a59339-e245-4dbd-9686-4d5763e39624";

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IInstallationBehavior interface)
    /// </summary>
    public static readonly Guid UAMG_IInstallationBehavior = new(UAMG_IInstallationBehavior_UUID);

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdateServiceRegistration interface)
    /// </summary>
    private const string UAMG_IUpdateServiceRegistration_UUID = "dde02280-12b3-4e0b-937b-6747f6acb286";

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IUpdateServiceRegistration interface)
    /// </summary>
    public static readonly Guid UAMG_IUpdateServiceRegistration = new(UAMG_IUpdateServiceRegistration_UUID);

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IAutomaticUpdatesResults interface)
    /// </summary>
    private const string UAMG_IAutomaticUpdatesResults_UUID = "e7a4d634-7942-4dd9-a111-82228ba33901";

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IAutomaticUpdatesResults interface)
    /// </summary>
    public static readonly Guid UAMG_IAutomaticUpdatesResults = new(UAMG_IAutomaticUpdatesResults_UUID);

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IWindowsDriverUpdateEntry interface)
    /// </summary>
    private const string UAMG_IWindowsDriverUpdateEntry_UUID = "ed8bfe40-a60b-42ea-9652-817dfcfa23ec";

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IWindowsDriverUpdateEntry interface)
    /// </summary>
    public static readonly Guid UAMG_IWindowsDriverUpdateEntry = new(UAMG_IWindowsDriverUpdateEntry_UUID);

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IStringCollection interface)
    /// </summary>
    private const string UAMG_IStringCollection_UUID = "eff90582-2ddc-480f-a06d-60f3fbc362c3";

    /// <summary>
    /// MS-UAMG: Update Agent Management Protocol (IStringCollection interface)
    /// </summary>
    public static readonly Guid UAMG_IStringCollection = new(UAMG_IStringCollection_UUID);

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsServiceSw interface)
    /// </summary>
    private const string VDS_IVdsServiceSw_UUID = "15fc031c-0652-4306-b2c3-f558b8f837e2";

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsServiceSw interface)
    /// </summary>
    public static readonly Guid VDS_IVdsServiceSw = new(VDS_IVdsServiceSw_UUID);

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsVolumeMF2 interface)
    /// </summary>
    private const string VDS_IVdsVolumeMF2_UUID = "4dbcee9a-6343-4651-b85f-5e75d74d983c";

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsVolumeMF2 interface)
    /// </summary>
    public static readonly Guid VDS_IVdsVolumeMF2 = new(VDS_IVdsVolumeMF2_UUID);

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsVDisk interface)
    /// </summary>
    private const string VDS_IVdsVDisk_UUID = "1e062b84-e5e6-4b4b-8a25-67b81e8f13e8";

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsVDisk interface)
    /// </summary>
    public static readonly Guid VDS_IVdsVDisk = new(VDS_IVdsVDisk_UUID);

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsHbaPort interface)
    /// </summary>
    private const string VDS_IVdsHbaPort_UUID = "2abd757f-2851-4997-9a13-47d2a885d6ca";

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsHbaPort interface)
    /// </summary>
    public static readonly Guid VDS_IVdsHbaPort = new(VDS_IVdsHbaPort_UUID);

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsDiskPartitionMF2 interface)
    /// </summary>
    private const string VDS_IVdsDiskPartitionMF2_UUID = "9cbe50ca-f2d2-4bf4-ace1-96896b729625";

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsDiskPartitionMF2 interface)
    /// </summary>
    public static readonly Guid VDS_IVdsDiskPartitionMF2 = new(VDS_IVdsDiskPartitionMF2_UUID);

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsVolumePlex interface)
    /// </summary>
    private const string VDS_IVdsVolumePlex_UUID = "4daa0135-e1d1-40f1-aaa5-3cc1e53221c3";

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsVolumePlex interface)
    /// </summary>
    public static readonly Guid VDS_IVdsVolumePlex = new(VDS_IVdsVolumePlex_UUID);

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsAdvancedDisk3 interface)
    /// </summary>
    private const string VDS_IVdsAdvancedDisk3_UUID = "3858c0d5-0f35-4bf5-9714-69874963bc36";

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsAdvancedDisk3 interface)
    /// </summary>
    public static readonly Guid VDS_IVdsAdvancedDisk3 = new(VDS_IVdsAdvancedDisk3_UUID);

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsDisk2 interface)
    /// </summary>
    private const string VDS_IVdsDisk2_UUID = "40f73c8b-687d-4a13-8d96-3d7f2e683936";

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsDisk2 interface)
    /// </summary>
    public static readonly Guid VDS_IVdsDisk2 = new(VDS_IVdsDisk2_UUID);

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsDisk3 interface)
    /// </summary>
    private const string VDS_IVdsDisk3_UUID = "8f4b2f5d-ec15-4357-992f-473ef10975b9";

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsDisk3 interface)
    /// </summary>
    public static readonly Guid VDS_IVdsDisk3 = new(VDS_IVdsDisk3_UUID);

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsServiceSAN interface)
    /// </summary>
    private const string VDS_IVdsServiceSAN_UUID = "fc5d23e8-a88b-41a5-8de0-2d2f73c5a630";

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsServiceSAN interface)
    /// </summary>
    public static readonly Guid VDS_IVdsServiceSAN = new(VDS_IVdsServiceSAN_UUID);

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsIscsiInitiatorAdapter interface)
    /// </summary>
    private const string VDS_IVdsIscsiInitiatorAdapter_UUID = "b07fedd4-1682-4440-9189-a39b55194dc5";

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsIscsiInitiatorAdapter interface)
    /// </summary>
    public static readonly Guid VDS_IVdsIscsiInitiatorAdapter = new(VDS_IVdsIscsiInitiatorAdapter_UUID);

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsVolume2 interface)
    /// </summary>
    private const string VDS_IVdsVolume2_UUID = "72ae6713-dcbb-4a03-b36b-371f6ac6b53d";

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsVolume2 interface)
    /// </summary>
    public static readonly Guid VDS_IVdsVolume2 = new(VDS_IVdsVolume2_UUID);

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsServiceUninstallDisk interface)
    /// </summary>
    private const string VDS_IVdsServiceUninstallDisk_UUID = "b6b22da8-f903-4be7-b492-c09d875ac9da";

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsServiceUninstallDisk interface)
    /// </summary>
    public static readonly Guid VDS_IVdsServiceUninstallDisk = new(VDS_IVdsServiceUninstallDisk_UUID);

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsDiskPartitionMF interface)
    /// </summary>
    private const string VDS_IVdsDiskPartitionMF_UUID = "538684e0-ba3d-4bc0-aca9-164aff85c2a9";

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsDiskPartitionMF interface)
    /// </summary>
    public static readonly Guid VDS_IVdsDiskPartitionMF = new(VDS_IVdsDiskPartitionMF_UUID);

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsOpenVDisk interface)
    /// </summary>
    private const string VDS_IVdsOpenVDisk_UUID = "75c8f324-f715-4fe3-a28e-f9011b61a4a1";

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsOpenVDisk interface)
    /// </summary>
    public static readonly Guid VDS_IVdsOpenVDisk = new(VDS_IVdsOpenVDisk_UUID);

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsDiskOnline interface)
    /// </summary>
    private const string VDS_IVdsDiskOnline_UUID = "90681b1d-6a7f-48e8-9061-31b7aa125322";

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsDiskOnline interface)
    /// </summary>
    public static readonly Guid VDS_IVdsDiskOnline = new(VDS_IVdsDiskOnline_UUID);

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsCreatePartitionEx interface)
    /// </summary>
    private const string VDS_IVdsCreatePartitionEx_UUID = "9882f547-cfc3-420b-9750-00dfbec50662";

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsCreatePartitionEx interface)
    /// </summary>
    public static readonly Guid VDS_IVdsCreatePartitionEx = new(VDS_IVdsCreatePartitionEx_UUID);

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsSubSystemImportTarget interface)
    /// </summary>
    private const string VDS_IVdsSubSystemImportTarget_UUID = "83bfb87f-43fb-4903-baa6-127f01029eec";

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsSubSystemImportTarget interface)
    /// </summary>
    public static readonly Guid VDS_IVdsSubSystemImportTarget = new(VDS_IVdsSubSystemImportTarget_UUID);

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsVolumeMF interface)
    /// </summary>
    private const string VDS_IVdsVolumeMF_UUID = "ee2d5ded-6236-4169-931d-b9778ce03dc6";

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsVolumeMF interface)
    /// </summary>
    public static readonly Guid VDS_IVdsVolumeMF = new(VDS_IVdsVolumeMF_UUID);

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsAdvancedDisk2 interface)
    /// </summary>
    private const string VDS_IVdsAdvancedDisk2_UUID = "9723f420-9355-42de-ab66-e31bb15beeac";

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsAdvancedDisk2 interface)
    /// </summary>
    public static readonly Guid VDS_IVdsAdvancedDisk2 = new(VDS_IVdsAdvancedDisk2_UUID);

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsServiceInitialization interface)
    /// </summary>
    private const string VDS_IVdsServiceInitialization_UUID = "4afc3636-db01-4052-80c3-03bbcb8d3c69";

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsServiceInitialization interface)
    /// </summary>
    public static readonly Guid VDS_IVdsServiceInitialization = new(VDS_IVdsServiceInitialization_UUID);

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsHwProvider interface)
    /// </summary>
    private const string VDS_IVdsHwProvider_UUID = "d99bdaae-b13a-4178-9fdb-e27f16b4603e";

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsHwProvider interface)
    /// </summary>
    public static readonly Guid VDS_IVdsHwProvider = new(VDS_IVdsHwProvider_UUID);

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsVolumeShrink interface)
    /// </summary>
    private const string VDS_IVdsVolumeShrink_UUID = "d68168c9-82a2-4f85-b6e9-74707c49a58f";

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsVolumeShrink interface)
    /// </summary>
    public static readonly Guid VDS_IVdsVolumeShrink = new(VDS_IVdsVolumeShrink_UUID);

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsPack2 interface)
    /// </summary>
    private const string VDS_IVdsPack2_UUID = "13b50bff-290a-47dd-8558-b7c58db1a71a";

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsPack2 interface)
    /// </summary>
    public static readonly Guid VDS_IVdsPack2 = new(VDS_IVdsPack2_UUID);

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsAdvancedDisk interface)
    /// </summary>
    private const string VDS_IVdsAdvancedDisk_UUID = "6e6f6b40-977c-4069-bddd-ac710059f8c0";

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsAdvancedDisk interface)
    /// </summary>
    public static readonly Guid VDS_IVdsAdvancedDisk = new(VDS_IVdsAdvancedDisk_UUID);

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsSwProvider interface)
    /// </summary>
    private const string VDS_IVdsSwProvider_UUID = "9aa58360-ce33-4f92-b658-ed24b14425b8";

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsSwProvider interface)
    /// </summary>
    public static readonly Guid VDS_IVdsSwProvider = new(VDS_IVdsSwProvider_UUID);

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsServiceLoader interface)
    /// </summary>
    private const string VDS_IVdsServiceLoader_UUID = "e0393303-90d4-4a97-ab71-e9b671ee2729";

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsServiceLoader interface)
    /// </summary>
    public static readonly Guid VDS_IVdsServiceLoader = new(VDS_IVdsServiceLoader_UUID);

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsDisk interface)
    /// </summary>
    private const string VDS_IVdsDisk_UUID = "07e5c822-f00c-47a1-8fce-b244da56fd06";

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsDisk interface)
    /// </summary>
    public static readonly Guid VDS_IVdsDisk = new(VDS_IVdsDisk_UUID);

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsAdviseSink interface)
    /// </summary>
    private const string VDS_IVdsAdviseSink_UUID = "8326cd1d-cf59-4936-b786-5efc08798e25";

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsAdviseSink interface)
    /// </summary>
    public static readonly Guid VDS_IVdsAdviseSink = new(VDS_IVdsAdviseSink_UUID);

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsVolumeOnline interface)
    /// </summary>
    private const string VDS_IVdsVolumeOnline_UUID = "1be2275a-b315-4f70-9e44-879b3a2a53f2";

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsVolumeOnline interface)
    /// </summary>
    public static readonly Guid VDS_IVdsVolumeOnline = new(VDS_IVdsVolumeOnline_UUID);

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsRemovable interface)
    /// </summary>
    private const string VDS_IVdsRemovable_UUID = "0316560b-5db4-4ed9-bbb5-213436ddc0d9";

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsRemovable interface)
    /// </summary>
    public static readonly Guid VDS_IVdsRemovable = new(VDS_IVdsRemovable_UUID);

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsServiceIscsi interface)
    /// </summary>
    private const string VDS_IVdsServiceIscsi_UUID = "14fbe036-3ed7-4e10-90e9-a5ff991aff01";

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsServiceIscsi interface)
    /// </summary>
    public static readonly Guid VDS_IVdsServiceIscsi = new(VDS_IVdsServiceIscsi_UUID);

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsPack interface)
    /// </summary>
    private const string VDS_IVdsPack_UUID = "3b69d7f5-9d94-4648-91ca-79939ba263bf";

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsPack interface)
    /// </summary>
    public static readonly Guid VDS_IVdsPack = new(VDS_IVdsPack_UUID);

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsAsync interface)
    /// </summary>
    private const string VDS_IVdsAsync_UUID = "d5d23b6d-5a55-4492-9889-397a3c2d2dbc";

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsAsync interface)
    /// </summary>
    public static readonly Guid VDS_IVdsAsync = new(VDS_IVdsAsync_UUID);

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsVolume interface)
    /// </summary>
    private const string VDS_IVdsVolume_UUID = "88306bb2-e71f-478c-86a2-79da200a0f11";

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsVolume interface)
    /// </summary>
    public static readonly Guid VDS_IVdsVolume = new(VDS_IVdsVolume_UUID);

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IEnumVdsObject interface)
    /// </summary>
    private const string VDS_IEnumVdsObject_UUID = "118610b7-8d94-4030-b5b8-500889788e4e";

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IEnumVdsObject interface)
    /// </summary>
    public static readonly Guid VDS_IEnumVdsObject = new(VDS_IEnumVdsObject_UUID);

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsServiceHba interface)
    /// </summary>
    private const string VDS_IVdsServiceHba_UUID = "0ac13689-3134-47c6-a17c-4669216801be";

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsServiceHba interface)
    /// </summary>
    public static readonly Guid VDS_IVdsServiceHba = new(VDS_IVdsServiceHba_UUID);

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsService interface)
    /// </summary>
    private const string VDS_IVdsService_UUID = "0818a8ef-9ba9-40d8-a6f9-e22833cc771e";

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsService interface)
    /// </summary>
    public static readonly Guid VDS_IVdsService = new(VDS_IVdsService_UUID);

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsVolumeMF3 interface)
    /// </summary>
    private const string VDS_IVdsVolumeMF3_UUID = "6788faf9-214e-4b85-ba59-266953616e09";

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsVolumeMF3 interface)
    /// </summary>
    public static readonly Guid VDS_IVdsVolumeMF3 = new(VDS_IVdsVolumeMF3_UUID);

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsVdProvider interface)
    /// </summary>
    private const string VDS_IVdsVdProvider_UUID = "b481498c-8354-45f9-84a0-0bdd2832a91f";

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsVdProvider interface)
    /// </summary>
    public static readonly Guid VDS_IVdsVdProvider = new(VDS_IVdsVdProvider_UUID);

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsProvider interface)
    /// </summary>
    private const string VDS_IVdsProvider_UUID = "10c5e575-7984-4e81-a56b-431f5f92ae42";

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsProvider interface)
    /// </summary>
    public static readonly Guid VDS_IVdsProvider = new(VDS_IVdsProvider_UUID);

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsIscsiInitiatorPortal interface)
    /// </summary>
    private const string VDS_IVdsIscsiInitiatorPortal_UUID = "38a0a9ab-7cc8-4693-ac07-1f28bd03c3da";

    /// <summary>
    /// MS-VDS: Virtual Disk Service (VDS) Protocol (IVdsIscsiInitiatorPortal interface)
    /// </summary>
    public static readonly Guid VDS_IVdsIscsiInitiatorPortal = new(VDS_IVdsIscsiInitiatorPortal_UUID);

    /// <summary>
    /// MS-W32T: W32Time Remote Protocol
    /// </summary>
    private const string W32T_UUID = "8fb6d884-2388-11d0-8c35-00c04fda2795";

    /// <summary>
    /// MS-W32T: W32Time Remote Protocol
    /// </summary>
    public static readonly Guid W32T = new(W32T_UUID);

    /// <summary>
    /// MS-WCCE: Windows Client Certificate Enrollment Protocol (ICertRequestD2 interface)
    /// </summary>
    private const string WCCE_ICertRequestD2_UUID = "5422fd3a-d4b8-4cef-a12e-e87d4ca22e90";

    /// <summary>
    /// MS-WCCE: Windows Client Certificate Enrollment Protocol (ICertRequestD2 interface)
    /// </summary>
    public static readonly Guid WCCE_ICertRequestD2 = new(WCCE_ICertRequestD2_UUID);

    /// <summary>
    /// MS-WCCE: Windows Client Certificate Enrollment Protocol (ICertRequestD interface)
    /// </summary>
    private const string WCCE_ICertRequestD_UUID = "d99e6e70-fc88-11d0-b498-00a0c90312f3";

    /// <summary>
    /// MS-WCCE: Windows Client Certificate Enrollment Protocol (ICertRequestD interface)
    /// </summary>
    public static readonly Guid WCCE_ICertRequestD = new(WCCE_ICertRequestD_UUID);

    /// <summary>
    /// MS-WDSC: Windows Deployment Services Control Protocol
    /// </summary>
    private const string WDSC_UUID = "1a927394-352e-4553-ae3f-7cf4aafca620";

    /// <summary>
    /// MS-WDSC: Windows Deployment Services Control Protocol
    /// </summary>
    public static readonly Guid WDSC = new(WDSC_UUID);

    /// <summary>
    /// MS-WKST: Workstation Service Remote Protocol
    /// </summary>
    private const string WKST_UUID = "6bffd098-a112-3610-9833-46c3f87e345a";

    /// <summary>
    /// MS-WKST: Workstation Service Remote Protocol
    /// </summary>
    public static readonly Guid WKST = new(WKST_UUID);

    /// <summary>
    /// MS-WMI: Windows Management Instrumentation Remote Protocol (IEnumWbemClassObject interface)
    /// </summary>
    private const string WMI_IEnumWbemClassObject_UUID = "027947e1-d731-11ce-a357-000000000001";

    /// <summary>
    /// MS-WMI: Windows Management Instrumentation Remote Protocol (IEnumWbemClassObject interface)
    /// </summary>
    public static readonly Guid WMI_IEnumWbemClassObject = new(WMI_IEnumWbemClassObject_UUID);

    /// <summary>
    /// MS-WMI: Windows Management Instrumentation Remote Protocol (IWbemFetchSmartEnum interface)
    /// </summary>
    private const string WMI_IWbemFetchSmartEnum_UUID = "1c1c45ee-4395-11d2-b60b-00104b703efd";

    /// <summary>
    /// MS-WMI: Windows Management Instrumentation Remote Protocol (IWbemFetchSmartEnum interface)
    /// </summary>
    public static readonly Guid WMI_IWbemFetchSmartEnum = new(WMI_IWbemFetchSmartEnum_UUID);

    /// <summary>
    /// MS-WMI: Windows Management Instrumentation Remote Protocol (IWbemRefreshingServices interface)
    /// </summary>
    private const string WMI_IWbemRefreshingServices_UUID = "2c9273e0-1dc3-11d3-b364-00105a1f8177";

    /// <summary>
    /// MS-WMI: Windows Management Instrumentation Remote Protocol (IWbemRefreshingServices interface)
    /// </summary>
    public static readonly Guid WMI_IWbemRefreshingServices = new(WMI_IWbemRefreshingServices_UUID);

    /// <summary>
    /// MS-WMI: Windows Management Instrumentation Remote Protocol (IWbemWCOSmartEnum interface)
    /// </summary>
    private const string WMI_IWbemWCOSmartEnum_UUID = "423ec01e-2e35-11d2-b604-00104b703efd";

    /// <summary>
    /// MS-WMI: Windows Management Instrumentation Remote Protocol (IWbemWCOSmartEnum interface)
    /// </summary>
    public static readonly Guid WMI_IWbemWCOSmartEnum = new(WMI_IWbemWCOSmartEnum_UUID);

    /// <summary>
    /// MS-WMI: Windows Management Instrumentation Remote Protocol (IWbemContext interface)
    /// </summary>
    private const string WMI_IWbemContext_UUID = "44aca674-e8fc-11d0-a07c-00c04fb68820";

    /// <summary>
    /// MS-WMI: Windows Management Instrumentation Remote Protocol (IWbemContext interface)
    /// </summary>
    public static readonly Guid WMI_IWbemContext = new(WMI_IWbemContext_UUID);

    /// <summary>
    /// MS-WMI: Windows Management Instrumentation Remote Protocol (IWbemCallResult interface)
    /// </summary>
    private const string WMI_IWbemCallResult_UUID = "44aca675-e8fc-11d0-a07c-00c04fb68820";

    /// <summary>
    /// MS-WMI: Windows Management Instrumentation Remote Protocol (IWbemCallResult interface)
    /// </summary>
    public static readonly Guid WMI_IWbemCallResult = new(WMI_IWbemCallResult_UUID);

    /// <summary>
    /// MS-WMI: Windows Management Instrumentation Remote Protocol (IWbemLoginHelper interface)
    /// </summary>
    private const string WMI_IWbemLoginHelper_UUID = "541679ab-2e5f-11d3-b34e-00104bcc4b4a";

    /// <summary>
    /// MS-WMI: Windows Management Instrumentation Remote Protocol (IWbemLoginHelper interface)
    /// </summary>
    public static readonly Guid WMI_IWbemLoginHelper = new(WMI_IWbemLoginHelper_UUID);

    /// <summary>
    /// MS-WMI: Windows Management Instrumentation Remote Protocol (IWbemObjectSink interface)
    /// </summary>
    private const string WMI_IWbemObjectSink_UUID = "7c857801-7381-11cf-884d-00aa004b2e24";

    /// <summary>
    /// MS-WMI: Windows Management Instrumentation Remote Protocol (IWbemObjectSink interface)
    /// </summary>
    public static readonly Guid WMI_IWbemObjectSink = new(WMI_IWbemObjectSink_UUID);

    /// <summary>
    /// MS-WMI: Windows Management Instrumentation Remote Protocol (IWbemServices interface)
    /// </summary>
    private const string WMI_IWbemServices_UUID = "9556dc99-828c-11cf-a37e-00aa003240c7";

    /// <summary>
    /// MS-WMI: Windows Management Instrumentation Remote Protocol (IWbemServices interface)
    /// </summary>
    public static readonly Guid WMI_IWbemServices = new(WMI_IWbemServices_UUID);

    /// <summary>
    /// MS-WMI: Windows Management Instrumentation Remote Protocol (IWbemBackupRestoreEx interface)
    /// </summary>
    private const string WMI_IWbemBackupRestoreEx_UUID = "a359dec5-e813-4834-8a2a-ba7f1d777d76";

    /// <summary>
    /// MS-WMI: Windows Management Instrumentation Remote Protocol (IWbemBackupRestoreEx interface)
    /// </summary>
    public static readonly Guid WMI_IWbemBackupRestoreEx = new(WMI_IWbemBackupRestoreEx_UUID);

    /// <summary>
    /// MS-WMI: Windows Management Instrumentation Remote Protocol (IWbemBackupRestore interface)
    /// </summary>
    private const string WMI_IWbemBackupRestore_UUID = "c49e32c7-bc8b-11d2-85d4-00105a1f8304";

    /// <summary>
    /// MS-WMI: Windows Management Instrumentation Remote Protocol (IWbemBackupRestore interface)
    /// </summary>
    public static readonly Guid WMI_IWbemBackupRestore = new(WMI_IWbemBackupRestore_UUID);

    /// <summary>
    /// MS-WMI: Windows Management Instrumentation Remote Protocol (IWbemLoginClientID interface)
    /// </summary>
    private const string WMI_IWbemLoginClientID_UUID = "d4781cd6-e5d3-44df-ad94-930efe48a887";

    /// <summary>
    /// MS-WMI: Windows Management Instrumentation Remote Protocol (IWbemLoginClientID interface)
    /// </summary>
    public static readonly Guid WMI_IWbemLoginClientID = new(WMI_IWbemLoginClientID_UUID);

    /// <summary>
    /// MS-WMI: Windows Management Instrumentation Remote Protocol (IWbemClassObject interface)
    /// </summary>
    private const string WMI_IWbemClassObject_UUID = "dc12a681-737f-11cf-884d-00aa004b2e24";

    /// <summary>
    /// MS-WMI: Windows Management Instrumentation Remote Protocol (IWbemClassObject interface)
    /// </summary>
    public static readonly Guid WMI_IWbemClassObject = new(WMI_IWbemClassObject_UUID);

    /// <summary>
    /// MS-WMI: Windows Management Instrumentation Remote Protocol (IWbemRemoteRefresher interface)
    /// </summary>
    private const string WMI_IWbemRemoteRefresher_UUID = "f1e9c5b2-f59b-11d2-b362-00105a1f8177";

    /// <summary>
    /// MS-WMI: Windows Management Instrumentation Remote Protocol (IWbemRemoteRefresher interface)
    /// </summary>
    public static readonly Guid WMI_IWbemRemoteRefresher = new(WMI_IWbemRemoteRefresher_UUID);

    /// <summary>
    /// MS-WMI: Windows Management Instrumentation Remote Protocol (IWbemLevel1Login interface)
    /// </summary>
    private const string WMI_IWbemLevel1Login_UUID = "f309ad18-d86a-11d0-a075-00c04fb68820";

    /// <summary>
    /// MS-WMI: Windows Management Instrumentation Remote Protocol (IWbemLevel1Login interface)
    /// </summary>
    public static readonly Guid WMI_IWbemLevel1Login = new(WMI_IWbemLevel1Login_UUID);

    /// <summary>
    /// MS-WMI: Windows Management Instrumentation Remote Protocol (WbemContext interface)
    /// </summary>
    private const string WMI_WbemContext_UUID = "674b6698-ee92-11d0-ad71-00c04fd8fdff";

    /// <summary>
    /// MS-WMI: Windows Management Instrumentation Remote Protocol (WbemContext interface)
    /// </summary>
    public static readonly Guid WMI_WbemContext = new(WMI_WbemContext_UUID);

    /// <summary>
    /// MS-WMI: Windows Management Instrumentation Remote Protocol (WbemLevel1Login interface)
    /// </summary>
    private const string WMI_WbemLevel1Login_UUID = "8bc3f05e-d86b-11d0-a075-00c04fb68820";

    /// <summary>
    /// MS-WMI: Windows Management Instrumentation Remote Protocol (WbemLevel1Login interface)
    /// </summary>
    public static readonly Guid WMI_WbemLevel1Login = new(WMI_WbemLevel1Login_UUID);

    /// <summary>
    /// MS-WMI: Windows Management Instrumentation Remote Protocol (WbemClassObject interface)
    /// </summary>
    private const string WMI_WbemClassObject_UUID = "9a653086-174f-11d2-b5f9-00104b703efd";

    /// <summary>
    /// MS-WMI: Windows Management Instrumentation Remote Protocol (WbemClassObject interface)
    /// </summary>
    public static readonly Guid WMI_WbemClassObject = new(WMI_WbemClassObject_UUID);

    /// <summary>
    /// MS-WMI: Windows Management Instrumentation Remote Protocol (WbemBackupRestore interface)
    /// </summary>
    private const string WMI_WbemBackupRestore_UUID = "c49e32c6-bc8b-11d2-85d4-00105a1f8304";

    /// <summary>
    /// MS-WMI: Windows Management Instrumentation Remote Protocol (WbemBackupRestore interface)
    /// </summary>
    public static readonly Guid WMI_WbemBackupRestore = new(WMI_WbemBackupRestore_UUID);

    /// <summary>
    /// MS-WSRM: Windows System Resource Manager (WSRM) Protocol (IWRMConfig interface)
    /// </summary>
    private const string WSRM_IWRMConfig_UUID = "21546ae8-4da5-445e-987f-627fea39c5e8";

    /// <summary>
    /// MS-WSRM: Windows System Resource Manager (WSRM) Protocol (IWRMConfig interface)
    /// </summary>
    public static readonly Guid WSRM_IWRMConfig = new(WSRM_IWRMConfig_UUID);

    /// <summary>
    /// MS-WSRM: Windows System Resource Manager (WSRM) Protocol (IResourceManager2 interface)
    /// </summary>
    private const string WSRM_IResourceManager2_UUID = "2a3eb639-d134-422d-90d8-aaa1b5216202";

    /// <summary>
    /// MS-WSRM: Windows System Resource Manager (WSRM) Protocol (IResourceManager2 interface)
    /// </summary>
    public static readonly Guid WSRM_IResourceManager2 = new(WSRM_IResourceManager2_UUID);

    /// <summary>
    /// MS-WSRM: Windows System Resource Manager (WSRM) Protocol (IWRMCalendar interface)
    /// </summary>
    private const string WSRM_IWRMCalendar_UUID = "481e06cf-ab04-4498-8ffe-124a0a34296d";

    /// <summary>
    /// MS-WSRM: Windows System Resource Manager (WSRM) Protocol (IWRMCalendar interface)
    /// </summary>
    public static readonly Guid WSRM_IWRMCalendar = new(WSRM_IWRMCalendar_UUID);

    /// <summary>
    /// MS-WSRM: Windows System Resource Manager (WSRM) Protocol (IWRMAccounting interface)
    /// </summary>
    private const string WSRM_IWRMAccounting_UUID = "4f7ca01c-a9e5-45b6-b142-2332a1339c1d";

    /// <summary>
    /// MS-WSRM: Windows System Resource Manager (WSRM) Protocol (IWRMAccounting interface)
    /// </summary>
    public static readonly Guid WSRM_IWRMAccounting = new(WSRM_IWRMAccounting_UUID);

    /// <summary>
    /// MS-WSRM: Windows System Resource Manager (WSRM) Protocol (IWRMPolicy interface)
    /// </summary>
    private const string WSRM_IWRMPolicy_UUID = "59602eb6-57b0-4fd8-aa4b-ebf06971fe15";

    /// <summary>
    /// MS-WSRM: Windows System Resource Manager (WSRM) Protocol (IWRMPolicy interface)
    /// </summary>
    public static readonly Guid WSRM_IWRMPolicy = new(WSRM_IWRMPolicy_UUID);

    /// <summary>
    /// MS-WSRM: Windows System Resource Manager (WSRM) Protocol (IWRMMachineGroup interface)
    /// </summary>
    private const string WSRM_IWRMMachineGroup_UUID = "943991a5-b3fe-41fa-9696-7f7b656ee34b";

    /// <summary>
    /// MS-WSRM: Windows System Resource Manager (WSRM) Protocol (IWRMMachineGroup interface)
    /// </summary>
    public static readonly Guid WSRM_IWRMMachineGroup = new(WSRM_IWRMMachineGroup_UUID);

    /// <summary>
    /// MS-WSRM: Windows System Resource Manager (WSRM) Protocol (IWRMResourceGroup interface)
    /// </summary>
    private const string WSRM_IWRMResourceGroup_UUID = "bc681469-9dd9-4bf4-9b3d-709f69efe431";

    /// <summary>
    /// MS-WSRM: Windows System Resource Manager (WSRM) Protocol (IWRMResourceGroup interface)
    /// </summary>
    public static readonly Guid WSRM_IWRMResourceGroup = new(WSRM_IWRMResourceGroup_UUID);

    /// <summary>
    /// MS-WSRM: Windows System Resource Manager (WSRM) Protocol (IResourceManager interface)
    /// </summary>
    private const string WSRM_IResourceManager_UUID = "c5cebee2-9df5-4cdd-a08c-c2471bc144b4";

    /// <summary>
    /// MS-WSRM: Windows System Resource Manager (WSRM) Protocol (IResourceManager interface)
    /// </summary>
    public static readonly Guid WSRM_IResourceManager = new(WSRM_IResourceManager_UUID);

    /// <summary>
    /// MS-WSRM: Windows System Resource Manager (WSRM) Protocol (ResourceManager interface)
    /// </summary>
    private const string WSRM_ResourceManager_UUID = "e8bcffac-b864-4574-b2e8-f1fb21dfdc18";

    /// <summary>
    /// MS-WSRM: Windows System Resource Manager (WSRM) Protocol (ResourceManager interface)
    /// </summary>
    public static readonly Guid WSRM_ResourceManager = new(WSRM_ResourceManager_UUID);

    /// <summary>
    /// MS-WSRM: Windows System Resource Manager (WSRM) Protocol (IWRMProtocol interface)
    /// </summary>
    private const string WSRM_IWRMProtocol_UUID = "f31931a9-832d-481c-9503-887a0e6a79f0";

    /// <summary>
    /// MS-WSRM: Windows System Resource Manager (WSRM) Protocol (IWRMProtocol interface)
    /// </summary>
    public static readonly Guid WSRM_IWRMProtocol = new(WSRM_IWRMProtocol_UUID);

    /// <summary>
    /// MS-WSRM: Windows System Resource Manager (WSRM) Protocol (IWRMRemoteSessionMgmt interface)
    /// </summary>
    private const string WSRM_IWRMRemoteSessionMgmt_UUID = "fc910418-55ca-45ef-b264-83d4ce7d30e0";

    /// <summary>
    /// MS-WSRM: Windows System Resource Manager (WSRM) Protocol (IWRMRemoteSessionMgmt interface)
    /// </summary>
    public static readonly Guid WSRM_IWRMRemoteSessionMgmt = new(WSRM_IWRMRemoteSessionMgmt_UUID);
}
