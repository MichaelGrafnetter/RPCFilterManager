using System.Globalization;

namespace DSInternals.Win32.RpcFilters;

/// <summary>
/// Well-known RPC protocol translator.
/// </summary>
public static class WellKnownProtocolTranslator
{
    private const string DRSR_drsuapi_UUID = "e3514235-4b06-11d1-ab04-00c04fc2dcd2";

    /// <summary>
    /// MS-DRSR: Directory Replication Service Remote Protocol
    /// </summary>
    public static readonly Guid DRSR_drsuapi = new(DRSR_drsuapi_UUID);

    private const string DRSR_dsaop_UUID = "7c44d7d4-31d5-424c-bd5e-2b3e1f323d22";

    /// <summary>
    /// MS-DRSR: Directory Replication Service Remote Protocol
    /// </summary>
    public static readonly Guid DRSR_dsaop = new(DRSR_dsaop_UUID);

    private const string SCMR_UUID = "367abb81-9844-35f1-ad32-98f038001003";

    /// <summary>
    /// MS-SCMR: Service Control Manager Remote Protocol
    /// </summary>
    public static readonly Guid SCMR = new(SCMR_UUID);

    private const string TSCH_UUID = "86d35949-83c9-4044-b424-db363231fd0c";

    /// <summary>
    /// MS-TSCH: Task Scheduler Service Remoting Protocol (ITaskSchedulerService)
    /// </summary>
    public static readonly Guid TSCH = new(TSCH_UUID);

    private const string ATSvc_UUID = "1ff70682-0a51-30e8-076d-740be8cee98b";

    /// <summary>
    /// MS-TSCH: Task Scheduler Service Remoting Protocol (ATSvc)
    /// </summary>
    public static readonly Guid ATSvc = new(ATSvc_UUID);

    private const string SASec_UUID = "378e52b0-c0a9-11cf-822d-00aa0051e40f";

    /// <summary>
    /// MS-TSCH: Task Scheduler Service Remoting Protocol (SASec)
    /// </summary>
    public static readonly Guid SASec = new(SASec_UUID);

    private const string EVEN_UUID = "82273fdc-e32a-18c3-3f78-827929dc23ea";

    /// <summary>
    /// MS-EVEN: EventLog Remoting Protocol
    /// </summary>
    public static readonly Guid EVEN = new(EVEN_UUID);

    private const string EVEN6_UUID = "f6beaff7-1e19-4fbb-9f8f-b89e2018337c";

    /// <summary>
    /// MS-EVEN6: EventLog Remoting Protocol Version 6.0
    /// </summary>
    public static readonly Guid EVEN6 = new(EVEN6_UUID);

    private const string KIWI_UUID = "17fc11e9-c258-4b8d-8d07-2f4125156244";

    /// <summary>
    /// MimiCom: Mimikatz Remote Protocol
    /// </summary>
    public static readonly Guid KIWI = new(KIWI_UUID);

    private const string RRP_UUID = "338cd001-2244-31f1-aaaa-900038001003";

    /// <summary>
    /// MS-RRP: Windows Remote Registry Protocol
    /// </summary>
    public static readonly Guid RRP = new(RRP_UUID);

    private const string RSP_NP_UUID = "894de0c0-0d55-11d3-a322-00c04fa321a1";

    /// <summary>
    /// MS-RSP: Remote Shutdown Protocol (InitShutdown)
    /// </summary>
    public static readonly Guid RSP_NP = new(RSP_NP_UUID);

    private const string RSP_TCP_UUID = "d95afe70-a6d5-4259-822e-2c84da1ddb0d";

    /// <summary>
    /// MS-RSP: Remote Shutdown Protocol (WindowsShutdown)
    /// </summary>
    public static readonly Guid RSP_TCP = new(RSP_TCP_UUID);

    private const string RPRN_UUID = "12345678-1234-abcd-ef00-0123456789ab";

    /// <summary>
    /// MS-RPRN: Print Spooler Remote Protocol
    /// </summary>
    public static readonly Guid RPRN = new(RPRN_UUID);

    private const string PAR_UUID = "76f03f96-cdfd-44fc-a22c-64950a001209";

    /// <summary>
    /// MS-PAR: Print System Asynchronous Remote Protocol
    /// </summary>
    public static readonly Guid PAR = new(PAR_UUID);

    private const string DFSNM_UUID = "4fc742e0-4a10-11cf-8273-00aa004ae673";

    /// <summary>
    /// MS-DFS: Distributed File System Namespace Management Protocol
    /// </summary>
    public static readonly Guid DFSNM = new(DFSNM_UUID);

    private const string SAMR_UUID = "12345778-1234-abcd-ef00-0123456789ac";

    /// <summary>
    /// MS-SAMR: Security Account Manager (SAM) Remote Protocol
    /// </summary>
    public static readonly Guid SAMR = new(SAMR_UUID);

    private const string NRPC_UUID = "12345678-1234-abcd-ef00-01234567cffb";

    /// <summary>
    /// MS-NRPC: Netlogon Remote Protocol
    /// </summary>
    public static readonly Guid NRPC = new(NRPC_UUID);

    private const string FRS1_UUID = "f5cc59b4-4264-101a-8c59-08002b2f8426";

    /// <summary>
    /// MS-FRS1: File Replication Service Remote Protocol
    /// </summary>
    public static readonly Guid FRS1 = new(FRS1_UUID);

    private const string FRS2_UUID = "897e2e5f-93f3-4376-9c9c-fd2277495c27";

    /// <summary>
    /// MS-FRS2: Distributed File System Replication Protocol
    /// </summary>
    public static readonly Guid FRS2 = new(FRS2_UUID);

    private const string FSRVP_UUID = "a8e0653c-2744-4389-a61d-7373df8b2292";

    /// <summary>
    /// MS-FSRVP: Volume Shadow Copy Service Remote Protocol
    /// </summary>
    public static readonly Guid FSRVP = new(FSRVP_UUID);

    private const string EFSR_UUID = "df1941c5-fe89-4e79-bf10-463657acf44d";

    /// <summary>
    /// MS-EFSR: Encrypting File System Remote Protocol (EFSRPC)
    /// </summary>
    public static readonly Guid EFSR = new(EFSR_UUID);

    private const string EFSR_LSA_UUID = "c681d488-d850-11d0-8c52-00c04fd90f7e";

    /// <summary>
    /// MS-EFSR: Encrypting File System Remote Protocol (LSARPC)
    /// </summary>
    public static readonly Guid EFSR_LSA = new(EFSR_LSA_UUID);

    private const string SRVSVC_UUID = "4b324fc8-1670-01d3-1278-5a47bf6ee188";

    /// <summary>
    /// MS-SRVSVC: Server Service Remote Protocol
    /// </summary>
    public static readonly Guid SRVSVC = new(SRVSVC_UUID);

    private const string WKSSVC_UUID = "6bffd098-a112-3610-9833-46c3f87e345a";

    /// <summary>
    /// MS-WKSSVC: Workstation Service Remote Protocol
    /// </summary>
    public static readonly Guid WKSSVC = new(WKSSVC_UUID);

    private const string BKRP_UUID = "3dde7c30-165d-11d1-ab8f-00805f14db40";

    /// <summary>
    /// MS-BKRP: Backup Key Remote Protocol
    /// </summary>
    public static readonly Guid BKRP = new(BKRP_UUID);

    private const string LSAD_UUID = "12345778-1234-abcd-ef00-0123456789ab";

    /// <summary>
    /// MS-LSAD: Local Security Authority (LSA) Remote Protocol
    /// </summary>
    public static readonly Guid LSAD = new(LSAD_UUID);

    private const string DNSP_UUID = "50abc2a4-574d-40b3-9d66-ee4fd5fba076";

    /// <summary>
    /// MS-DNSP: Domain Name Service (DNS) Server Management Protocol
    /// </summary>
    public static readonly Guid DNSP = new(DNSP_UUID);

    private const string CSRA_ICertAdminD_UUID = "d99e6e71-fc88-11d0-b498-00a0c90312f3";

    /// <summary>
    /// MS-CSRA: Certificate Services Remote Administration Protocol (ICertAdminD)
    /// </summary>
    public static readonly Guid CSRA_ICertAdminD = new(CSRA_ICertAdminD_UUID);

    private const string CSRA_ICertAdminD2_UUID = "7fe0d935-dda6-443f-85d0-1cfb58fe41dd";
    /// <summary>
    /// MS-CSRA: Certificate Services Remote Administration Protocol (ICertAdminD2)
    /// </summary>
    public static readonly Guid CSRA_ICertAdminD2 = new(CSRA_ICertAdminD2_UUID);

    private const string ICPR_UUID = "91ae6020-9e3c-11cf-8d7c-00aa00c091be";

    /// <summary>
    /// MS-ICPR: ICertPassage Remote Protocol
    /// </summary>
    public static readonly Guid ICPR = new(ICPR_UUID);

    private const string PAN_IRPCAsyncNotify_UUID = "0b6edbfa-4a24-4fc6-8a23-942b1eca65d1";

    /// <summary>
    /// MS-PAN: Print System Asynchronous Notification Protocol (IRPCAsyncNotify)
    /// </summary>
    public static readonly Guid PAN_IRPCAsyncNotify = new(PAN_IRPCAsyncNotify_UUID);

    private const string PAN_IRPCRemoteObject_UUID = "ae33069b-a2a8-46ee-a235-ddfd339be281";

    /// <summary>
    /// MS-PAN: Print System Asynchronous Notification Protocol (IRPCRemoteObject)
    /// </summary>
    public static readonly Guid PAN_IRPCRemoteObject = new(PAN_IRPCRemoteObject_UUID);

    private const string NSPI_UUID = "f5cc5a18-4264-101a-8c59-08002b2f8426";

    /// <summary>
    /// MS-NSPI: Name Service Provider Interface (NSPI) Remote Protocol
    /// </summary>
    public static readonly Guid NSPI = new(NSPI_UUID);

    private const string EPMAP_UUID = "e1af8308-5d1f-11c9-91a4-08002b14a0fa";

    /// <summary>
    /// DCERPC Endpoint Mapper
    /// </summary>
    public static readonly Guid EPMAP = new(EPMAP_UUID);

    private const string DSSP_UUID = "3919286a-b10c-11d0-9ba8-00c04fd92ef5";

    /// <summary>
    /// MS-DSSP: Directory Services Setup Remote Protocol
    /// </summary>
    public static readonly Guid DSSP = new(DSSP_UUID);

    private const string BRWSA_UUID = "6bffd098-a112-3610-9833-012892020162";

    /// <summary>
    /// MS-BRWSA: Common Internet File System (CIFS) Browser Auxiliary Protocol
    /// </summary>
    public static readonly Guid BRWSA = new(BRWSA_UUID);

    private const string DHCPM_dhcpsrv_UUID = "6bffd098-a112-3610-9833-46c3f874532d";

    /// <summary>
    /// MS-DHCPM: Microsoft Dynamic Host Configuration Protocol (DHCP) Server Management Protocol (dhcpsrv)
    /// </summary>
    public static readonly Guid DHCPM_dhcpsrv = new(DHCPM_dhcpsrv_UUID);

    private const string DHCPM_dhcpsrv2_UUID = "5b821720-f63b-11d0-aad2-00c04fc324db";

    /// <summary>
    /// MS-DHCPM: Microsoft Dynamic Host Configuration Protocol (DHCP) Server Management Protocol (dhcpsrv2)
    /// </summary>
    public static readonly Guid DHCPM_dhcpsrv2 = new(DHCPM_dhcpsrv2_UUID);

    private const string DLTM_UUID = "4da1c422-943d-11d1-acae-00c04fc2aa3f";

    /// <summary>
    /// MS-DLTM: Distributed Link Tracking: Central Manager Protocol
    /// </summary>
    public static readonly Guid DLTM = new(DLTM_UUID);

    private const string DLTW_UUID = "300f3532-38cc-11d0-a3f0-0020af6b0add";

    /// <summary>
    /// MS-DLTW: Distributed Link Tracking: Workstation Protocol
    /// </summary>
    public static readonly Guid DLTW = new(DLTW_UUID);

    private const string W32T_UUID = "8fb6d884-2388-11d0-8c35-00c04fda2795";

    /// <summary>
    /// MS-W32T: W32Time Remote Protocol
    /// </summary>
    public static readonly Guid W32T = new(W32T_UUID);

    private const string RRASM_DIMSVC_UUID = "8f09f000-b7ed-11ce-bbd2-00001a181cad";

    /// <summary>
    /// MS-RRASM: Routing and Remote Access Server (RRAS) Management Protocol (DIMSVC)
    /// </summary>
    public static readonly Guid RRASM_DIMSVC = new(RRASM_DIMSVC_UUID);

    private const string RRASM_RASRPC_UUID = "20610036-fa22-11cf-9823-00a0c911e5df";

    /// <summary>
    /// MS-RRASM: Routing and Remote Access Server (RRAS) Management Protocol (RASRPC)
    /// </summary>
    public static readonly Guid RRASM_RASRPC = new(RRASM_RASRPC_UUID);

    private const string RRASM_IRemoteNetworkConfig_UUID = "66a2db1b-d706-11d0-a37b-00c04fc9da04";

    /// <summary>
    /// MS-RRASM: Routing and Remote Access Server (RRAS) Management Protocol (IRemoteNetworkConfig)
    /// </summary>
    public static readonly Guid RRASM_IRemoteNetworkConfig = new(RRASM_IRemoteNetworkConfig_UUID);

    private const string RRASM_IRemoteRouterRestart_UUID = "66a2db20-d706-11d0-a37b-00c04fc9da04";

    /// <summary>
    /// MS-RRASM: Routing and Remote Access Server (RRAS) Management Protocol (IRemoteRouterRestart)
    /// </summary>
    public static readonly Guid RRASM_IRemoteRouterRestart = new(RRASM_IRemoteRouterRestart_UUID);

    private const string RRASM_IRemoteSetDnsConfig_UUID = "66a2db21-d706-11d0-a37b-00c04fc9da04";

    /// <summary>
    /// MS-RRASM: Routing and Remote Access Server (RRAS) Management Protocol (IRemoteSetDnsConfig)
    /// </summary>
    public static readonly Guid RRASM_IRemoteSetDnsConfig = new(RRASM_IRemoteSetDnsConfig_UUID);

    private const string RRASM_IRemoteICFICSConfig_UUID = "66a2db22-d706-11d0-a37b-00c04fc9da04";

    /// <summary>
    /// MS-RRASM: Routing and Remote Access Server (RRAS) Management Protocol (IRemoteICFICSConfig)
    /// </summary>
    public static readonly Guid RRASM_IRemoteICFICSConfig = new(RRASM_IRemoteICFICSConfig_UUID);

    private const string RRASM_IRemoteStringIdConfig_UUID = "67e08fc2-2984-4b62-b92e-fc1aae64bbbb";

    /// <summary>
    /// MS-RRASM: Routing and Remote Access Server (RRAS) Management Protocol (IRemoteStringIdConfig)
    /// </summary>
    public static readonly Guid RRASM_IRemoteStringIdConfig = new(RRASM_IRemoteStringIdConfig_UUID);

    private const string RRASM_IRemoteIPV6Config_UUID = "6139d8a4-e508-4ebb-bac7-d7f275145897";

    /// <summary>
    /// MS-RRASM: Routing and Remote Access Server (RRAS) Management Protocol (IRemoteIPV6Config)
    /// </summary>
    public static readonly Guid RRASM_IRemoteIPV6Config = new(RRASM_IRemoteIPV6Config_UUID);

    private const string RRASM_IRemoteSstpCertCheck_UUID = "5ff9bdf6-bd91-4d8b-a614-d6317acc8dd8";

    /// <summary>
    /// MS-RRASM: Routing and Remote Access Server (RRAS) Management Protocol (IRemoteSstpCertCheck)
    /// </summary>
    public static readonly Guid RRASM_IRemoteSstpCertCheck = new(RRASM_IRemoteSstpCertCheck_UUID);

    private const string RAIW_winsif_UUID = "45f52c28-7f9f-101a-b52b-08002b2efabe";

    /// <summary>
    /// MS-RAIW: Remote Administrative Interface: WINS (winsif)
    /// </summary>
    public static readonly Guid RAIW_winsif = new(RAIW_winsif_UUID);

    private const string RAIW_winsi2_UUID = "811109bf-a4e1-11d1-ab54-00a0c91e9b45";

    /// <summary>
    /// MS-RAIW: Remote Administrative Interface: WINS (winsif2)
    /// </summary>
    public static readonly Guid RAIW_winsi2 = new(RAIW_winsi2_UUID);

    private const string TSTS_LSM_Session_UUID = "484809d6-4239-471b-b5bc-61df8c23ac48";

    /// <summary>
    /// MS-TSTS: Terminal Services Terminal Server Runtime Interface Protocol (LSM Session)
    /// </summary>
    public static readonly Guid TSTS_LSM_Session = new(TSTS_LSM_Session_UUID);

    private const string TSTS_LSM_Notification_UUID = "11899a43-2b68-4a76-92e3-a3d6ad8c26ce";

    /// <summary>
    /// MS-TSTS: Terminal Services Terminal Server Runtime Interface Protocol (LSM Notification)
    /// </summary>
    public static readonly Guid TSTS_LSM_Notification = new(TSTS_LSM_Notification_UUID);

    private const string TSTS_LSM_Enumeration_UUID = "88143fd0-c28d-4b2b-8fef-8d882f6a9390";

    /// <summary>
    /// MS-TSTS: Terminal Services Terminal Server Runtime Interface Protocol (LSM Enumeration)
    /// </summary>
    public static readonly Guid TSTS_LSM_Enumeration = new(TSTS_LSM_Enumeration_UUID);

    private const string TSTS_TermSrv_UUID = "bde95fdf-eee0-45de-9e12-e5a61cd0d4fe";

    /// <summary>
    /// MS-TSTS: Terminal Services Terminal Server Runtime Interface Protocol (TermSrv)
    /// </summary>
    public static readonly Guid TSTS_TermSrv = new(TSTS_TermSrv_UUID);

    private const string TSTS_TermSrv_Listener_UUID = "497d95a6-2d27-4bf5-9bbd-a6046957133c";

    /// <summary>
    /// MS-TSTS: Terminal Services Terminal Server Runtime Interface Protocol (TermSrv Listener)
    /// </summary>
    public static readonly Guid TSTS_TermSrv_Listener = new(TSTS_TermSrv_Listener_UUID);

    private const string TSTS_Legacy_UUID = "5ca4a760-ebb1-11cf-8611-00a0245420ed";

    /// <summary>
    /// MS-TSTS: Terminal Services Terminal Server Runtime Interface Protocol (Legacy)
    /// </summary>
    public static readonly Guid TSTS_Legacy = new(TSTS_Legacy_UUID);

    private const string TSTS_TSVIPPublic_UUID = "53b46b02-c73b-4a3e-8dee-b16b80672fc0";

    /// <summary>
    /// MS-TSTS: Terminal Services Terminal Server Runtime Interface Protocol (TSVIPPublic)
    /// </summary>
    public static readonly Guid TSTS_TSVIPPublic = new(TSTS_TSVIPPublic_UUID);

    private const string TSTS_SessEnvPublicRpc_UUID = "1257b580-ce2f-4109-82d6-a9459d0bf6bc";

    /// <summary>
    /// MS-TSTS: Terminal Services Terminal Server Runtime Interface Protocol (SessEnvPublicRpc)
    /// </summary>
    public static readonly Guid TSTS_SessEnvPublicRpc = new(TSTS_SessEnvPublicRpc_UUID);

    private const string DCOM_IActivation_UUID = "4d9f4ab8-7d1c-11cf-861e-0020af6e7c57";

    /// <summary>
    /// MS-DCOM: Distributed Component Object Model (DCOM) Remote Protocol (IActivation)
    /// </summary>
    public static readonly Guid DCOM_IActivation = new(DCOM_IActivation_UUID);

    private const string DCOM_IActivationPropertiesIn_UUID = "000001a2-0000-0000-c000-000000000046";

    /// <summary>
    /// MS-DCOM: Distributed Component Object Model (DCOM) Remote Protocol (IActivationPropertiesIn)
    /// </summary>
    public static readonly Guid DCOM_IActivationPropertiesIn = new(DCOM_IActivationPropertiesIn_UUID);

    private const string DCOM_IActivationPropertiesOut_UUID = "000001a3-0000-0000-c000-000000000046";

    /// <summary>
    /// MS-DCOM: Distributed Component Object Model (DCOM) Remote Protocol (IActivationPropertiesOut)
    /// </summary>
    public static readonly Guid DCOM_IActivationPropertiesOut = new(DCOM_IActivationPropertiesOut_UUID);

    private const string DCOM_IContext_UUID = "000001c0-0000-0000-c000-000000000046";

    /// <summary>
    /// MS-DCOM: Distributed Component Object Model (DCOM) Remote Protocol (IContext)
    /// </summary>
    public static readonly Guid DCOM_IContext = new(DCOM_IContext_UUID);

    private const string DCOM_IObjectExporter_UUID = "99fcfec4-5260-101b-bbcb-00aa0021347a";

    /// <summary>
    /// MS-DCOM: Distributed Component Object Model (DCOM) Remote Protocol (IObjectExporter)
    /// </summary>
    public static readonly Guid DCOM_IObjectExporter = new(DCOM_IObjectExporter_UUID);

    private const string DCOM_IRemoteSCMActivator_UUID = "000001a0-0000-0000-c000-000000000046";

    /// <summary>
    /// MS-DCOM: Distributed Component Object Model (DCOM) Remote Protocol (IRemoteSCMActivator)
    /// </summary>
    public static readonly Guid DCOM_IRemoteSCMActivator = new(DCOM_IRemoteSCMActivator_UUID);

    private const string DCOM_IRemUnknown_UUID = "00000131-0000-0000-c000-000000000046";

    /// <summary>
    /// MS-DCOM: Distributed Component Object Model (DCOM) Remote Protocol (IRemUnknown)
    /// </summary>
    public static readonly Guid DCOM_IRemUnknown = new(DCOM_IRemUnknown_UUID);

    private const string DCOM_IRemUnknown2_UUID = "00000143-0000-0000-c000-000000000046";

    /// <summary>
    /// MS-DCOM: Distributed Component Object Model (DCOM) Remote Protocol (IRemUnknown2)
    /// </summary>
    public static readonly Guid DCOM_IRemUnknown2 = new(DCOM_IRemUnknown2_UUID);

    private const string DCOM_IUnknown_UUID = "00000000-0000-0000-c000-000000000046";

    /// <summary>
    /// MS-DCOM: Distributed Component Object Model (DCOM) Remote Protocol (IUnknown)
    /// </summary>
    public static readonly Guid DCOM_IUnknown = new(DCOM_IUnknown_UUID);

    private const string WMI_IWbemLevel1Login_UUID = "f309ad18-d86a-11d0-a075-00c04fb68820";

    /// <summary>
    /// MS-WMI: Windows Management Instrumentation Remote Protocol (IWbemLevel1Login)
    /// </summary>
    public static readonly Guid WMI_IWbemLevel1Login = new(WMI_IWbemLevel1Login_UUID);

    private const string WMI_IWbemLoginClientID_UUID = "d4781cd6-e5d3-44df-ad94-930efe48a887";

    /// <summary>
    /// MS-WMI: Windows Management Instrumentation Remote Protocol (IWbemLoginClientID)
    /// </summary>
    public static readonly Guid WMI_IWbemLoginClientID = new(WMI_IWbemLoginClientID_UUID);

    private const string WMI_IWbemLoginHelper_UUID = "541679ab-2e5f-11d3-b34e-00104bcc4b4a";

    /// <summary>
    /// MS-WMI: Windows Management Instrumentation Remote Protocol (IWbemLoginHelper)
    /// </summary>
    public static readonly Guid WMI_IWbemLoginHelper = new(WMI_IWbemLoginHelper_UUID);

    private const string WMI_IWbemServices_UUID = "9556dc99-828c-11cf-a37e-00aa003240c7";

    /// <summary>
    /// MS-WMI: Windows Management Instrumentation Remote Protocol (IWbemServices)
    /// </summary>
    public static readonly Guid WMI_IWbemServices = new(WMI_IWbemServices_UUID);

    private const string WMI_IWbemBackupRestore_UUID = "c49e32c7-bc8b-11d2-85d4-00105a1f8304";

    /// <summary>
    /// MS-WMI: Windows Management Instrumentation Remote Protocol (IWbemBackupRestore)
    /// </summary>
    public static readonly Guid WMI_IWbemBackupRestore = new(WMI_IWbemBackupRestore_UUID);

    private const string WMI_IWbemBackupRestoreEx_UUID = "a359dec5-e813-4834-8a2a-ba7f1d777d76";

    /// <summary>
    /// MS-WMI: Windows Management Instrumentation Remote Protocol (IWbemBackupRestoreEx)
    /// </summary>
    public static readonly Guid WMI_IWbemBackupRestoreEx = new(WMI_IWbemBackupRestoreEx_UUID);

    private const string WMI_IWbemClassObject_UUID = "dc12a681-737f-11cf-884d-00aa004b2e24";

    /// <summary>
    /// MS-WMI: Windows Management Instrumentation Remote Protocol (IWbemClassObject)
    /// </summary>
    public static readonly Guid WMI_IWbemClassObject = new(WMI_IWbemClassObject_UUID);

    private const string WMI_IWbemContext_UUID = "44aca674-e8fc-11d0-a07c-00c04fb68820";

    /// <summary>
    /// MS-WMI: Windows Management Instrumentation Remote Protocol (IWbemContext)
    /// </summary>
    public static readonly Guid WMI_IWbemContext = new(WMI_IWbemContext_UUID);

    private const string WCCE_ICertRequestD_UUID = "d99e6e70-fc88-11d0-b498-00a0c90312f3";

    /// <summary>
    /// MS-WCCE: Windows Client Certificate Enrollment Protocol (ICertRequestD)
    /// </summary>
    public static readonly Guid WCCE_ICertRequestD = new(WCCE_ICertRequestD_UUID);

    private const string WCCE_ICertRequestD2_UUID = "5422fd3a-d4b8-4cef-a12e-e87d4ca22e90";

    /// <summary>
    /// MS-WCCE: Windows Client Certificate Enrollment Protocol (ICertRequestD2)
    /// </summary>
    public static readonly Guid WCCE_ICertRequestD2 = new(WCCE_ICertRequestD2_UUID);

    /// <summary>
    /// MS-EVEN6: EvtRpcClearLog
    /// </summary>
    public const ushort EvtRpcClearLog = 6;

    /// <summary>
    /// MS-EVEN: ElfrClearELFW
    /// </summary>
    public const ushort ElfrClearELFW = 0;

    /// <summary>
    /// MS-EVEN: ElfrClearELFA
    /// </summary>
    public const ushort ElfrClearELFA = 12;

    /// <summary>
    /// MS-SCMR: RCreateServiceW
    /// </summary>
    public const ushort RCreateServiceW = 12;

    /// <summary>
    /// MS-SCMR: RCreateServiceA
    /// </summary>
    public const ushort RCreateServiceA = 24;

    /// <summary>
    /// MS-SCMR: RCreateServiceWOW64A
    /// </summary>
    public const ushort RCreateServiceWOW64A = 44;

    /// <summary>
    /// MS-SCMR: RCreateServiceWOW64W
    /// </summary>
    public const ushort RCreateServiceWOW64W = 45;

    /// <summary>
    /// MS-SCMR: RCreateWowService
    /// </summary>
    public const ushort RCreateWowService = 60;

    /// <summary>
    /// MS-DRSR: IDL_DRSGetNCChanges
    /// </summary>
    public const ushort IDL_DRSGetNCChanges = 3;

    /// <summary>
    /// MS-DRSR: IDL_DRSReplicaAdd
    /// </summary>
    public const ushort IDL_DRSReplicaAdd = 5;

    /// <summary>
    /// MS-RRP: BaseRegCreateKey
    /// </summary>
    public const ushort BaseRegCreateKey = 6;

    /// <summary>
    /// MS-RRP: BaseRegSetValue
    /// </summary>
    public const ushort BaseRegSetValue = 22;

    /// <summary>
    /// MS-TSCH: SchRpcRegisterTask
    /// </summary>
    public const ushort SchRpcRegisterTask = 1;

    /// <summary>
    /// MS-TSCH: NetrJobAdd
    /// </summary>
    public const ushort NetrJobAdd = 0;

    /// <summary>
    /// MS-SRVS: NetrFileEnum
    /// </summary>
    public const ushort NetrFileEnum = 9;

    /// <summary>
    /// MS-SRVS: NetrSessionEnum
    /// </summary>
    public const ushort NetrSessionEnum = 12;

    /// <summary>
    /// MS-SRVS: NetrShareEnum
    /// </summary>
    public const ushort NetrShareEnum = 15;

    /// <summary>
    /// MS-SRVS: NetrConnectionEnum
    /// </summary>
    public const ushort NetrConnectionEnum = 8;

    /// <summary>
    /// MS-PAR: RpcAsyncAddPrinterDriver
    /// </summary>
    public const ushort RpcAsyncAddPrinterDriver = 39;

    /// <summary>
    /// MS-RPRN: RpcAddPrinterDriverEx
    /// </summary>
    public const ushort RpcAddPrinterDriverEx = 89;

    /// <summary>
    /// MS-RPRN: RpcRemoteFindFirstPrinterChangeNotification
    /// </summary>
    public const ushort RpcRemoteFindFirstPrinterChangeNotification = 62;

    /// <summary>
    /// MS-RPRN: RpcRemoteFindFirstPrinterChangeNotification
    /// </summary>
    public const ushort RpcRemoteFindFirstPrinterChangeNotificationEx = 65;

    /// <summary>
    /// MS-SAMR: SamrEnumerateGroupsInDomain
    /// </summary>
    public const ushort SamrEnumerateGroupsInDomain = 11;

    /// <summary>
    /// MS-SAMR: SamrEnumerateUsersInDomain
    /// </summary>
    public const ushort SamrEnumerateUsersInDomain = 13;

    /// <summary>
    /// MS-LSAD: LsarRetrievePrivateData
    /// </summary>
    public const ushort LsarRetrievePrivateData = 43;

    /// <summary>
    /// MS-EFSR: EfsRpcOpenFileRaw
    /// </summary>
    public const ushort EfsRpcOpenFileRaw = 0;

    /// <summary>
    /// MS-EFSR: EfsRpcEncryptFileSrv
    /// </summary>
    public const ushort EfsRpcEncryptFileSrv = 4;

    /// <summary>
    /// MS-EFSR: EfsRpcDecryptFileSrv
    /// </summary>
    public const ushort EfsRpcDecryptFileSrv = 5;

    /// <summary>
    /// MS-EFSR: EfsRpcQueryUsersOnFile
    /// </summary>
    public const ushort EfsRpcQueryUsersOnFile = 6;

    /// <summary>
    /// MS-EFSR: EfsRpcQueryRecoveryAgents
    /// </summary>
    public const ushort EfsRpcQueryRecoveryAgents = 7;

    /// <summary>
    /// MS-EFSR: EfsRpcRemoveUsersFromFile
    /// </summary>
    public const ushort EfsRpcRemoveUsersFromFile = 8;

    /// <summary>
    /// MS-EFSR: EfsRpcAddUsersToFile
    /// </summary>
    public const ushort EfsRpcAddUsersToFile = 9;

    /// <summary>
    /// MS-FSRVP: IsPathSupported
    /// </summary>
    public const ushort IsPathSupported = 8;

    /// <summary>
    /// MS-FSRVP: IsPathShadowCopied
    /// </summary>
    public const ushort IsPathShadowCopied = 9;

    /// <summary>
    /// MS-DFSNM: NetrDfsAddStdRoot
    /// </summary>
    public const ushort NetrDfsAddStdRoot = 12;

    /// <summary>
    /// MS-DFSNM: NetrDfsRemoveStdRoot
    /// </summary>
    public const ushort NetrDfsRemoveStdRoot = 13;

    /// <summary>
    /// MS-DFSNM: NetrDfsAddRootTarget
    /// </summary>
    public const ushort NetrDfsAddRootTarget = 23;

    /// <summary>
    /// MS-DFSNM: NetrDfsRemoveRootTarget
    /// </summary>
    public const ushort NetrDfsRemoveRootTarget = 24;

    /// <summary>
    /// Translates a well-known RPC protocol to its corresponding interface UUID.
    /// </summary>
    /// <param name="protocol">RPC protocol enumeration</param>
    /// <returns>Interface UUID</returns>
    /// <exception cref="ArgumentOutOfRangeException"></exception>
    public static Guid ToInterfaceUUID(this WellKnownProtocol protocol)
    {
        return protocol switch
        {
            WellKnownProtocol.DirectoryReplicationService => DRSR_drsuapi,
            WellKnownProtocol.DomainRenameScript => DRSR_dsaop,
            WellKnownProtocol.ServiceControlManager => SCMR,
            WellKnownProtocol.TaskSchedulerAgent => SASec,
            WellKnownProtocol.NetSchedule => ATSvc,
            WellKnownProtocol.TaskSchedulerService => TSCH,
            WellKnownProtocol.EventLog => EVEN,
            WellKnownProtocol.EventLogV6 => EVEN6,
            WellKnownProtocol.MimiCom => KIWI,
            WellKnownProtocol.RemoteRegistry => RRP,
            WellKnownProtocol.InitShutdown => RSP_NP,
            WellKnownProtocol.WindowsShutdown => RSP_TCP,
            WellKnownProtocol.SecurityAccountManager => SAMR,
            WellKnownProtocol.PrintSpooler => RPRN,
            WellKnownProtocol.NamespaceManagement => DFSNM,
            WellKnownProtocol.FileReplicationService => FRS1,
            WellKnownProtocol.DistributedFileReplication => FRS2,
            WellKnownProtocol.VolumeShadowCopy => FSRVP,
            WellKnownProtocol.Netlogon => NRPC,
            WellKnownProtocol.EncryptingFileSystem => EFSR,
            WellKnownProtocol.EncryptingFileSystemLSA => EFSR_LSA,
            WellKnownProtocol.ServerService => SRVSVC,
            WellKnownProtocol.WorkstationService => WKSSVC,
            WellKnownProtocol.BackupKey => BKRP,
            WellKnownProtocol.LocalSecurityAuthority => LSAD,
            WellKnownProtocol.DnsManagement => DNSP,
            WellKnownProtocol.EndpointMapper => EPMAP,
            WellKnownProtocol.DirectoryServicesSetup => DSSP,
            WellKnownProtocol.MasterBrowser => BRWSA,
            WellKnownProtocol.RemoteAccessManagement => RRASM_RASRPC,
            WellKnownProtocol.WindowsTime => W32T,
            WellKnownProtocol.DistributedLinkTrackingClient => DLTW,
            WellKnownProtocol.PrintSpoolerAsync => PAR,
            WellKnownProtocol.DistributedLinkTrackingServer => DLTM,
            WellKnownProtocol.NameServiceProvider => NSPI,
            WellKnownProtocol.ICertPassage => ICPR,
            WellKnownProtocol.ICertRequestD => WCCE_ICertRequestD,
            WellKnownProtocol.ICertRequestD2 => WCCE_ICertRequestD2,
            WellKnownProtocol.ICertAdminD => CSRA_ICertAdminD,
            WellKnownProtocol.ICertAdminD2 => CSRA_ICertAdminD2,
            _ => throw new ArgumentOutOfRangeException(nameof(protocol), protocol, "This protocol is not yet supported.")
        };
    }

    /// <summary>
    /// Translates a well-known RPC operation to its corresponding protocol and operation number.
    /// </summary>
    /// <param name="operation">RPC protocol operation enumeration</param>
    /// <returns>Well-known protocol and operation number</returns>
    /// <exception cref="ArgumentOutOfRangeException"></exception>
    public static (WellKnownProtocol protocol, ushort OperationNumber) ToOperationNumber(this WellKnownOperation operation)
    {
        return operation switch
        {
            WellKnownOperation.IDL_DRSGetNCChanges => (WellKnownProtocol.DirectoryReplicationService, IDL_DRSGetNCChanges),
            WellKnownOperation.IDL_DRSReplicaAdd => (WellKnownProtocol.DirectoryReplicationService, IDL_DRSReplicaAdd),
            WellKnownOperation.EvtRpcClearLog => (WellKnownProtocol.EventLogV6, EvtRpcClearLog),
            WellKnownOperation.ElfrClearELFW => (WellKnownProtocol.EventLog, ElfrClearELFW),
            WellKnownOperation.ElfrClearELFA => (WellKnownProtocol.EventLog, ElfrClearELFA),
            WellKnownOperation.RCreateServiceW => (WellKnownProtocol.ServiceControlManager, RCreateServiceW),
            WellKnownOperation.RCreateServiceA => (WellKnownProtocol.ServiceControlManager, RCreateServiceA),
            WellKnownOperation.RCreateServiceWOW64A => (WellKnownProtocol.ServiceControlManager, RCreateServiceWOW64A),
            WellKnownOperation.RCreateServiceWOW64W => (WellKnownProtocol.ServiceControlManager, RCreateServiceWOW64W),
            WellKnownOperation.RCreateWowService => (WellKnownProtocol.ServiceControlManager, RCreateWowService),
            WellKnownOperation.BaseRegCreateKey => (WellKnownProtocol.RemoteRegistry, BaseRegCreateKey),
            WellKnownOperation.BaseRegSetValue => (WellKnownProtocol.RemoteRegistry, BaseRegSetValue),
            WellKnownOperation.SchRpcRegisterTask => (WellKnownProtocol.TaskSchedulerService, SchRpcRegisterTask),
            WellKnownOperation.NetrJobAdd => (WellKnownProtocol.NetSchedule, NetrJobAdd),
            WellKnownOperation.NetrFileEnum => (WellKnownProtocol.ServerService, NetrFileEnum),
            WellKnownOperation.NetrSessionEnum => (WellKnownProtocol.ServerService, NetrSessionEnum),
            WellKnownOperation.NetrShareEnum => (WellKnownProtocol.ServerService, NetrShareEnum),
            WellKnownOperation.NetrConnectionEnum => (WellKnownProtocol.ServerService, NetrConnectionEnum),
            WellKnownOperation.RpcAsyncAddPrinterDriver => (WellKnownProtocol.PrintSpoolerAsync, RpcAsyncAddPrinterDriver),
            WellKnownOperation.RpcAddPrinterDriverEx => (WellKnownProtocol.PrintSpooler, RpcAddPrinterDriverEx),
            WellKnownOperation.RpcRemoteFindFirstPrinterChangeNotification => (WellKnownProtocol.PrintSpooler, RpcRemoteFindFirstPrinterChangeNotification),
            WellKnownOperation.RpcRemoteFindFirstPrinterChangeNotificationEx => (WellKnownProtocol.PrintSpooler, RpcRemoteFindFirstPrinterChangeNotificationEx),
            WellKnownOperation.SamrEnumerateGroupsInDomain => (WellKnownProtocol.SecurityAccountManager, SamrEnumerateGroupsInDomain),
            WellKnownOperation.SamrEnumerateUsersInDomain => (WellKnownProtocol.SecurityAccountManager, SamrEnumerateUsersInDomain),
            WellKnownOperation.LsarRetrievePrivateData => (WellKnownProtocol.LocalSecurityAuthority, LsarRetrievePrivateData),
            WellKnownOperation.EfsRpcOpenFileRaw => (WellKnownProtocol.EncryptingFileSystem, EfsRpcOpenFileRaw),
            WellKnownOperation.EfsRpcEncryptFileSrv => (WellKnownProtocol.EncryptingFileSystem, EfsRpcEncryptFileSrv),
            WellKnownOperation.EfsRpcDecryptFileSrv => (WellKnownProtocol.EncryptingFileSystem, EfsRpcDecryptFileSrv),
            WellKnownOperation.EfsRpcQueryUsersOnFile => (WellKnownProtocol.EncryptingFileSystem, EfsRpcQueryUsersOnFile),
            WellKnownOperation.EfsRpcQueryRecoveryAgents => (WellKnownProtocol.EncryptingFileSystem, EfsRpcQueryRecoveryAgents),
            WellKnownOperation.EfsRpcRemoveUsersFromFile => (WellKnownProtocol.EncryptingFileSystem, EfsRpcRemoveUsersFromFile),
            WellKnownOperation.EfsRpcAddUsersToFile => (WellKnownProtocol.EncryptingFileSystem, EfsRpcAddUsersToFile),
            WellKnownOperation.IsPathSupported => (WellKnownProtocol.VolumeShadowCopy, IsPathSupported),
            WellKnownOperation.IsPathShadowCopied => (WellKnownProtocol.VolumeShadowCopy, IsPathShadowCopied),
            WellKnownOperation.NetrDfsAddStdRoot => (WellKnownProtocol.NamespaceManagement, NetrDfsAddStdRoot),
            WellKnownOperation.NetrDfsRemoveStdRoot => (WellKnownProtocol.NamespaceManagement, NetrDfsRemoveStdRoot),
            WellKnownOperation.NetrDfsAddRootTarget => (WellKnownProtocol.NamespaceManagement, NetrDfsAddRootTarget),
            WellKnownOperation.NetrDfsRemoveRootTarget => (WellKnownProtocol.NamespaceManagement, NetrDfsRemoveRootTarget),
            _ => throw new ArgumentOutOfRangeException(nameof(operation), operation, "This operation is not yet supported.")
        };
    }

    /// <summary>
    /// Checks if the specified protocol supports RPC over named pipes by default.
    /// </summary>
    public static bool SupportsNamedPipes(this Guid? interfaceUUID)
    {
        if (!interfaceUUID.HasValue)
        {
            // No interface UUID is configured in the filter
            return false;
        }

        string interfaceUUIDString = interfaceUUID.Value.ToString().ToLowerInvariant();

        switch (interfaceUUIDString)
        {
            case SCMR_UUID:
            case TSCH_UUID:
            case ATSvc_UUID:
            case SASec_UUID:
            case EVEN_UUID:
            case EVEN6_UUID:
            case RRP_UUID:
            case RSP_TCP_UUID:
            case RSP_NP_UUID:
            case SAMR_UUID:
            case RPRN_UUID:
            case DFSNM_UUID:
            case EFSR_UUID:
            case EFSR_LSA_UUID:
            case SRVSVC_UUID:
            case WKSSVC_UUID:
            case FSRVP_UUID:
            case BKRP_UUID:
            case LSAD_UUID:
            case DNSP_UUID:
            case EPMAP_UUID:
            case DSSP_UUID:
            case BRWSA_UUID:
            case NRPC_UUID:
            case W32T_UUID:
            case DLTW_UUID:
            case RRASM_DIMSVC_UUID:
            case RRASM_RASRPC_UUID:
            case RRASM_IRemoteNetworkConfig_UUID:
            case RRASM_IRemoteRouterRestart_UUID:
            case RRASM_IRemoteSetDnsConfig_UUID:
            case RRASM_IRemoteICFICSConfig_UUID:
            case RRASM_IRemoteStringIdConfig_UUID:
            case RRASM_IRemoteIPV6Config_UUID:
            case RRASM_IRemoteSstpCertCheck_UUID:
            case TSTS_LSM_Session_UUID:
            case TSTS_LSM_Notification_UUID:
            case TSTS_LSM_Enumeration_UUID:
            case TSTS_TermSrv_UUID:
            case TSTS_TermSrv_Listener_UUID:
            case TSTS_Legacy_UUID:
            case TSTS_TSVIPPublic_UUID:
            case TSTS_SessEnvPublicRpc_UUID:
            case RAIW_winsif_UUID:
            case RAIW_winsi2_UUID:
                return true;
            case DRSR_drsuapi_UUID:
            case DRSR_dsaop_UUID:
            case FRS1_UUID:
            case FRS2_UUID:
            default:
                // We either do not know the protocol or it does not use named pipes.
                return false;
        }
    }

    /// <summary>
    /// Translates a well-known RPC interface UUID to its corresponding protocol name.
    /// </summary>
    /// <param name="interfaceUUID">RPC interface UUID</param>
    /// <param name="alwaysIncludeInterfaceUUID">Indicated whether the original interface UUID should be appended to the translated protocol name.</param>
    /// <returns>Protocol name</returns>
    public static string? ToProtocolName(this Guid? interfaceUUID, bool alwaysIncludeInterfaceUUID = false)
    {
        if (!interfaceUUID.HasValue)
        {
            // No interface UUID is configured in the filter
            return null;
        }

        string interfaceUUIDString = interfaceUUID.Value.ToString().ToLowerInvariant();

        string protocolName = interfaceUUIDString switch
        {
            DRSR_drsuapi_UUID => "MS-DRSR (drsuapi)",
            DRSR_dsaop_UUID => "MS-DRSR (dsaop)",
            SCMR_UUID => "MS-SCMR",
            SASec_UUID => "MS-TSCH (SASec)",
            ATSvc_UUID => "MS-TSCH (ATSvc)",
            TSCH_UUID => "MS-TSCH (ITaskSchedulerService)",
            EVEN_UUID => "MS-EVEN",
            EVEN6_UUID => "MS-EVEN6",
            KIWI_UUID => "MimiCom",
            RRP_UUID => "MS-RRP",
            RSP_NP_UUID => "MS-RSP (InitShutdown)",
            RSP_TCP_UUID => "MS-RSP (WindowsShutdown)",
            RPRN_UUID => "MS-RPRN",
            PAR_UUID => "MS-PAR",
            DFSNM_UUID => "MS-DFSNM",
            FRS1_UUID => "MS-FRS1",
            FRS2_UUID => "MS-FRS2",
            FSRVP_UUID => "MS-FSRP",
            NRPC_UUID => "MS-NRPC",
            EFSR_UUID => "MS-EFSR (\\pipe\\efsrpc)",
            EFSR_LSA_UUID => "MS-EFSR (\\pipe\\lsarpc)",
            LSAD_UUID => "MS-LSAD",
            SRVSVC_UUID => "MS-SRVSVC",
            WKSSVC_UUID => "MS-WKSSVC",
            BKRP_UUID => "MS-BKRP",
            DNSP_UUID => "MS-DNSP",
            SAMR_UUID => "MS-SAMR",
            EPMAP_UUID => "EPMAP",
            CSRA_ICertAdminD_UUID => "MS-CSRA (ICertAdminD)",
            CSRA_ICertAdminD2_UUID => "MS-CSRA (ICertAdminD2)",
            ICPR_UUID => "MS-ICPR",
            PAN_IRPCAsyncNotify_UUID => "MS-PAN (IRPCAsyncNotify)",
            PAN_IRPCRemoteObject_UUID => "MS-PAN (IRPCRemoteObject)",
            NSPI_UUID => "MS-NSPI",
            DSSP_UUID => "MS-DSSP",
            BRWSA_UUID => "MS-BRWSA",
            DHCPM_dhcpsrv_UUID => "MS-DHCPM (dhcpsrv)",
            DHCPM_dhcpsrv2_UUID => "MS-DHCPM (dhcpsrv2)",
            DLTM_UUID => "MS-DLTM",
            DLTW_UUID => "MS-DLTW",
            RRASM_RASRPC_UUID => "MS-RRASM (RASRPC)",
            RRASM_DIMSVC_UUID => "MS-RRASM (DIMSVC)",
            RRASM_IRemoteNetworkConfig_UUID => "MS-RRASM (IRemoteNetworkConfig)",
            RRASM_IRemoteRouterRestart_UUID => "MS-RRASM (IRemoteRouterRestart)",
            RRASM_IRemoteSetDnsConfig_UUID => "MS-RRASM (IRemoteSetDnsConfig)",
            RRASM_IRemoteICFICSConfig_UUID => "MS-RRASM (IRemoteICFICSConfig)",
            RRASM_IRemoteStringIdConfig_UUID => "MS-RRASM (IRemoteStringIdConfig)",
            RRASM_IRemoteIPV6Config_UUID => "MS-RRASM (IRemoteIPV6Config)",
            RRASM_IRemoteSstpCertCheck_UUID => "MS-RRASM (IRemoteSstpCertCheck)",
            W32T_UUID => "MS-W32T",
            RAIW_winsif_UUID => "MS-RAIW (winsif",
            RAIW_winsi2_UUID => "MS-RAIW (winsi2)",
            TSTS_LSM_Session_UUID => "MS-TSTS (LSM Session)",
            TSTS_LSM_Notification_UUID => "MS-TSTS (LSM Notification)",
            TSTS_LSM_Enumeration_UUID => "MS-TSTS (LSM Enumeration)",
            TSTS_TermSrv_UUID => "MS-TSTS (TermSrv)",
            TSTS_TermSrv_Listener_UUID => "MS-TSTS (TermSrv Listener)",
            TSTS_Legacy_UUID => "MS-TSTS (Legacy)",
            TSTS_TSVIPPublic_UUID => "MS-TSTS (TSVIPPublic)",
            TSTS_SessEnvPublicRpc_UUID => "MS-TSTS (SessEnvPublicRpc)",
            DCOM_IActivation_UUID => "MS-DCOM (IActivation)",
            DCOM_IActivationPropertiesIn_UUID => "MS-DCOM (IActivationPropertiesIn)",
            DCOM_IActivationPropertiesOut_UUID => "MS-DCOM (IActivationPropertiesOut)",
            DCOM_IContext_UUID => "MS-DCOM (IContext)",
            DCOM_IObjectExporter_UUID => "MS-DCOM (IObjectExporter)",
            DCOM_IRemoteSCMActivator_UUID => "MS-DCOM (IRemoteSCMActivator)",
            DCOM_IRemUnknown_UUID => "MS-DCOM (IRemUnknown)",
            DCOM_IRemUnknown2_UUID => "MS-DCOM (IRemUnknown2)",
            DCOM_IUnknown_UUID => "MS-DCOM (IUnknown)",
            WMI_IWbemLevel1Login_UUID => "MS-WMI (IWbemLevel1Login)",
            WMI_IWbemLoginClientID_UUID => "MS-WMI (IWbemLoginClientID)",
            WMI_IWbemLoginHelper_UUID => "MS-WMI (IWbemLoginHelper)",
            WMI_IWbemServices_UUID => "MS-WMI (IWbemServices)",
            WMI_IWbemBackupRestore_UUID => "MS-WMI (IWbemBackupRestore)",
            WMI_IWbemBackupRestoreEx_UUID => "MS-WMI (IWbemBackupRestoreEx)",
            WMI_IWbemClassObject_UUID => "MS-WMI (IWbemClassObject)",
            WMI_IWbemContext_UUID => "MS-WMI (IWbemContext)",
            WCCE_ICertRequestD_UUID => "MS-WCCE (ICertRequestD)",
            WCCE_ICertRequestD2_UUID => "MS-WCCE (ICertRequestD)",
            // Return the original GUID if no match is found
            _ => interfaceUUIDString
        };

        if (protocolName != interfaceUUIDString && alwaysIncludeInterfaceUUID)
        {
            // Append the original interface UUID to the translated protocol name if requested by the caller
            protocolName = $"{protocolName} - {{{interfaceUUIDString}}}";
        }

        return protocolName;
    }

    /// <summary>
    /// Translates a well-known RPC operation number to its name.
    /// </summary>
    /// <param name="interfaceUUID">RPC interface UUID</param>
    /// <param name="operationNumber">Interface-specific operation number</param>
    /// <param name="alwaysIncludeOperationNumber">Indicated whether the original operation number should be appended to the translated operation name.</param>
    /// <returns>Operation name</returns>
    public static string? ToOperationName(Guid? interfaceUUID, ushort? operationNumber, bool alwaysIncludeOperationNumber = true)
    {
        if (operationNumber == null)
        {
            // No operation number is configured in the filter
            return null;
        }
        else if (!interfaceUUID.HasValue)
        {
            // Although the operation number is defined, it cannot be translated without the corresponding interface UUID
            return operationNumber?.ToString(CultureInfo.InvariantCulture);
        }

        string interfaceUUIDString = interfaceUUID.Value.ToString().ToLowerInvariant();

        // Both interface UUID and operation number are configured in the filter
        string? operationName = (interfaceUUIDString, operationNumber) switch
        {
            (DRSR_drsuapi_UUID, IDL_DRSGetNCChanges) => nameof(IDL_DRSGetNCChanges),
            (DRSR_drsuapi_UUID, IDL_DRSReplicaAdd) => nameof(IDL_DRSReplicaAdd),
            (EVEN6_UUID, EvtRpcClearLog) => nameof(EvtRpcClearLog),
            (EVEN_UUID, ElfrClearELFW) => nameof(ElfrClearELFW),
            (EVEN_UUID, ElfrClearELFA) => nameof(ElfrClearELFA),
            (SCMR_UUID, RCreateServiceW) => nameof(RCreateServiceW),
            (SCMR_UUID, RCreateServiceA) => nameof(RCreateServiceA),
            (SCMR_UUID, RCreateServiceWOW64A) => nameof(RCreateServiceWOW64A),
            (SCMR_UUID, RCreateServiceWOW64W) => nameof(RCreateServiceWOW64W),
            (SCMR_UUID, RCreateWowService) => nameof(RCreateWowService),
            (RRP_UUID, BaseRegCreateKey) => nameof(BaseRegCreateKey),
            (RRP_UUID, BaseRegSetValue) => nameof(BaseRegSetValue),
            (TSCH_UUID, SchRpcRegisterTask) => nameof(SchRpcRegisterTask),
            (ATSvc_UUID, NetrJobAdd) => nameof(NetrJobAdd),
            (SRVSVC_UUID, NetrFileEnum) => nameof(NetrFileEnum),
            (SRVSVC_UUID, NetrSessionEnum) => nameof(NetrSessionEnum),
            (SRVSVC_UUID, NetrShareEnum) => nameof(NetrShareEnum),
            (SRVSVC_UUID, NetrConnectionEnum) => nameof(NetrConnectionEnum),
            (PAR_UUID, RpcAsyncAddPrinterDriver) => nameof(RpcAsyncAddPrinterDriver),
            (RPRN_UUID, RpcAddPrinterDriverEx) => nameof(RpcAddPrinterDriverEx),
            (RPRN_UUID, RpcRemoteFindFirstPrinterChangeNotification) => nameof(RpcRemoteFindFirstPrinterChangeNotification),
            (RPRN_UUID, RpcRemoteFindFirstPrinterChangeNotificationEx) => nameof(RpcRemoteFindFirstPrinterChangeNotificationEx),
            (SAMR_UUID, SamrEnumerateGroupsInDomain) => nameof(SamrEnumerateGroupsInDomain),
            (SAMR_UUID, SamrEnumerateUsersInDomain) => nameof(SamrEnumerateUsersInDomain),
            (LSAD_UUID, LsarRetrievePrivateData) => nameof(LsarRetrievePrivateData),
            (EFSR_UUID, EfsRpcOpenFileRaw) => nameof(EfsRpcOpenFileRaw),
            (EFSR_UUID, EfsRpcEncryptFileSrv) => nameof(EfsRpcEncryptFileSrv),
            (EFSR_UUID, EfsRpcDecryptFileSrv) => nameof(EfsRpcDecryptFileSrv),
            (EFSR_UUID, EfsRpcQueryUsersOnFile) => nameof(EfsRpcQueryUsersOnFile),
            (EFSR_UUID, EfsRpcQueryRecoveryAgents) => nameof(EfsRpcQueryRecoveryAgents),
            (EFSR_UUID, EfsRpcRemoveUsersFromFile) => nameof(EfsRpcRemoveUsersFromFile),
            (EFSR_UUID, EfsRpcAddUsersToFile) => nameof(EfsRpcAddUsersToFile),
            (EFSR_LSA_UUID, EfsRpcOpenFileRaw) => nameof(EfsRpcOpenFileRaw),
            (EFSR_LSA_UUID, EfsRpcEncryptFileSrv) => nameof(EfsRpcEncryptFileSrv),
            (EFSR_LSA_UUID, EfsRpcDecryptFileSrv) => nameof(EfsRpcDecryptFileSrv),
            (EFSR_LSA_UUID, EfsRpcQueryUsersOnFile) => nameof(EfsRpcQueryUsersOnFile),
            (EFSR_LSA_UUID, EfsRpcQueryRecoveryAgents) => nameof(EfsRpcQueryRecoveryAgents),
            (EFSR_LSA_UUID, EfsRpcRemoveUsersFromFile) => nameof(EfsRpcRemoveUsersFromFile),
            (EFSR_LSA_UUID, EfsRpcAddUsersToFile) => nameof(EfsRpcAddUsersToFile),
            (FSRVP_UUID, IsPathSupported) => nameof(IsPathSupported),
            (FSRVP_UUID, IsPathShadowCopied) => nameof(IsPathShadowCopied),
            (DFSNM_UUID, NetrDfsAddStdRoot) => nameof(NetrDfsAddStdRoot),
            (DFSNM_UUID, NetrDfsRemoveStdRoot) => nameof(NetrDfsRemoveStdRoot),
            (DFSNM_UUID, NetrDfsAddRootTarget) => nameof(NetrDfsAddRootTarget),
            (DFSNM_UUID, NetrDfsRemoveRootTarget) => nameof(NetrDfsRemoveRootTarget),
            _ => null
        };

        // Check if an operation name was found
        if (operationName != null)
        {
            // Return the translated operation name and optionally include the original number in  parenthesis
            return alwaysIncludeOperationNumber ? $"{operationName} ({operationNumber})" : operationName;
        }
        else
        {
            // Return the original operation number if no match is found
            return operationNumber?.ToString(CultureInfo.InvariantCulture);
        }
    }
}
