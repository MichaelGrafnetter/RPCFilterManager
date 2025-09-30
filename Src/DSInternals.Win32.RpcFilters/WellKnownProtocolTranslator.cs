using System.Globalization;

namespace DSInternals.Win32.RpcFilters;

/// <summary>
/// Well-known RPC protocol translator.
/// </summary>
public static partial class WellKnownProtocolTranslator
{
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
            WellKnownProtocol.TaskSchedulerAgent => TSCH_SASec,
            WellKnownProtocol.NetSchedule => TSCH_ATSvc,
            WellKnownProtocol.TaskSchedulerService => TSCH_ITaskSchedulerService,
            WellKnownProtocol.EventLog => EVEN,
            WellKnownProtocol.EventLogV6 => EVEN6,
            WellKnownProtocol.MimiCom => KIWI,
            WellKnownProtocol.RemoteRegistry => RRP,
            WellKnownProtocol.InitShutdown => RSP_InitShutdown,
            WellKnownProtocol.WindowsShutdown => RSP_WindowsShutdown,
            WellKnownProtocol.SecurityAccountManager => SAMR,
            WellKnownProtocol.PrintSpooler => RPRN,
            WellKnownProtocol.NamespaceManagement => DFSNM,
            WellKnownProtocol.FileReplicationService => FRS1_frsrpc,
            WellKnownProtocol.DistributedFileReplication => FRS2,
            WellKnownProtocol.VolumeShadowCopy => FSRVP,
            WellKnownProtocol.Netlogon => NRPC,
            WellKnownProtocol.EncryptingFileSystem => EFSR_efsrpc,
            WellKnownProtocol.EncryptingFileSystemLSA => EFSR_lsarpc,
            WellKnownProtocol.ServerService => SRVS,
            WellKnownProtocol.WorkstationService => WKST,
            WellKnownProtocol.BackupKey => BKRP,
            WellKnownProtocol.LocalSecurityAuthority => LSAT,
            WellKnownProtocol.DnsManagement => DNSP,
            WellKnownProtocol.EndpointMapper => EPMAP,
            WellKnownProtocol.DirectoryServicesSetup => DSSP,
            WellKnownProtocol.MasterBrowser => BRWSA,
            WellKnownProtocol.RemoteAccessManagement => RRASM_rasrpc,
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
            case TSCH_ITaskSchedulerService_UUID:
            case TSCH_ATSvc_UUID:
            case TSCH_SASec_UUID:
            case EVEN_UUID:
            case EVEN6_UUID:
            case RRP_UUID:
            case RSP_InitShutdown_UUID:
            case RSP_WindowsShutdown_UUID:
            case SAMR_UUID:
            case RPRN_UUID:
            case DFSNM_UUID:
            case EFSR_efsrpc_UUID:
            case EFSR_lsarpc_UUID:
            case SRVS_UUID:
            case WKST_UUID:
            case FSRVP_UUID:
            case BKRP_UUID:
            case LSAT_UUID:
            case DNSP_UUID:
            case EPMAP_UUID:
            case DSSP_UUID:
            case BRWSA_UUID:
            case NRPC_UUID:
            case W32T_UUID:
            case DLTW_UUID:
            case RRASM_dimsvc_UUID:
            case RRASM_rasrpc_UUID:
            case RRASM_IRemoteNetworkConfig_UUID:
            case RRASM_IRemoteRouterRestart_UUID:
            case RRASM_IRemoteSetDnsConfig_UUID:
            case RRASM_IRemoteICFICSConfig_UUID:
            case RRASM_IRemoteStringIdConfig_UUID:
            case RRASM_IRemoteIPV6Config_UUID:
            case RRASM_IRemoteSstpCertCheck_UUID:
            case TSTS_TermSrvSession_UUID:
            case TSTS_TermSrvNotification_UUID:
            case TSTS_TermSrvEnumeration_UUID:
            case TSTS_IcaApi_UUID:
            case TSTS_RCMListener_UUID:
            case TSTS_RCMPublic_UUID:
            case TSTS_TSVIPPublic_UUID:
            case TSTS_SessEnvPublicRpc_UUID:
            case RAIW_winsif_UUID:
            case RAIW_winsi2_UUID:
                return true;
            case DRSR_drsuapi_UUID:
            case DRSR_dsaop_UUID:
            case FRS1_frsrpc_UUID:
            case FRS1_NtFrsApi_UUID:
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
            TSCH_SASec_UUID => "MS-TSCH (SASec)",
            TSCH_ATSvc_UUID => "MS-TSCH (ATSvc)",
            TSCH_ITaskSchedulerService_UUID => "MS-TSCH (ITaskSchedulerService)",
            EVEN_UUID => "MS-EVEN",
            EVEN6_UUID => "MS-EVEN6",
            KIWI_UUID => "MimiCom",
            RRP_UUID => "MS-RRP",
            RSP_InitShutdown_UUID => "MS-RSP (InitShutdown)",
            RSP_WindowsShutdown_UUID => "MS-RSP (WindowsShutdown)",
            RPRN_UUID => "MS-RPRN",
            PAR_UUID => "MS-PAR",
            DFSNM_UUID => "MS-DFSNM",
            FRS1_frsrpc_UUID => "MS-FRS1 (frsrpc)",
            FRS1_NtFrsApi_UUID => "MS-FRS1 (NtFrsApi)",
            FRS2_UUID => "MS-FRS2",
            FSRVP_UUID => "MS-FSRP",
            NRPC_UUID => "MS-NRPC",
            EFSR_efsrpc_UUID => "MS-EFSR (\\pipe\\efsrpc)",
            EFSR_lsarpc_UUID => "MS-EFSR (\\pipe\\lsarpc)",
            LSAT_UUID => "MS-LSAT",
            SRVS_UUID => "MS-SRVS",
            WKST_UUID => "MS-WKST",
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
            RRASM_rasrpc_UUID => "MS-RRASM (RASRPC)",
            RRASM_dimsvc_UUID => "MS-RRASM (DIMSVC)",
            RRASM_IRemoteNetworkConfig_UUID => "MS-RRASM (IRemoteNetworkConfig)",
            RRASM_IRemoteRouterRestart_UUID => "MS-RRASM (IRemoteRouterRestart)",
            RRASM_IRemoteSetDnsConfig_UUID => "MS-RRASM (IRemoteSetDnsConfig)",
            RRASM_IRemoteICFICSConfig_UUID => "MS-RRASM (IRemoteICFICSConfig)",
            RRASM_IRemoteStringIdConfig_UUID => "MS-RRASM (IRemoteStringIdConfig)",
            RRASM_IRemoteIPV6Config_UUID => "MS-RRASM (IRemoteIPV6Config)",
            RRASM_IRemoteSstpCertCheck_UUID => "MS-RRASM (IRemoteSstpCertCheck)",
            W32T_UUID => "MS-W32T",
            RAIW_winsif_UUID => "MS-RAIW (winsif)",
            RAIW_winsi2_UUID => "MS-RAIW (winsi2)",
            TSTS_TermSrvSession_UUID => "MS-TSTS (LSM Session)",
            TSTS_TermSrvNotification_UUID => "MS-TSTS (LSM Notification)",
            TSTS_TermSrvEnumeration_UUID => "MS-TSTS (LSM Enumeration)",
            TSTS_RCMPublic_UUID => "MS-TSTS (TermSrv)",
            TSTS_RCMListener_UUID => "MS-TSTS (TermSrv Listener)",
            TSTS_IcaApi_UUID => "MS-TSTS (Legacy)",
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
            CCFG_UUID => "MC-CCFG",
            IISA_IAppHostWritableAdminManager_UUID => "MC-IISA (IAppHostWritableAdminManager)",
            IISA_IAppHostPropertySchema_UUID => "MC-IISA (IAppHostPropertySchema)",
            IISA_IAppHostConfigLocationCollection_UUID => "MC-IISA (IAppHostConfigLocationCollection)",
            IISA_IAppHostMethodSchema_UUID => "MC-IISA (IAppHostMethodSchema)",
            IISA_IAppHostSectionGroup_UUID => "MC-IISA (IAppHostSectionGroup)",
            IISA_IAppHostConstantValue_UUID => "MC-IISA (IAppHostConstantValue)",
            IISA_IAppHostMethodInstance_UUID => "MC-IISA (IAppHostMethodInstance)",
            IISA_IAppHostElementSchemaCollection_UUID => "MC-IISA (IAppHostElementSchemaCollection)",
            IISA_IAppHostPropertySchemaCollection_UUID => "MC-IISA (IAppHostPropertySchemaCollection)",
            IISA_IAppHostMethod_UUID => "MC-IISA (IAppHostMethod)",
            IISA_IAppHostChangeHandler_UUID => "MC-IISA (IAppHostChangeHandler)",
            IISA_IAppHostConstantValueCollection_UUID => "MC-IISA (IAppHostConstantValueCollection)",
            IISA_IAppHostAdminManager_UUID => "MC-IISA (IAppHostAdminManager)",
            IISA_IAppHostProperty_UUID => "MC-IISA (IAppHostProperty)",
            IISA_IAppHostConfigException_UUID => "MC-IISA (IAppHostConfigException)",
            IISA_IAppHostConfigLocation_UUID => "MC-IISA (IAppHostConfigLocation)",
            IISA_IAppHostElementCollection_UUID => "MC-IISA (IAppHostElementCollection)",
            IISA_IAppHostChildElementCollection_UUID => "MC-IISA (IAppHostChildElementCollection)",
            IISA_IAppHostConfigManager_UUID => "MC-IISA (IAppHostConfigManager)",
            IISA_IAppHostPathMapper_UUID => "MC-IISA (IAppHostPathMapper)",
            IISA_IAppHostCollectionSchema_UUID => "MC-IISA (IAppHostCollectionSchema)",
            IISA_IAppHostElement_UUID => "MC-IISA (IAppHostElement)",
            IISA_IAppHostPropertyException_UUID => "MC-IISA (IAppHostPropertyException)",
            IISA_IAppHostElementSchema_UUID => "MC-IISA (IAppHostElementSchema)",
            IISA_IAppHostPropertyCollection_UUID => "MC-IISA (IAppHostPropertyCollection)",
            IISA_IAppHostMappingExtension_UUID => "MC-IISA (IAppHostMappingExtension)",
            IISA_IAppHostMethodCollection_UUID => "MC-IISA (IAppHostMethodCollection)",
            IISA_IAppHostConfigFile_UUID => "MC-IISA (IAppHostConfigFile)",
            IISA_IAppHostSectionDefinitionCollection_UUID => "MC-IISA (IAppHostSectionDefinitionCollection)",
            IISA_IAppHostSectionDefinition_UUID => "MC-IISA (IAppHostSectionDefinition)",
            ADTG_IDataFactory_UUID => "MS-ADTG (IDataFactory)",
            ADTG_IDataFactory2_UUID => "MS-ADTG (IDataFactory2)",
            ADTG_IDataFactory3_UUID => "MS-ADTG (IDataFactory3)",
            BPAU_UUID => "MS-BPAU",
            CAPR_UUID => "MS-CAPR",
            CMPO_UUID => "MS-CMPO",
            CMRP_UUID => "MS-CMRP",
            COM_UUID => "MS-COM",
            COMA_ICatalogTableRead_UUID => "MS-COMA (ICatalogTableRead)",
            COMA_IContainerControl_UUID => "MS-COMA (IContainerControl)",
            COMA_IAlternateLaunch_UUID => "MS-COMA (IAlternateLaunch)",
            COMA_ICatalogUtils_UUID => "MS-COMA (ICatalogUtils)",
            COMA_IRegister_UUID => "MS-COMA (IRegister)",
            COMA_ICatalogSession_UUID => "MS-COMA (ICatalogSession)",
            COMA_IRegister2_UUID => "MS-COMA (IRegister2)",
            COMA_IReplicationUtil_UUID => "MS-COMA (IReplicationUtil)",
            COMA_IContainerControl2_UUID => "MS-COMA (IContainerControl2)",
            COMA_IExport2_UUID => "MS-COMA (IExport2)",
            COMA_IImport2_UUID => "MS-COMA (IImport2)",
            COMA_ICatalogTableInfo_UUID => "MS-COMA (ICatalogTableInfo)",
            COMA_IExport_UUID => "MS-COMA (IExport)",
            COMA_ICatalog64BitSupport_UUID => "MS-COMA (ICatalog64BitSupport)",
            COMA_ICapabilitySupport_UUID => "MS-COMA (ICapabilitySupport)",
            COMA_ICatalogTableWrite_UUID => "MS-COMA (ICatalogTableWrite)",
            COMA_IImport_UUID => "MS-COMA (IImport)",
            COMA_ICatalogUtils2_UUID => "MS-COMA (ICatalogUtils2)",
            COMEV_IEventClass_UUID => "MS-COMEV (IEventClass)",
            COMEV_IEventClass2_UUID => "MS-COMEV (IEventClass2)",
            COMEV_IEventClass3_UUID => "MS-COMEV (IEventClass3)",
            COMEV_IEventSystem_UUID => "MS-COMEV (IEventSystem)",
            COMEV_IEventSystem2_UUID => "MS-COMEV (IEventSystem2)",
            COMEV_IEventSubscription_UUID => "MS-COMEV (IEventSubscription)",
            COMEV_IEventSubscription2_UUID => "MS-COMEV (IEventSubscription2)",
            COMEV_IEventSubscription3_UUID => "MS-COMEV (IEventSubscription3)",
            COMEV_IEventObjectCollection_UUID => "MS-COMEV (IEventObjectCollection)",
            COMEV_IEventSystemInitialize_UUID => "MS-COMEV (IEventSystemInitialize)",
            COMEV_IEnumEventObject_UUID => "MS-COMEV (IEnumEventObject)",
            COMT_IGetTrackingData_UUID => "MS-COMT (IGetTrackingData)",
            COMT_IProcessDump_UUID => "MS-COMT (IProcessDump)",
            COMT_IComTrackingInfoEvents_UUID => "MS-COMT (IComTrackingInfoEvents)",
            CSVP_IClusterSetup_UUID => "MS-CSVP (IClusterSetup)",
            CSVP_IClusterUpdate_UUID => "MS-CSVP (IClusterUpdate)",
            CSVP_IClusterCleanup_UUID => "MS-CSVP (IClusterCleanup)",
            CSVP_IClusterLog_UUID => "MS-CSVP (IClusterLog)",
            CSVP_IClusterFirewall_UUID => "MS-CSVP (IClusterFirewall)",
            CSVP_IClusterStorage2_UUID => "MS-CSVP (IClusterStorage2)",
            CSVP_IClusterStorage3_UUID => "MS-CSVP (IClusterStorage3)",
            CSVP_IClusterNetwork2_UUID => "MS-CSVP (IClusterNetwork2)",
            CSVP_ClusterStorage2_UUID => "MS-CSVP (ClusterStorage2)",
            CSVP_ClusterNetwork2_UUID => "MS-CSVP (ClusterNetwork2)",
            CSVP_ClusterCleanup_UUID => "MS-CSVP (ClusterCleanup)",
            CSVP_ClusterSetup_UUID => "MS-CSVP (ClusterSetup)",
            CSVP_ClusterLog_UUID => "MS-CSVP (ClusterLog)",
            CSVP_ClusterFirewall_UUID => "MS-CSVP (ClusterFirewall)",
            CSVP_ClusterUpdate_UUID => "MS-CSVP (ClusterUpdate)",
            DFSRH_IServerHealthReport_UUID => "MS-DFSRH (IServerHealthReport)",
            DFSRH_IServerHealthReport2_UUID => "MS-DFSRH (IServerHealthReport2)",
            DFSRH_IADProxy_UUID => "MS-DFSRH (IADProxy)",
            DFSRH_IADProxy2_UUID => "MS-DFSRH (IADProxy2)",
            DMRP_IVolumeClient_UUID => "MS-DMRP (IVolumeClient)",
            DMRP_IDMRemoteServer_UUID => "MS-DMRP (IDMRemoteServer)",
            DMRP_IDMNotify_UUID => "MS-DMRP (IDMNotify)",
            DMRP_IVolumeClient2_UUID => "MS-DMRP (IVolumeClient2)",
            DMRP_IVolumeClient4_UUID => "MS-DMRP (IVolumeClient4)",
            DMRP_IVolumeClient3_UUID => "MS-DMRP (IVolumeClient3)",
            FASP_UUID => "MS-FASP",
            FAX_faxclient_UUID => "MS-FAX (faxclient)",
            FAX_sharedfax_UUID => "MS-FAX (sharedfax)",
            FSRM_IFsrmFileManagementJob_UUID => "MS-FSRM (IFsrmFileManagementJob)",
            FSRM_IFsrmActionCommand_UUID => "MS-FSRM (IFsrmActionCommand)",
            FSRM_IFsrmQuotaBase_UUID => "MS-FSRM (IFsrmQuotaBase)",
            FSRM_IFsrmStorageModuleDefinition_UUID => "MS-FSRM (IFsrmStorageModuleDefinition)",
            FSRM_IFsrmMutableCollection_UUID => "MS-FSRM (IFsrmMutableCollection)",
            FSRM_IFsrmFileScreenTemplate_UUID => "MS-FSRM (IFsrmFileScreenTemplate)",
            FSRM_IFsrmObject_UUID => "MS-FSRM (IFsrmObject)",
            FSRM_IFsrmReportManager_UUID => "MS-FSRM (IFsrmReportManager)",
            FSRM_IFsrmActionReport_UUID => "MS-FSRM (IFsrmActionReport)",
            FSRM_IFsrmPropertyCondition_UUID => "MS-FSRM (IFsrmPropertyCondition)",
            FSRM_IFsrmQuota_UUID => "MS-FSRM (IFsrmQuota)",
            FSRM_IFsrmReportJob_UUID => "MS-FSRM (IFsrmReportJob)",
            FSRM_IFsrmDerivedObjectsResult_UUID => "MS-FSRM (IFsrmDerivedObjectsResult)",
            FSRM_IFsrmQuotaTemplateManager_UUID => "MS-FSRM (IFsrmQuotaTemplateManager)",
            FSRM_IFsrmFileGroupManager_UUID => "MS-FSRM (IFsrmFileGroupManager)",
            FSRM_IFsrmQuotaObject_UUID => "MS-FSRM (IFsrmQuotaObject)",
            FSRM_IFsrmPropertyDefinition2_UUID => "MS-FSRM (IFsrmPropertyDefinition2)",
            FSRM_IFsrmQuotaManagerEx_UUID => "MS-FSRM (IFsrmQuotaManagerEx)",
            FSRM_IFsrmProperty_UUID => "MS-FSRM (IFsrmProperty)",
            FSRM_IFsrmActionEventLog_UUID => "MS-FSRM (IFsrmActionEventLog)",
            FSRM_IFsrmPipelineModuleDefinition_UUID => "MS-FSRM (IFsrmPipelineModuleDefinition)",
            FSRM_IFsrmFileScreen_UUID => "MS-FSRM (IFsrmFileScreen)",
            FSRM_IFsrmReportScheduler_UUID => "MS-FSRM (IFsrmReportScheduler)",
            FSRM_IFsrmAction_UUID => "MS-FSRM (IFsrmAction)",
            FSRM_IFsrmPathMapper_UUID => "MS-FSRM (IFsrmPathMapper)",
            FSRM_IFsrmActionEmail2_UUID => "MS-FSRM (IFsrmActionEmail2)",
            FSRM_IFsrmQuotaManager_UUID => "MS-FSRM (IFsrmQuotaManager)",
            FSRM_IFsrmFileGroup_UUID => "MS-FSRM (IFsrmFileGroup)",
            FSRM_IFsrmCommittableCollection_UUID => "MS-FSRM (IFsrmCommittableCollection)",
            FSRM_IFsrmQuotaTemplateImported_UUID => "MS-FSRM (IFsrmQuotaTemplateImported)",
            FSRM_IFsrmQuotaTemplate_UUID => "MS-FSRM (IFsrmQuotaTemplate)",
            FSRM_IFsrmFileGroupImported_UUID => "MS-FSRM (IFsrmFileGroupImported)",
            FSRM_IFsrmClassificationRule_UUID => "MS-FSRM (IFsrmClassificationRule)",
            FSRM_IFsrmClassifierModuleDefinition_UUID => "MS-FSRM (IFsrmClassifierModuleDefinition)",
            FSRM_IFsrmFileScreenException_UUID => "MS-FSRM (IFsrmFileScreenException)",
            FSRM_IFsrmRule_UUID => "MS-FSRM (IFsrmRule)",
            FSRM_IFsrmFileScreenTemplateManager_UUID => "MS-FSRM (IFsrmFileScreenTemplateManager)",
            FSRM_IFsrmClassificationManager_UUID => "MS-FSRM (IFsrmClassificationManager)",
            FSRM_IFsrmActionEmail_UUID => "MS-FSRM (IFsrmActionEmail)",
            FSRM_IFsrmReport_UUID => "MS-FSRM (IFsrmReport)",
            FSRM_IFsrmFileScreenTemplateImported_UUID => "MS-FSRM (IFsrmFileScreenTemplateImported)",
            FSRM_IFsrmPropertyDefinitionValue_UUID => "MS-FSRM (IFsrmPropertyDefinitionValue)",
            FSRM_IFsrmPropertyDefinition_UUID => "MS-FSRM (IFsrmPropertyDefinition)",
            FSRM_IFsrmFileManagementJobManager_UUID => "MS-FSRM (IFsrmFileManagementJobManager)",
            FSRM_IFsrmFileScreenBase_UUID => "MS-FSRM (IFsrmFileScreenBase)",
            FSRM_IFsrmSetting_UUID => "MS-FSRM (IFsrmSetting)",
            FSRM_IFsrmCollection_UUID => "MS-FSRM (IFsrmCollection)",
            FSRM_IFsrmAutoApplyQuota_UUID => "MS-FSRM (IFsrmAutoApplyQuota)",
            FSRM_IFsrmFileScreenManager_UUID => "MS-FSRM (IFsrmFileScreenManager)",
            GKDI_UUID => "MS-GKDI",
            IISS_UUID => "MS-IISS",
            IMSA_IMSAdminBase3W_UUID => "MS-IMSA (IMSAdminBase3W)",
            IMSA_IMSAdminBase2W_UUID => "MS-IMSA (IMSAdminBase2W)",
            IMSA_IWamAdmin2_UUID => "MS-IMSA (IWamAdmin2)",
            IMSA_IMSAdminBaseW_UUID => "MS-IMSA (IMSAdminBaseW)",
            IMSA_IWamAdmin_UUID => "MS-IMSA (IWamAdmin)",
            IMSA_IIISCertObj_UUID => "MS-IMSA (IIISCertObj)",
            IMSA_IIISApplicationAdmin_UUID => "MS-IMSA (IIISApplicationAdmin)",
            IOI_IRemoteDispatch_UUID => "MS-IOI (IRemoteDispatch)",
            IOI_IServicedComponentInfo_UUID => "MS-IOI (IServicedComponentInfo)",
            IOI_IManagedObject_UUID => "MS-IOI (IManagedObject)",
            IRP_UUID => "MS-IRP",
            LREC_UUID => "MS-LREC",
            MQDS_dscomm2_UUID => "MS-MQDS (dscomm2)",
            MQDS_dscomm_UUID => "MS-MQDS (dscomm)",
            MQMP_qmcomm2_UUID => "MS-MQMP (qmcomm2)",
            MQMP_qmcomm_UUID => "MS-MQMP (qmcomm)",
            MQMR_UUID => "MS-MQMR",
            MQQP_UUID => "MS-MQQP",
            MQRR_UUID => "MS-MQRR",
            MSRP_msgsvc_UUID => "MS-MSRP (msgsvc)",
            MSRP_msgsvcsend_UUID => "MS-MSRP (msgsvcsend)",
            OAUT_IDispatch_UUID => "MS-OAUT (IDispatch)",
            OAUT_ITypeInfo_UUID => "MS-OAUT (ITypeInfo)",
            OAUT_ITypeLib_UUID => "MS-OAUT (ITypeLib)",
            OAUT_ITypeComp_UUID => "MS-OAUT (ITypeComp)",
            OAUT_IEnumVARIANT_UUID => "MS-OAUT (IEnumVARIANT)",
            OAUT_ITypeLib2_UUID => "MS-OAUT (ITypeLib2)",
            OAUT_ITypeInfo2_UUID => "MS-OAUT (ITypeInfo2)",
            OCSPA_UUID => "MS-OCSPA",
            OXABREF_UUID => "MS-OXABREF",
            OXCRPC_emsmdb_UUID => "MS-OXCRPC (emsmdb)",
            OXCRPC_asyncemsmdb_UUID => "MS-OXCRPC (asyncemsmdb)",
            PCQ_UUID => "MS-PCQ",
            PLA_ITraceDataProviderCollection_UUID => "MS-PLA (ITraceDataProviderCollection)",
            PLA_IFolderAction_UUID => "MS-PLA (IFolderAction)",
            PLA_IValueMapItem_UUID => "MS-PLA (IValueMapItem)",
            PLA_03837541_UUID => "MS-PLA (03837541)",
            PLA_IFolderActionCollection_UUID => "MS-PLA (IFolderActionCollection)",
            PLA_IDataCollectorSetCollection_UUID => "MS-PLA (IDataCollectorSetCollection)",
            PLA_ISchedule_UUID => "MS-PLA (ISchedule)",
            PLA_IValueMap_UUID => "MS-PLA (IValueMap)",
            PLA_ITraceDataCollector_UUID => "MS-PLA (ITraceDataCollector)",
            PLA_IApiTracingDataCollector_UUID => "MS-PLA (IApiTracingDataCollector)",
            PLA_ITraceDataProvider_UUID => "MS-PLA (ITraceDataProvider)",
            PLA_IScheduleCollection_UUID => "MS-PLA (IScheduleCollection)",
            PLA_IPerformanceCounterDataCollector_UUID => "MS-PLA (IPerformanceCounterDataCollector)",
            PLA_IDataCollectorSet_UUID => "MS-PLA (IDataCollectorSet)",
            PLA_IDataCollector_UUID => "MS-PLA (IDataCollector)",
            PLA_IConfigurationDataCollector_UUID => "MS-PLA (IConfigurationDataCollector)",
            PLA_IDataCollectorCollection_UUID => "MS-PLA (IDataCollectorCollection)",
            PLA_IAlertDataCollector_UUID => "MS-PLA (IAlertDataCollector)",
            RAA_UUID => "MS-RAA",
            RAI_IRASrv_UUID => "MS-RAI (IRASrv)",
            RAI_PCHService_UUID => "MS-RAI (PCHService)",
            RAI_IPCHService_UUID => "MS-RAI (IPCHService)",
            RAI_RASrv_UUID => "MS-RAI (RASrv Class)",
            RAI_IPCHCollection_UUID => "MS-RAI (IPCHCollection)",
            RAI_ISAFSession_UUID => "MS-RAI (ISAFSession)",
            RAINPS_IIASDataStoreComServer2_UUID => "MS-RAINPS (IIASDataStoreComServer2)",
            RAINPS_IIASDataStoreComServer_UUID => "MS-RAINPS (IIASDataStoreComServer)",
            RPCL_UUID => "MS-RPCL",
            RSMP_INtmsObjectManagement3_UUID => "MS-RSMP (INtmsObjectManagement3)",
            RSMP_INtmsSession1_UUID => "MS-RSMP (INtmsSession1)",
            RSMP_CNtmsSvr_UUID => "MS-RSMP (CNtmsSvr)",
            RSMP_IMessenger_UUID => "MS-RSMP (IMessenger)",
            RSMP_INtmsObjectManagement2_UUID => "MS-RSMP (INtmsObjectManagement2)",
            RSMP_INtmsMediaServices1_UUID => "MS-RSMP (INtmsMediaServices1)",
            RSMP_INtmsLibraryControl2_UUID => "MS-RSMP (INtmsLibraryControl2)",
            RSMP_INtmsLibraryControl1_UUID => "MS-RSMP (INtmsLibraryControl1)",
            RSMP_IClientSink_UUID => "MS-RSMP (IClientSink)",
            RSMP_INtmsObjectInfo1_UUID => "MS-RSMP (INtmsObjectInfo1)",
            RSMP_IRobustNtmsMediaServices1_UUID => "MS-RSMP (IRobustNtmsMediaServices1)",
            RSMP_INtmsNotifySink_UUID => "MS-RSMP (INtmsNotifySink)",
            RSMP_INtmsObjectManagement1_UUID => "MS-RSMP (INtmsObjectManagement1)",
            SCMP_IVssEnumMgmtObject_UUID => "MS-SCMP (IVssEnumMgmtObject)",
            SCMP_IVssSnapshotMgmt_UUID => "MS-SCMP (IVssSnapshotMgmt)",
            SCMP_IVssDifferentialSoftwareSnapshotMgmt_UUID => "MS-SCMP (IVssDifferentialSoftwareSnapshotMgmt)",
            SCMP_IVssEnumObject_UUID => "MS-SCMP (IVssEnumObject)",
            SWN_UUID => "MS-SWN",
            TPMVSC_ITpmVirtualSmartCardManagerStatusCallback_UUID => "MS-TPMVSC (ITpmVirtualSmartCardManagerStatusCallback)",
            TPMVSC_ITpmVirtualSmartCardManager2_UUID => "MS-TPMVSC (ITpmVirtualSmartCardManager2)",
            TPMVSC_ITpmVirtualSmartCardManager_UUID => "MS-TPMVSC (ITpmVirtualSmartCardManager)",
            TPMVSC_ITpmVirtualSmartCardManager3_UUID => "MS-TPMVSC (ITpmVirtualSmartCardManager3)",
            TRP_remotesp_UUID => "MS-TRP (remotesp)",
            TRP_tapsrv_UUID => "MS-TRP (tapsrv)",
            TSGU_UUID => "MS-TSGU",
            TSRAP_UUID => "MS-TSRAP",
            UAMG_IWindowsDriverUpdate4_UUID => "MS-UAMG (IWindowsDriverUpdate4)",
            UAMG_IUpdateSearcher3_UUID => "MS-UAMG (IUpdateSearcher3)",
            UAMG_IUpdateCollection_UUID => "MS-UAMG (IUpdateCollection)",
            UAMG_IUpdateServiceManager2_UUID => "MS-UAMG (IUpdateServiceManager2)",
            UAMG_IWindowsDriverUpdateEntryCollection_UUID => "MS-UAMG (IWindowsDriverUpdateEntryCollection)",
            UAMG_IUpdate3_UUID => "MS-UAMG (IUpdate3)",
            UAMG_IUpdate2_UUID => "MS-UAMG (IUpdate2)",
            UAMG_IUpdateService2_UUID => "MS-UAMG (IUpdateService2)",
            UAMG_IUpdateServiceManager_UUID => "MS-UAMG (IUpdateServiceManager)",
            UAMG_IUpdate4_UUID => "MS-UAMG (IUpdate4)",
            UAMG_ICategoryCollection_UUID => "MS-UAMG (ICategoryCollection)",
            UAMG_IUpdateIdentity_UUID => "MS-UAMG (IUpdateIdentity)",
            UAMG_IWindowsDriverUpdate3_UUID => "MS-UAMG (IWindowsDriverUpdate3)",
            UAMG_IAutomaticUpdates2_UUID => "MS-UAMG (IAutomaticUpdates2)",
            UAMG_IUpdateSearcher2_UUID => "MS-UAMG (IUpdateSearcher2)",
            UAMG_IUpdateExceptionCollection_UUID => "MS-UAMG (IUpdateExceptionCollection)",
            UAMG_IUpdateDownloadContent_UUID => "MS-UAMG (IUpdateDownloadContent)",
            UAMG_IWindowsDriverUpdate2_UUID => "MS-UAMG (IWindowsDriverUpdate2)",
            UAMG_IAutomaticUpdates_UUID => "MS-UAMG (IAutomaticUpdates)",
            UAMG_IUpdate_UUID => "MS-UAMG (IUpdate)",
            UAMG_IWindowsDriverUpdate5_UUID => "MS-UAMG (IWindowsDriverUpdate5)",
            UAMG_ISearchJob_UUID => "MS-UAMG (ISearchJob)",
            UAMG_IUpdateService_UUID => "MS-UAMG (IUpdateService)",
            UAMG_IImageInformation_UUID => "MS-UAMG (IImageInformation)",
            UAMG_IUpdateSession_UUID => "MS-UAMG (IUpdateSession)",
            UAMG_ICategory_UUID => "MS-UAMG (ICategory)",
            UAMG_IWindowsUpdateAgentInfo_UUID => "MS-UAMG (IWindowsUpdateAgentInfo)",
            UAMG_IUpdateSearcher_UUID => "MS-UAMG (IUpdateSearcher)",
            UAMG_IUpdateSession3_UUID => "MS-UAMG (IUpdateSession3)",
            UAMG_IUpdateSession2_UUID => "MS-UAMG (IUpdateSession2)",
            UAMG_IUpdateServiceCollection_UUID => "MS-UAMG (IUpdateServiceCollection)",
            UAMG_IUpdateException_UUID => "MS-UAMG (IUpdateException)",
            UAMG_IUpdateHistoryEntryCollection_UUID => "MS-UAMG (IUpdateHistoryEntryCollection)",
            UAMG_IWindowsDriverUpdate_UUID => "MS-UAMG (IWindowsDriverUpdate)",
            UAMG_IUpdateDownloadContentCollection_UUID => "MS-UAMG (IUpdateDownloadContentCollection)",
            UAMG_IUpdateHistoryEntry_UUID => "MS-UAMG (IUpdateHistoryEntry)",
            UAMG_IUpdate5_UUID => "MS-UAMG (IUpdate5)",
            UAMG_IUpdateHistoryEntry2_UUID => "MS-UAMG (IUpdateHistoryEntry2)",
            UAMG_IUpdateDownloadContent2_UUID => "MS-UAMG (IUpdateDownloadContent2)",
            UAMG_ISearchResult_UUID => "MS-UAMG (ISearchResult)",
            UAMG_IInstallationBehavior_UUID => "MS-UAMG (IInstallationBehavior)",
            UAMG_IUpdateServiceRegistration_UUID => "MS-UAMG (IUpdateServiceRegistration)",
            UAMG_IAutomaticUpdatesResults_UUID => "MS-UAMG (IAutomaticUpdatesResults)",
            UAMG_IWindowsDriverUpdateEntry_UUID => "MS-UAMG (IWindowsDriverUpdateEntry)",
            UAMG_IStringCollection_UUID => "MS-UAMG (IStringCollection)",
            VDS_IVdsServiceSw_UUID => "MS-VDS (IVdsServiceSw)",
            VDS_IVdsVolumeMF2_UUID => "MS-VDS (IVdsVolumeMF2)",
            VDS_IVdsVDisk_UUID => "MS-VDS (IVdsVDisk)",
            VDS_IVdsHbaPort_UUID => "MS-VDS (IVdsHbaPort)",
            VDS_IVdsDiskPartitionMF2_UUID => "MS-VDS (IVdsDiskPartitionMF2)",
            VDS_IVdsVolumePlex_UUID => "MS-VDS (IVdsVolumePlex)",
            VDS_IVdsAdvancedDisk3_UUID => "MS-VDS (IVdsAdvancedDisk3)",
            VDS_IVdsDisk2_UUID => "MS-VDS (IVdsDisk2)",
            VDS_IVdsDisk3_UUID => "MS-VDS (IVdsDisk3)",
            VDS_IVdsServiceSAN_UUID => "MS-VDS (IVdsServiceSAN)",
            VDS_IVdsIscsiInitiatorAdapter_UUID => "MS-VDS (IVdsIscsiInitiatorAdapter)",
            VDS_IVdsVolume2_UUID => "MS-VDS (IVdsVolume2)",
            VDS_IVdsServiceUninstallDisk_UUID => "MS-VDS (IVdsServiceUninstallDisk)",
            VDS_IVdsDiskPartitionMF_UUID => "MS-VDS (IVdsDiskPartitionMF)",
            VDS_IVdsOpenVDisk_UUID => "MS-VDS (IVdsOpenVDisk)",
            VDS_IVdsDiskOnline_UUID => "MS-VDS (IVdsDiskOnline)",
            VDS_IVdsCreatePartitionEx_UUID => "MS-VDS (IVdsCreatePartitionEx)",
            VDS_IVdsSubSystemImportTarget_UUID => "MS-VDS (IVdsSubSystemImportTarget)",
            VDS_IVdsVolumeMF_UUID => "MS-VDS (IVdsVolumeMF)",
            VDS_IVdsAdvancedDisk2_UUID => "MS-VDS (IVdsAdvancedDisk2)",
            VDS_IVdsServiceInitialization_UUID => "MS-VDS (IVdsServiceInitialization)",
            VDS_IVdsHwProvider_UUID => "MS-VDS (IVdsHwProvider)",
            VDS_IVdsVolumeShrink_UUID => "MS-VDS (IVdsVolumeShrink)",
            VDS_IVdsPack2_UUID => "MS-VDS (IVdsPack2)",
            VDS_IVdsAdvancedDisk_UUID => "MS-VDS (IVdsAdvancedDisk)",
            VDS_IVdsSwProvider_UUID => "MS-VDS (IVdsSwProvider)",
            VDS_IVdsServiceLoader_UUID => "MS-VDS (IVdsServiceLoader)",
            VDS_IVdsDisk_UUID => "MS-VDS (IVdsDisk)",
            VDS_IVdsAdviseSink_UUID => "MS-VDS (IVdsAdviseSink)",
            VDS_IVdsVolumeOnline_UUID => "MS-VDS (IVdsVolumeOnline)",
            VDS_IVdsRemovable_UUID => "MS-VDS (IVdsRemovable)",
            VDS_IVdsServiceIscsi_UUID => "MS-VDS (IVdsServiceIscsi)",
            VDS_IVdsPack_UUID => "MS-VDS (IVdsPack)",
            VDS_IVdsAsync_UUID => "MS-VDS (IVdsAsync)",
            VDS_IVdsVolume_UUID => "MS-VDS (IVdsVolume)",
            VDS_IEnumVdsObject_UUID => "MS-VDS (IEnumVdsObject)",
            VDS_IVdsServiceHba_UUID => "MS-VDS (IVdsServiceHba)",
            VDS_IVdsService_UUID => "MS-VDS (IVdsService)",
            VDS_IVdsVolumeMF3_UUID => "MS-VDS (IVdsVolumeMF3)",
            VDS_IVdsVdProvider_UUID => "MS-VDS (IVdsVdProvider)",
            VDS_IVdsProvider_UUID => "MS-VDS (IVdsProvider)",
            VDS_IVdsIscsiInitiatorPortal_UUID => "MS-VDS (IVdsIscsiInitiatorPortal)",
            WDSC_UUID => "MS-WDSC",
            WMI_IEnumWbemClassObject_UUID => "MS-WMI (IEnumWbemClassObject)",
            WMI_IWbemFetchSmartEnum_UUID => "MS-WMI (IWbemFetchSmartEnum)",
            WMI_IWbemRefreshingServices_UUID => "MS-WMI (IWbemRefreshingServices)",
            WMI_IWbemWCOSmartEnum_UUID => "MS-WMI (IWbemWCOSmartEnum)",
            WMI_IWbemCallResult_UUID => "MS-WMI (IWbemCallResult)",
            WMI_IWbemObjectSink_UUID => "MS-WMI (IWbemObjectSink)",
            WMI_IWbemRemoteRefresher_UUID => "MS-WMI (IWbemRemoteRefresher)",
            WMI_WbemContext_UUID => "MS-WMI (WbemContext)",
            WMI_WbemLevel1Login_UUID => "MS-WMI (WbemLevel1Login)",
            WMI_WbemClassObject_UUID => "MS-WMI (WbemClassObject)",
            WMI_WbemBackupRestore_UUID => "MS-WMI (WbemBackupRestore)",
            WSRM_IWRMConfig_UUID => "MS-WSRM (IWRMConfig)",
            WSRM_IResourceManager2_UUID => "MS-WSRM (IResourceManager2)",
            WSRM_IWRMCalendar_UUID => "MS-WSRM (IWRMCalendar)",
            WSRM_IWRMAccounting_UUID => "MS-WSRM (IWRMAccounting)",
            WSRM_IWRMPolicy_UUID => "MS-WSRM (IWRMPolicy)",
            WSRM_IWRMMachineGroup_UUID => "MS-WSRM (IWRMMachineGroup)",
            WSRM_IWRMResourceGroup_UUID => "MS-WSRM (IWRMResourceGroup)",
            WSRM_IResourceManager_UUID => "MS-WSRM (IResourceManager)",
            WSRM_ResourceManager_UUID => "MS-WSRM (ResourceManager)",
            WSRM_IWRMProtocol_UUID => "MS-WSRM (IWRMProtocol)",
            WSRM_IWRMRemoteSessionMgmt_UUID => "MS-WSRM (IWRMRemoteSessionMgmt)",
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
            (TSCH_ITaskSchedulerService_UUID, SchRpcRegisterTask) => nameof(SchRpcRegisterTask),
            (TSCH_ATSvc_UUID, NetrJobAdd) => nameof(NetrJobAdd),
            (SRVS_UUID, NetrFileEnum) => nameof(NetrFileEnum),
            (SRVS_UUID, NetrSessionEnum) => nameof(NetrSessionEnum),
            (SRVS_UUID, NetrShareEnum) => nameof(NetrShareEnum),
            (SRVS_UUID, NetrConnectionEnum) => nameof(NetrConnectionEnum),
            (PAR_UUID, RpcAsyncAddPrinterDriver) => nameof(RpcAsyncAddPrinterDriver),
            (RPRN_UUID, RpcAddPrinterDriverEx) => nameof(RpcAddPrinterDriverEx),
            (RPRN_UUID, RpcRemoteFindFirstPrinterChangeNotification) => nameof(RpcRemoteFindFirstPrinterChangeNotification),
            (RPRN_UUID, RpcRemoteFindFirstPrinterChangeNotificationEx) => nameof(RpcRemoteFindFirstPrinterChangeNotificationEx),
            (SAMR_UUID, SamrEnumerateGroupsInDomain) => nameof(SamrEnumerateGroupsInDomain),
            (SAMR_UUID, SamrEnumerateUsersInDomain) => nameof(SamrEnumerateUsersInDomain),
            (EFSR_efsrpc_UUID, LsarRetrievePrivateData) => nameof(LsarRetrievePrivateData),
            (EFSR_efsrpc_UUID, EfsRpcOpenFileRaw) => nameof(EfsRpcOpenFileRaw),
            (EFSR_efsrpc_UUID, EfsRpcEncryptFileSrv) => nameof(EfsRpcEncryptFileSrv),
            (EFSR_efsrpc_UUID, EfsRpcDecryptFileSrv) => nameof(EfsRpcDecryptFileSrv),
            (EFSR_efsrpc_UUID, EfsRpcQueryUsersOnFile) => nameof(EfsRpcQueryUsersOnFile),
            (EFSR_efsrpc_UUID, EfsRpcQueryRecoveryAgents) => nameof(EfsRpcQueryRecoveryAgents),
            (EFSR_efsrpc_UUID, EfsRpcRemoveUsersFromFile) => nameof(EfsRpcRemoveUsersFromFile),
            (EFSR_efsrpc_UUID, EfsRpcAddUsersToFile) => nameof(EfsRpcAddUsersToFile),
            (EFSR_lsarpc_UUID, EfsRpcOpenFileRaw) => nameof(EfsRpcOpenFileRaw),
            (EFSR_lsarpc_UUID, EfsRpcEncryptFileSrv) => nameof(EfsRpcEncryptFileSrv),
            (EFSR_lsarpc_UUID, EfsRpcDecryptFileSrv) => nameof(EfsRpcDecryptFileSrv),
            (EFSR_lsarpc_UUID, EfsRpcQueryUsersOnFile) => nameof(EfsRpcQueryUsersOnFile),
            (EFSR_lsarpc_UUID, EfsRpcQueryRecoveryAgents) => nameof(EfsRpcQueryRecoveryAgents),
            (EFSR_lsarpc_UUID, EfsRpcRemoveUsersFromFile) => nameof(EfsRpcRemoveUsersFromFile),
            (EFSR_lsarpc_UUID, EfsRpcAddUsersToFile) => nameof(EfsRpcAddUsersToFile),
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
