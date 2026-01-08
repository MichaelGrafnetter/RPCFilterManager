#pragma warning disable CA1707 // Identifiers should not contain underscores
#pragma warning disable CA1711 // Identifiers should not have incorrect suffix

namespace DSInternals.Win32.RpcFilters;

/// <summary>
/// Well-known RPC protocol translator.
/// </summary>
public static partial class WellKnownProtocolTranslator
{
    #region Misc Protocols
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
    /// MC-CCFG: CleanupNode
    /// </summary>
    public const ushort CleanupNode = 0;

    /// <summary>
    /// MS-BKRP: BackuprKey
    /// </summary>
    public const ushort BackuprKey = 0;

    /// <summary>
    /// MS-BPAU: ExchangePublicKeys
    /// </summary>
    public const ushort ExchangePublicKeys = 0;

    #endregion // Misc Protocols
    #region MS-BRWSA

    /// <summary>
    /// MS-BRWSA: Opnum0NotUsedOnWire
    /// </summary>
    public const ushort BRWSA_Opnum0NotUsedOnWire = 0;

    /// <summary>
    /// MS-BRWSA: Opnum1NotUsedOnWire
    /// </summary>
    public const ushort BRWSA_Opnum1NotUsedOnWire = 1;

    /// <summary>
    /// MS-BRWSA: I_BrowserrQueryOtherDomains
    /// </summary>
    public const ushort I_BrowserrQueryOtherDomains = 2;

    /// <summary>
    /// MS-BRWSA: Opnum3NotUsedOnWire
    /// </summary>
    public const ushort BRWSA_Opnum3NotUsedOnWire = 3;

    /// <summary>
    /// MS-BRWSA: Opnum4NotUsedOnWire
    /// </summary>
    public const ushort BRWSA_Opnum4NotUsedOnWire = 4;

    /// <summary>
    /// MS-BRWSA: Opnum5NotUsedOnWire
    /// </summary>
    public const ushort BRWSA_Opnum5NotUsedOnWire = 5;

    /// <summary>
    /// MS-BRWSA: Opnum6NotUsedOnWire
    /// </summary>
    public const ushort BRWSA_Opnum6NotUsedOnWire = 6;

    /// <summary>
    /// MS-BRWSA: Opnum7NotUsedOnWire
    /// </summary>
    public const ushort BRWSA_Opnum7NotUsedOnWire = 7;

    /// <summary>
    /// MS-BRWSA: Opnum8NotUsedOnWire
    /// </summary>
    public const ushort BRWSA_Opnum8NotUsedOnWire = 8;

    /// <summary>
    /// MS-BRWSA: Opnum9NotUsedOnWire
    /// </summary>
    public const ushort BRWSA_Opnum9NotUsedOnWire = 9;

    /// <summary>
    /// MS-BRWSA: Opnum10NotUsedOnWire
    /// </summary>
    public const ushort BRWSA_Opnum10NotUsedOnWire = 10;

    /// <summary>
    /// MS-BRWSA: Opnum11NotUsedOnWire
    /// </summary>
    public const ushort BRWSA_Opnum11NotUsedOnWire = 11;

    #endregion // MS-BRWSA
    #region MS-CAPR

    /// <summary>
    /// MS-CAPR: LsarGetAvailableCAPIDs
    /// </summary>
    public const ushort LsarGetAvailableCAPIDs = 0;

    #endregion // MS-CAPR
    #region MS-GKDI

    /// <summary>
    /// MS-GKDI: GetKey
    /// </summary>
    public const ushort GetKey = 0;

    #endregion // MS-GKDI
    #region MS-SAMR

    /// <summary>
    /// MS-SAMR: SamrConnect
    /// </summary>
    public const ushort SamrConnect = 0;

    /// <summary>
    /// MS-SAMR: SamrCloseHandle
    /// </summary>
    public const ushort SamrCloseHandle = 1;

    /// <summary>
    /// MS-SAMR: SamrSetSecurityObject
    /// </summary>
    public const ushort SamrSetSecurityObject = 2;

    /// <summary>
    /// MS-SAMR: SamrQuerySecurityObject
    /// </summary>
    public const ushort SamrQuerySecurityObject = 3;

    /// <summary>
    /// MS-SAMR: Opnum4NotUsedOnWire
    /// </summary>
    public const ushort SAMR_Opnum4NotUsedOnWire = 4;

    /// <summary>
    /// MS-SAMR: SamrLookupDomainInSamServer
    /// </summary>
    public const ushort SamrLookupDomainInSamServer = 5;

    /// <summary>
    /// MS-SAMR: SamrEnumerateDomainsInSamServer
    /// </summary>
    public const ushort SamrEnumerateDomainsInSamServer = 6;

    /// <summary>
    /// MS-SAMR: SamrOpenDomain
    /// </summary>
    public const ushort SamrOpenDomain = 7;

    /// <summary>
    /// MS-SAMR: SamrQueryInformationDomain
    /// </summary>
    public const ushort SamrQueryInformationDomain = 8;

    /// <summary>
    /// MS-SAMR: SamrSetInformationDomain
    /// </summary>
    public const ushort SamrSetInformationDomain = 9;

    /// <summary>
    /// MS-SAMR: SamrCreateGroupInDomain
    /// </summary>
    public const ushort SamrCreateGroupInDomain = 10;

    /// <summary>
    /// MS-SAMR: SamrEnumerateGroupsInDomain
    /// </summary>
    public const ushort SamrEnumerateGroupsInDomain = 11;

    /// <summary>
    /// MS-SAMR: SamrCreateUserInDomain
    /// </summary>
    public const ushort SamrCreateUserInDomain = 12;

    /// <summary>
    /// MS-SAMR: SamrEnumerateUsersInDomain
    /// </summary>
    public const ushort SamrEnumerateUsersInDomain = 13;

    /// <summary>
    /// MS-SAMR: SamrCreateAliasInDomain
    /// </summary>
    public const ushort SamrCreateAliasInDomain = 14;

    /// <summary>
    /// MS-SAMR: SamrEnumerateAliasesInDomain
    /// </summary>
    public const ushort SamrEnumerateAliasesInDomain = 15;

    /// <summary>
    /// MS-SAMR: SamrGetAliasMembership
    /// </summary>
    public const ushort SamrGetAliasMembership = 16;

    /// <summary>
    /// MS-SAMR: SamrLookupNamesInDomain
    /// </summary>
    public const ushort SamrLookupNamesInDomain = 17;

    /// <summary>
    /// MS-SAMR: SamrLookupIdsInDomain
    /// </summary>
    public const ushort SamrLookupIdsInDomain = 18;

    /// <summary>
    /// MS-SAMR: SamrOpenGroup
    /// </summary>
    public const ushort SamrOpenGroup = 19;

    /// <summary>
    /// MS-SAMR: SamrQueryInformationGroup
    /// </summary>
    public const ushort SamrQueryInformationGroup = 20;

    /// <summary>
    /// MS-SAMR: SamrSetInformationGroup
    /// </summary>
    public const ushort SamrSetInformationGroup = 21;

    /// <summary>
    /// MS-SAMR: SamrAddMemberToGroup
    /// </summary>
    public const ushort SamrAddMemberToGroup = 22;

    /// <summary>
    /// MS-SAMR: SamrDeleteGroup
    /// </summary>
    public const ushort SamrDeleteGroup = 23;

    /// <summary>
    /// MS-SAMR: SamrRemoveMemberFromGroup
    /// </summary>
    public const ushort SamrRemoveMemberFromGroup = 24;

    /// <summary>
    /// MS-SAMR: SamrGetMembersInGroup
    /// </summary>
    public const ushort SamrGetMembersInGroup = 25;

    /// <summary>
    /// MS-SAMR: SamrSetMemberAttributesOfGroup
    /// </summary>
    public const ushort SamrSetMemberAttributesOfGroup = 26;

    /// <summary>
    /// MS-SAMR: SamrOpenAlias
    /// </summary>
    public const ushort SamrOpenAlias = 27;

    /// <summary>
    /// MS-SAMR: SamrQueryInformationAlias
    /// </summary>
    public const ushort SamrQueryInformationAlias = 28;

    /// <summary>
    /// MS-SAMR: SamrSetInformationAlias
    /// </summary>
    public const ushort SamrSetInformationAlias = 29;

    /// <summary>
    /// MS-SAMR: SamrDeleteAlias
    /// </summary>
    public const ushort SamrDeleteAlias = 30;

    /// <summary>
    /// MS-SAMR: SamrAddMemberToAlias
    /// </summary>
    public const ushort SamrAddMemberToAlias = 31;

    /// <summary>
    /// MS-SAMR: SamrRemoveMemberFromAlias
    /// </summary>
    public const ushort SamrRemoveMemberFromAlias = 32;

    /// <summary>
    /// MS-SAMR: SamrGetMembersInAlias
    /// </summary>
    public const ushort SamrGetMembersInAlias = 33;

    /// <summary>
    /// MS-SAMR: SamrOpenUser
    /// </summary>
    public const ushort SamrOpenUser = 34;

    /// <summary>
    /// MS-SAMR: SamrDeleteUser
    /// </summary>
    public const ushort SamrDeleteUser = 35;

    /// <summary>
    /// MS-SAMR: SamrQueryInformationUser
    /// </summary>
    public const ushort SamrQueryInformationUser = 36;

    /// <summary>
    /// MS-SAMR: SamrSetInformationUser
    /// </summary>
    public const ushort SamrSetInformationUser = 37;

    /// <summary>
    /// MS-SAMR: SamrChangePasswordUser
    /// </summary>
    public const ushort SamrChangePasswordUser = 38;

    /// <summary>
    /// MS-SAMR: SamrGetGroupsForUser
    /// </summary>
    public const ushort SamrGetGroupsForUser = 39;

    /// <summary>
    /// MS-SAMR: SamrQueryDisplayInformation
    /// </summary>
    public const ushort SamrQueryDisplayInformation = 40;

    /// <summary>
    /// MS-SAMR: SamrGetDisplayEnumerationIndex
    /// </summary>
    public const ushort SamrGetDisplayEnumerationIndex = 41;

    /// <summary>
    /// MS-SAMR: Opnum42NotUsedOnWire
    /// </summary>
    public const ushort SAMR_Opnum42NotUsedOnWire = 42;

    /// <summary>
    /// MS-SAMR: Opnum43NotUsedOnWire
    /// </summary>
    public const ushort SAMR_Opnum43NotUsedOnWire = 43;

    /// <summary>
    /// MS-SAMR: SamrGetUserDomainPasswordInformation
    /// </summary>
    public const ushort SamrGetUserDomainPasswordInformation = 44;

    /// <summary>
    /// MS-SAMR: SamrRemoveMemberFromForeignDomain
    /// </summary>
    public const ushort SamrRemoveMemberFromForeignDomain = 45;

    /// <summary>
    /// MS-SAMR: SamrQueryInformationDomain2
    /// </summary>
    public const ushort SamrQueryInformationDomain2 = 46;

    /// <summary>
    /// MS-SAMR: SamrQueryInformationUser2
    /// </summary>
    public const ushort SamrQueryInformationUser2 = 47;

    /// <summary>
    /// MS-SAMR: SamrQueryDisplayInformation2
    /// </summary>
    public const ushort SamrQueryDisplayInformation2 = 48;

    /// <summary>
    /// MS-SAMR: SamrGetDisplayEnumerationIndex2
    /// </summary>
    public const ushort SamrGetDisplayEnumerationIndex2 = 49;

    /// <summary>
    /// MS-SAMR: SamrCreateUser2InDomain
    /// </summary>
    public const ushort SamrCreateUser2InDomain = 50;

    /// <summary>
    /// MS-SAMR: SamrQueryDisplayInformation3
    /// </summary>
    public const ushort SamrQueryDisplayInformation3 = 51;

    /// <summary>
    /// MS-SAMR: SamrAddMultipleMembersToAlias
    /// </summary>
    public const ushort SamrAddMultipleMembersToAlias = 52;

    /// <summary>
    /// MS-SAMR: SamrRemoveMultipleMembersFromAlias
    /// </summary>
    public const ushort SamrRemoveMultipleMembersFromAlias = 53;

    /// <summary>
    /// MS-SAMR: SamrOemChangePasswordUser2
    /// </summary>
    public const ushort SamrOemChangePasswordUser2 = 54;

    /// <summary>
    /// MS-SAMR: SamrUnicodeChangePasswordUser2
    /// </summary>
    public const ushort SamrUnicodeChangePasswordUser2 = 55;

    /// <summary>
    /// MS-SAMR: SamrGetDomainPasswordInformation
    /// </summary>
    public const ushort SamrGetDomainPasswordInformation = 56;

    /// <summary>
    /// MS-SAMR: SamrConnect2
    /// </summary>
    public const ushort SamrConnect2 = 57;

    /// <summary>
    /// MS-SAMR: SamrSetInformationUser2
    /// </summary>
    public const ushort SamrSetInformationUser2 = 58;

    /// <summary>
    /// MS-SAMR: Opnum59NotUsedOnWire
    /// </summary>
    public const ushort SAMR_Opnum59NotUsedOnWire = 59;

    /// <summary>
    /// MS-SAMR: Opnum60NotUsedOnWire
    /// </summary>
    public const ushort SAMR_Opnum60NotUsedOnWire = 60;

    /// <summary>
    /// MS-SAMR: Opnum61NotUsedOnWire
    /// </summary>
    public const ushort SAMR_Opnum61NotUsedOnWire = 61;

    /// <summary>
    /// MS-SAMR: SamrConnect4
    /// </summary>
    public const ushort SamrConnect4 = 62;

    /// <summary>
    /// MS-SAMR: Opnum63NotUsedOnWire
    /// </summary>
    public const ushort SAMR_Opnum63NotUsedOnWire = 63;

    /// <summary>
    /// MS-SAMR: SamrConnect5
    /// </summary>
    public const ushort SamrConnect5 = 64;

    /// <summary>
    /// MS-SAMR: SamrRidToSid
    /// </summary>
    public const ushort SamrRidToSid = 65;

    /// <summary>
    /// MS-SAMR: SamrSetDSRMPassword
    /// </summary>
    public const ushort SamrSetDSRMPassword = 66;

    /// <summary>
    /// MS-SAMR: SamrValidatePassword
    /// </summary>
    public const ushort SamrValidatePassword = 67;

    /// <summary>
    /// MS-SAMR: Opnum68NotUsedOnWire
    /// </summary>
    public const ushort SAMR_Opnum68NotUsedOnWire = 68;

    /// <summary>
    /// MS-SAMR: Opnum69NotUsedOnWire
    /// </summary>
    public const ushort SAMR_Opnum69NotUsedOnWire = 69;

    /// <summary>
    /// MS-SAMR: Opnum70NotUsedOnWire
    /// </summary>
    public const ushort SAMR_Opnum70NotUsedOnWire = 70;

    /// <summary>
    /// MS-SAMR: Opnum71NotUsedOnWire
    /// </summary>
    public const ushort SAMR_Opnum71NotUsedOnWire = 71;

    /// <summary>
    /// MS-SAMR: Opnum72NotUsedOnWire
    /// </summary>
    public const ushort SAMR_Opnum72NotUsedOnWire = 72;

    /// <summary>
    /// MS-SAMR: SamrUnicodeChangePasswordUser4
    /// </summary>
    public const ushort SamrUnicodeChangePasswordUser4 = 73;

    /// <summary>
    /// MS-SAMR: SamrValidateComputerAccountReuseAttempt
    /// </summary>
    public const ushort SamrValidateComputerAccountReuseAttempt = 74;

    /// <summary>
    /// MS-SAMR: Opnum75NotUsedOnWire
    /// </summary>
    public const ushort SAMR_Opnum75NotUsedOnWire = 75;

    /// <summary>
    /// MS-SAMR: Opnum76NotUsedOnWire
    /// </summary>
    public const ushort SAMR_Opnum76NotUsedOnWire = 76;

    /// <summary>
    /// MS-SAMR: SamrAccountIsDelegatedManagedServiceAccount
    /// </summary>
    public const ushort SamrAccountIsDelegatedManagedServiceAccount = 77;

    #endregion // MS-SAMR
    #region MS-SCMR

    /// <summary>
    /// MS-SCMR: RCloseServiceHandle
    /// </summary>
    public const ushort RCloseServiceHandle = 0;

    /// <summary>
    /// MS-SCMR: RControlService
    /// </summary>
    public const ushort RControlService = 1;

    /// <summary>
    /// MS-SCMR: RDeleteService
    /// </summary>
    public const ushort RDeleteService = 2;

    /// <summary>
    /// MS-SCMR: RLockServiceDatabase
    /// </summary>
    public const ushort RLockServiceDatabase = 3;

    /// <summary>
    /// MS-SCMR: RQueryServiceObjectSecurity
    /// </summary>
    public const ushort RQueryServiceObjectSecurity = 4;

    /// <summary>
    /// MS-SCMR: RSetServiceObjectSecurity
    /// </summary>
    public const ushort RSetServiceObjectSecurity = 5;

    /// <summary>
    /// MS-SCMR: RQueryServiceStatus
    /// </summary>
    public const ushort RQueryServiceStatus = 6;

    /// <summary>
    /// MS-SCMR: RSetServiceStatus
    /// </summary>
    public const ushort RSetServiceStatus = 7;

    /// <summary>
    /// MS-SCMR: RUnlockServiceDatabase
    /// </summary>
    public const ushort RUnlockServiceDatabase = 8;

    /// <summary>
    /// MS-SCMR: RNotifyBootConfigStatus
    /// </summary>
    public const ushort RNotifyBootConfigStatus = 9;

    /// <summary>
    /// MS-SCMR: Opnum10NotUsedOnWire
    /// </summary>
    public const ushort SCMR_Opnum10NotUsedOnWire = 10;

    /// <summary>
    /// MS-SCMR: RChangeServiceConfigW
    /// </summary>
    public const ushort RChangeServiceConfigW = 11;

    /// <summary>
    /// MS-SCMR: RCreateServiceW
    /// </summary>
    public const ushort RCreateServiceW = 12;

    /// <summary>
    /// MS-SCMR: REnumDependentServicesW
    /// </summary>
    public const ushort REnumDependentServicesW = 13;

    /// <summary>
    /// MS-SCMR: REnumServicesStatusW
    /// </summary>
    public const ushort REnumServicesStatusW = 14;

    /// <summary>
    /// MS-SCMR: ROpenSCManagerW
    /// </summary>
    public const ushort ROpenSCManagerW = 15;

    /// <summary>
    /// MS-SCMR: ROpenServiceW
    /// </summary>
    public const ushort ROpenServiceW = 16;

    /// <summary>
    /// MS-SCMR: RQueryServiceConfigW
    /// </summary>
    public const ushort RQueryServiceConfigW = 17;

    /// <summary>
    /// MS-SCMR: RQueryServiceLockStatusW
    /// </summary>
    public const ushort RQueryServiceLockStatusW = 18;

    /// <summary>
    /// MS-SCMR: RStartServiceW
    /// </summary>
    public const ushort RStartServiceW = 19;

    /// <summary>
    /// MS-SCMR: RGetServiceDisplayNameW
    /// </summary>
    public const ushort RGetServiceDisplayNameW = 20;

    /// <summary>
    /// MS-SCMR: RGetServiceKeyNameW
    /// </summary>
    public const ushort RGetServiceKeyNameW = 21;

    /// <summary>
    /// MS-SCMR: Opnum22NotUsedOnWire
    /// </summary>
    public const ushort SCMR_Opnum22NotUsedOnWire = 22;

    /// <summary>
    /// MS-SCMR: RChangeServiceConfigA
    /// </summary>
    public const ushort RChangeServiceConfigA = 23;

    /// <summary>
    /// MS-SCMR: RCreateServiceA
    /// </summary>
    public const ushort RCreateServiceA = 24;

    /// <summary>
    /// MS-SCMR: REnumDependentServicesA
    /// </summary>
    public const ushort REnumDependentServicesA = 25;

    /// <summary>
    /// MS-SCMR: REnumServicesStatusA
    /// </summary>
    public const ushort REnumServicesStatusA = 26;

    /// <summary>
    /// MS-SCMR: ROpenSCManagerA
    /// </summary>
    public const ushort ROpenSCManagerA = 27;

    /// <summary>
    /// MS-SCMR: ROpenServiceA
    /// </summary>
    public const ushort ROpenServiceA = 28;

    /// <summary>
    /// MS-SCMR: RQueryServiceConfigA
    /// </summary>
    public const ushort RQueryServiceConfigA = 29;

    /// <summary>
    /// MS-SCMR: RQueryServiceLockStatusA
    /// </summary>
    public const ushort RQueryServiceLockStatusA = 30;

    /// <summary>
    /// MS-SCMR: RStartServiceA
    /// </summary>
    public const ushort RStartServiceA = 31;

    /// <summary>
    /// MS-SCMR: RGetServiceDisplayNameA
    /// </summary>
    public const ushort RGetServiceDisplayNameA = 32;

    /// <summary>
    /// MS-SCMR: RGetServiceKeyNameA
    /// </summary>
    public const ushort RGetServiceKeyNameA = 33;

    /// <summary>
    /// MS-SCMR: Opnum34NotUsedOnWire
    /// </summary>
    public const ushort SCMR_Opnum34NotUsedOnWire = 34;

    /// <summary>
    /// MS-SCMR: REnumServiceGroupW
    /// </summary>
    public const ushort REnumServiceGroupW = 35;

    /// <summary>
    /// MS-SCMR: RChangeServiceConfig2A
    /// </summary>
    public const ushort RChangeServiceConfig2A = 36;

    /// <summary>
    /// MS-SCMR: RChangeServiceConfig2W
    /// </summary>
    public const ushort RChangeServiceConfig2W = 37;

    /// <summary>
    /// MS-SCMR: RQueryServiceConfig2A
    /// </summary>
    public const ushort RQueryServiceConfig2A = 38;

    /// <summary>
    /// MS-SCMR: RQueryServiceConfig2W
    /// </summary>
    public const ushort RQueryServiceConfig2W = 39;

    /// <summary>
    /// MS-SCMR: RQueryServiceStatusEx
    /// </summary>
    public const ushort RQueryServiceStatusEx = 40;

    /// <summary>
    /// MS-SCMR: REnumServicesStatusExA
    /// </summary>
    public const ushort REnumServicesStatusExA = 41;

    /// <summary>
    /// MS-SCMR: REnumServicesStatusExW
    /// </summary>
    public const ushort REnumServicesStatusExW = 42;

    /// <summary>
    /// MS-SCMR: Opnum43NotUsedOnWire
    /// </summary>
    public const ushort SCMR_Opnum43NotUsedOnWire = 43;

    /// <summary>
    /// MS-SCMR: RCreateServiceWOW64A
    /// </summary>
    public const ushort RCreateServiceWOW64A = 44;

    /// <summary>
    /// MS-SCMR: RCreateServiceWOW64W
    /// </summary>
    public const ushort RCreateServiceWOW64W = 45;

    /// <summary>
    /// MS-SCMR: Opnum46NotUsedOnWire
    /// </summary>
    public const ushort SCMR_Opnum46NotUsedOnWire = 46;

    /// <summary>
    /// MS-SCMR: RNotifyServiceStatusChange
    /// </summary>
    public const ushort RNotifyServiceStatusChange = 47;

    /// <summary>
    /// MS-SCMR: RGetNotifyResults
    /// </summary>
    public const ushort RGetNotifyResults = 48;

    /// <summary>
    /// MS-SCMR: RCloseNotifyHandle
    /// </summary>
    public const ushort RCloseNotifyHandle = 49;

    /// <summary>
    /// MS-SCMR: RControlServiceExA
    /// </summary>
    public const ushort RControlServiceExA = 50;

    /// <summary>
    /// MS-SCMR: RControlServiceExW
    /// </summary>
    public const ushort RControlServiceExW = 51;

    /// <summary>
    /// MS-SCMR: Opnum52NotUsedOnWire
    /// </summary>
    public const ushort SCMR_Opnum52NotUsedOnWire = 52;

    /// <summary>
    /// MS-SCMR: Opnum53NotUsedOnWire
    /// </summary>
    public const ushort SCMR_Opnum53NotUsedOnWire = 53;

    /// <summary>
    /// MS-SCMR: Opnum54NotUsedOnWire
    /// </summary>
    public const ushort SCMR_Opnum54NotUsedOnWire = 54;

    /// <summary>
    /// MS-SCMR: Opnum55NotUsedOnWire
    /// </summary>
    public const ushort SCMR_Opnum55NotUsedOnWire = 55;

    /// <summary>
    /// MS-SCMR: RQueryServiceConfigEx
    /// </summary>
    public const ushort RQueryServiceConfigEx = 56;

    /// <summary>
    /// MS-SCMR: Opnum57NotUsedOnWire
    /// </summary>
    public const ushort SCMR_Opnum57NotUsedOnWire = 57;

    /// <summary>
    /// MS-SCMR: Opnum58NotUsedOnWire
    /// </summary>
    public const ushort SCMR_Opnum58NotUsedOnWire = 58;

    /// <summary>
    /// MS-SCMR: Opnum59NotUsedOnWire
    /// </summary>
    public const ushort SCMR_Opnum59NotUsedOnWire = 59;

    /// <summary>
    /// MS-SCMR: RCreateWowService
    /// </summary>
    public const ushort RCreateWowService = 60;

    /// <summary>
    /// MS-SCMR: Opnum61NotUsedOnWire
    /// </summary>
    public const ushort SCMR_Opnum61NotUsedOnWire = 61;

    /// <summary>
    /// MS-SCMR: Opnum62NotUsedOnWire
    /// </summary>
    public const ushort SCMR_Opnum62NotUsedOnWire = 62;

    /// <summary>
    /// MS-SCMR: Opnum63NotUsedOnWire
    /// </summary>
    public const ushort SCMR_Opnum63NotUsedOnWire = 63;

    /// <summary>
    /// MS-SCMR: ROpenSCManager2
    /// </summary>
    public const ushort ROpenSCManager2 = 64;

    #endregion // MS-SCMR
    #region MS-DFSNM

    /// <summary>
    /// MS-DFSNM: NetrDfsManagerGetVersion
    /// </summary>
    public const ushort NetrDfsManagerGetVersion = 0;

    /// <summary>
    /// MS-DFSNM: NetrDfsAdd
    /// </summary>
    public const ushort NetrDfsAdd = 1;

    /// <summary>
    /// MS-DFSNM: NetrDfsRemove
    /// </summary>
    public const ushort NetrDfsRemove = 2;

    /// <summary>
    /// MS-DFSNM: NetrDfsSetInfo
    /// </summary>
    public const ushort NetrDfsSetInfo = 3;

    /// <summary>
    /// MS-DFSNM: NetrDfsGetInfo
    /// </summary>
    public const ushort NetrDfsGetInfo = 4;

    /// <summary>
    /// MS-DFSNM: NetrDfsEnum
    /// </summary>
    public const ushort NetrDfsEnum = 5;

    /// <summary>
    /// MS-DFSNM: NetrDfsMove
    /// </summary>
    public const ushort NetrDfsMove = 6;

    /// <summary>
    /// MS-DFSNM: Opnum7NotUsedOnWire
    /// </summary>
    public const ushort DFSNM_Opnum7NotUsedOnWire = 7;

    /// <summary>
    /// MS-DFSNM: Opnum8NotUsedOnWire
    /// </summary>
    public const ushort DFSNM_Opnum8NotUsedOnWire = 8;

    /// <summary>
    /// MS-DFSNM: Opnum9NotUsedOnWire
    /// </summary>
    public const ushort DFSNM_Opnum9NotUsedOnWire = 9;

    /// <summary>
    /// MS-DFSNM: NetrDfsAddFtRoot
    /// </summary>
    public const ushort NetrDfsAddFtRoot = 10;

    /// <summary>
    /// MS-DFSNM: NetrDfsRemoveFtRoot
    /// </summary>
    public const ushort NetrDfsRemoveFtRoot = 11;

    /// <summary>
    /// MS-DFSNM: NetrDfsAddStdRoot
    /// </summary>
    public const ushort NetrDfsAddStdRoot = 12;

    /// <summary>
    /// MS-DFSNM: NetrDfsRemoveStdRoot
    /// </summary>
    public const ushort NetrDfsRemoveStdRoot = 13;

    /// <summary>
    /// MS-DFSNM: NetrDfsManagerInitialize
    /// </summary>
    public const ushort NetrDfsManagerInitialize = 14;

    /// <summary>
    /// MS-DFSNM: NetrDfsAddStdRootForced
    /// </summary>
    public const ushort NetrDfsAddStdRootForced = 15;

    /// <summary>
    /// MS-DFSNM: NetrDfsGetDcAddress
    /// </summary>
    public const ushort NetrDfsGetDcAddress = 16;

    /// <summary>
    /// MS-DFSNM: NetrDfsSetDcAddress
    /// </summary>
    public const ushort NetrDfsSetDcAddress = 17;

    /// <summary>
    /// MS-DFSNM: NetrDfsFlushFtTable
    /// </summary>
    public const ushort NetrDfsFlushFtTable = 18;

    /// <summary>
    /// MS-DFSNM: NetrDfsAdd2
    /// </summary>
    public const ushort NetrDfsAdd2 = 19;

    /// <summary>
    /// MS-DFSNM: NetrDfsRemove2
    /// </summary>
    public const ushort NetrDfsRemove2 = 20;

    /// <summary>
    /// MS-DFSNM: NetrDfsEnumEx
    /// </summary>
    public const ushort NetrDfsEnumEx = 21;

    /// <summary>
    /// MS-DFSNM: NetrDfsSetInfo2
    /// </summary>
    public const ushort NetrDfsSetInfo2 = 22;

    /// <summary>
    /// MS-DFSNM: NetrDfsAddRootTarget
    /// </summary>
    public const ushort NetrDfsAddRootTarget = 23;

    /// <summary>
    /// MS-DFSNM: NetrDfsRemoveRootTarget
    /// </summary>
    public const ushort NetrDfsRemoveRootTarget = 24;

    /// <summary>
    /// MS-DFSNM: NetrDfsGetSupportedNamespaceVersion
    /// </summary>
    public const ushort NetrDfsGetSupportedNamespaceVersion = 25;

    #endregion // MS-DFSNM
    #region MS-RRP

    /// <summary>
    /// MS-RRP: OpenClassesRoot
    /// </summary>
    public const ushort OpenClassesRoot = 0;

    /// <summary>
    /// MS-RRP: OpenCurrentUser
    /// </summary>
    public const ushort OpenCurrentUser = 1;

    /// <summary>
    /// MS-RRP: OpenLocalMachine
    /// </summary>
    public const ushort OpenLocalMachine = 2;

    /// <summary>
    /// MS-RRP: OpenPerformanceData
    /// </summary>
    public const ushort OpenPerformanceData = 3;

    /// <summary>
    /// MS-RRP: OpenUsers
    /// </summary>
    public const ushort OpenUsers = 4;

    /// <summary>
    /// MS-RRP: BaseRegCloseKey
    /// </summary>
    public const ushort BaseRegCloseKey = 5;

    /// <summary>
    /// MS-RRP: BaseRegCreateKey
    /// </summary>
    public const ushort BaseRegCreateKey = 6;

    /// <summary>
    /// MS-RRP: BaseRegDeleteKey
    /// </summary>
    public const ushort BaseRegDeleteKey = 7;

    /// <summary>
    /// MS-RRP: BaseRegDeleteValue
    /// </summary>
    public const ushort BaseRegDeleteValue = 8;

    /// <summary>
    /// MS-RRP: BaseRegEnumKey
    /// </summary>
    public const ushort BaseRegEnumKey = 9;

    /// <summary>
    /// MS-RRP: BaseRegEnumValue
    /// </summary>
    public const ushort BaseRegEnumValue = 10;

    /// <summary>
    /// MS-RRP: BaseRegFlushKey
    /// </summary>
    public const ushort BaseRegFlushKey = 11;

    /// <summary>
    /// MS-RRP: BaseRegGetKeySecurity
    /// </summary>
    public const ushort BaseRegGetKeySecurity = 12;

    /// <summary>
    /// MS-RRP: BaseRegLoadKey
    /// </summary>
    public const ushort BaseRegLoadKey = 13;

    /// <summary>
    /// MS-RRP: Opnum14NotImplemented
    /// </summary>
    public const ushort RRP_Opnum14NotImplemented = 14;

    /// <summary>
    /// MS-RRP: BaseRegOpenKey
    /// </summary>
    public const ushort BaseRegOpenKey = 15;

    /// <summary>
    /// MS-RRP: BaseRegQueryInfoKey
    /// </summary>
    public const ushort BaseRegQueryInfoKey = 16;

    /// <summary>
    /// MS-RRP: BaseRegQueryValue
    /// </summary>
    public const ushort BaseRegQueryValue = 17;

    /// <summary>
    /// MS-RRP: BaseRegReplaceKey
    /// </summary>
    public const ushort BaseRegReplaceKey = 18;

    /// <summary>
    /// MS-RRP: BaseRegRestoreKey
    /// </summary>
    public const ushort BaseRegRestoreKey = 19;

    /// <summary>
    /// MS-RRP: BaseRegSaveKey
    /// </summary>
    public const ushort BaseRegSaveKey = 20;

    /// <summary>
    /// MS-RRP: BaseRegSetKeySecurity
    /// </summary>
    public const ushort BaseRegSetKeySecurity = 21;

    /// <summary>
    /// MS-RRP: BaseRegSetValue
    /// </summary>
    public const ushort BaseRegSetValue = 22;

    /// <summary>
    /// MS-RRP: BaseRegUnLoadKey
    /// </summary>
    public const ushort BaseRegUnLoadKey = 23;

    /// <summary>
    /// MS-RRP: Opnum24NotImplemented
    /// </summary>
    public const ushort RRP_Opnum24NotImplemented = 24;

    /// <summary>
    /// MS-RRP: Opnum25NotImplemented
    /// </summary>
    public const ushort RRP_Opnum25NotImplemented = 25;

    /// <summary>
    /// MS-RRP: BaseRegGetVersion
    /// </summary>
    public const ushort BaseRegGetVersion = 26;

    /// <summary>
    /// MS-RRP: OpenCurrentConfig
    /// </summary>
    public const ushort OpenCurrentConfig = 27;

    /// <summary>
    /// MS-RRP: Opnum28NotImplemented
    /// </summary>
    public const ushort RRP_Opnum28NotImplemented = 28;

    /// <summary>
    /// MS-RRP: BaseRegQueryMultipleValues
    /// </summary>
    public const ushort BaseRegQueryMultipleValues = 29;

    /// <summary>
    /// MS-RRP: Opnum30NotImplemented
    /// </summary>
    public const ushort RRP_Opnum30NotImplemented = 30;

    /// <summary>
    /// MS-RRP: BaseRegSaveKeyEx
    /// </summary>
    public const ushort BaseRegSaveKeyEx = 31;

    /// <summary>
    /// MS-RRP: OpenPerformanceText
    /// </summary>
    public const ushort OpenPerformanceText = 32;

    /// <summary>
    /// MS-RRP: OpenPerformanceNlsText
    /// </summary>
    public const ushort OpenPerformanceNlsText = 33;

    /// <summary>
    /// MS-RRP: BaseRegQueryMultipleValues2
    /// </summary>
    public const ushort BaseRegQueryMultipleValues2 = 34;

    /// <summary>
    /// MS-RRP: BaseRegDeleteKeyEx
    /// </summary>
    public const ushort BaseRegDeleteKeyEx = 35;

    #endregion // MS-RRP
    #region MS-DRSR

    /// <summary>
    /// MS-DRSR: IDL_DRSBind
    /// </summary>
    public const ushort IDL_DRSBind = 0;

    /// <summary>
    /// MS-DRSR: IDL_DRSUnbind
    /// </summary>
    public const ushort IDL_DRSUnbind = 1;

    /// <summary>
    /// MS-DRSR: IDL_DRSReplicaSync
    /// </summary>
    public const ushort IDL_DRSReplicaSync = 2;

    /// <summary>
    /// MS-DRSR: IDL_DRSGetNCChanges
    /// </summary>
    public const ushort IDL_DRSGetNCChanges = 3;

    /// <summary>
    /// MS-DRSR: IDL_DRSUpdateRefs
    /// </summary>
    public const ushort IDL_DRSUpdateRefs = 4;

    /// <summary>
    /// MS-DRSR: IDL_DRSReplicaAdd
    /// </summary>
    public const ushort IDL_DRSReplicaAdd = 5;

    /// <summary>
    /// MS-DRSR: IDL_DRSReplicaDel
    /// </summary>
    public const ushort IDL_DRSReplicaDel = 6;

    /// <summary>
    /// MS-DRSR: IDL_DRSReplicaModify
    /// </summary>
    public const ushort IDL_DRSReplicaModify = 7;

    /// <summary>
    /// MS-DRSR: IDL_DRSVerifyNames
    /// </summary>
    public const ushort IDL_DRSVerifyNames = 8;

    /// <summary>
    /// MS-DRSR: IDL_DRSGetMemberships
    /// </summary>
    public const ushort IDL_DRSGetMemberships = 9;

    /// <summary>
    /// MS-DRSR: IDL_DRSInterDomainMove
    /// </summary>
    public const ushort IDL_DRSInterDomainMove = 10;

    /// <summary>
    /// MS-DRSR: IDL_DRSGetNT4ChangeLog
    /// </summary>
    public const ushort IDL_DRSGetNT4ChangeLog = 11;

    /// <summary>
    /// MS-DRSR: IDL_DRSCrackNames
    /// </summary>
    public const ushort IDL_DRSCrackNames = 12;

    /// <summary>
    /// MS-DRSR: IDL_DRSWriteSPN
    /// </summary>
    public const ushort IDL_DRSWriteSPN = 13;

    /// <summary>
    /// MS-DRSR: IDL_DRSRemoveDsServer
    /// </summary>
    public const ushort IDL_DRSRemoveDsServer = 14;

    /// <summary>
    /// MS-DRSR: IDL_DRSRemoveDsDomain
    /// </summary>
    public const ushort IDL_DRSRemoveDsDomain = 15;

    /// <summary>
    /// MS-DRSR: IDL_DRSDomainControllerInfo
    /// </summary>
    public const ushort IDL_DRSDomainControllerInfo = 16;

    /// <summary>
    /// MS-DRSR: IDL_DRSAddEntry
    /// </summary>
    public const ushort IDL_DRSAddEntry = 17;

    /// <summary>
    /// MS-DRSR: IDL_DRSExecuteKCC
    /// </summary>
    public const ushort IDL_DRSExecuteKCC = 18;

    /// <summary>
    /// MS-DRSR: IDL_DRSGetReplInfo
    /// </summary>
    public const ushort IDL_DRSGetReplInfo = 19;

    /// <summary>
    /// MS-DRSR: IDL_DRSAddSidHistory
    /// </summary>
    public const ushort IDL_DRSAddSidHistory = 20;

    /// <summary>
    /// MS-DRSR: IDL_DRSGetMemberships2
    /// </summary>
    public const ushort IDL_DRSGetMemberships2 = 21;

    /// <summary>
    /// MS-DRSR: IDL_DRSReplicaVerifyObjects
    /// </summary>
    public const ushort IDL_DRSReplicaVerifyObjects = 22;

    /// <summary>
    /// MS-DRSR: IDL_DRSGetObjectExistence
    /// </summary>
    public const ushort IDL_DRSGetObjectExistence = 23;

    /// <summary>
    /// MS-DRSR: IDL_DRSQuerySitesByCost
    /// </summary>
    public const ushort IDL_DRSQuerySitesByCost = 24;

    /// <summary>
    /// MS-DRSR: IDL_DRSInitDemotion
    /// </summary>
    public const ushort IDL_DRSInitDemotion = 25;

    /// <summary>
    /// MS-DRSR: IDL_DRSReplicaDemotion
    /// </summary>
    public const ushort IDL_DRSReplicaDemotion = 26;

    /// <summary>
    /// MS-DRSR: IDL_DRSFinishDemotion
    /// </summary>
    public const ushort IDL_DRSFinishDemotion = 27;

    /// <summary>
    /// MS-DRSR: IDL_DRSAddCloneDC
    /// </summary>
    public const ushort IDL_DRSAddCloneDC = 28;

    /// <summary>
    /// MS-DRSR: IDL_DRSWriteNgcKey
    /// </summary>
    public const ushort IDL_DRSWriteNgcKey = 29;

    /// <summary>
    /// MS-DRSR: IDL_DRSReadNgcKey
    /// </summary>
    public const ushort IDL_DRSReadNgcKey = 30;

    /// <summary>
    /// MS-DRSR: IDL_DSAPrepareScript
    /// </summary>
    public const ushort IDL_DSAPrepareScript = 0;

    /// <summary>
    /// MS-DRSR: IDL_DSAExecuteScript
    /// </summary>
    public const ushort IDL_DSAExecuteScript = 1;

    #endregion // MS-DRSR
    #region MS-LSAD

    /// <summary>
    /// MS-LSAD: LsarClose
    /// </summary>
    public const ushort LsarClose = 0;

    /// <summary>
    /// MS-LSAD: Opnum1NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum1NotUsedOnWire = 1;

    /// <summary>
    /// MS-LSAD: LsarEnumeratePrivileges
    /// </summary>
    public const ushort LsarEnumeratePrivileges = 2;

    /// <summary>
    /// MS-LSAD: LsarQuerySecurityObject
    /// </summary>
    public const ushort LsarQuerySecurityObject = 3;

    /// <summary>
    /// MS-LSAD: LsarSetSecurityObject
    /// </summary>
    public const ushort LsarSetSecurityObject = 4;

    /// <summary>
    /// MS-LSAD: Opnum5NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum5NotUsedOnWire = 5;

    /// <summary>
    /// MS-LSAD: LsarOpenPolicy
    /// </summary>
    public const ushort LsarOpenPolicy = 6;

    /// <summary>
    /// MS-LSAD: LsarQueryInformationPolicy
    /// </summary>
    public const ushort LsarQueryInformationPolicy = 7;

    /// <summary>
    /// MS-LSAD: LsarSetInformationPolicy
    /// </summary>
    public const ushort LsarSetInformationPolicy = 8;

    /// <summary>
    /// MS-LSAD: Opnum9NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum9NotUsedOnWire = 9;

    /// <summary>
    /// MS-LSAD: LsarCreateAccount
    /// </summary>
    public const ushort LsarCreateAccount = 10;

    /// <summary>
    /// MS-LSAD: LsarEnumerateAccounts
    /// </summary>
    public const ushort LsarEnumerateAccounts = 11;

    /// <summary>
    /// MS-LSAD: LsarCreateTrustedDomain
    /// </summary>
    public const ushort LsarCreateTrustedDomain = 12;

    /// <summary>
    /// MS-LSAD: LsarEnumerateTrustedDomains
    /// </summary>
    public const ushort LsarEnumerateTrustedDomains = 13;

    /// <summary>
    /// MS-LSAD: Lsar_LSA_TM_14
    /// </summary>
    public const ushort Lsar_LSA_TM_14 = 14;

    /// <summary>
    /// MS-LSAD: Lsar_LSA_TM_15
    /// </summary>
    public const ushort Lsar_LSA_TM_15 = 15;

    /// <summary>
    /// MS-LSAD: LsarCreateSecret
    /// </summary>
    public const ushort LsarCreateSecret = 16;

    /// <summary>
    /// MS-LSAD: LsarOpenAccount
    /// </summary>
    public const ushort LsarOpenAccount = 17;

    /// <summary>
    /// MS-LSAD: LsarEnumeratePrivilegesAccount
    /// </summary>
    public const ushort LsarEnumeratePrivilegesAccount = 18;

    /// <summary>
    /// MS-LSAD: LsarAddPrivilegesToAccount
    /// </summary>
    public const ushort LsarAddPrivilegesToAccount = 19;

    /// <summary>
    /// MS-LSAD: LsarRemovePrivilegesFromAccount
    /// </summary>
    public const ushort LsarRemovePrivilegesFromAccount = 20;

    /// <summary>
    /// MS-LSAD: Opnum21NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum21NotUsedOnWire = 21;

    /// <summary>
    /// MS-LSAD: Opnum22NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum22NotUsedOnWire = 22;

    /// <summary>
    /// MS-LSAD: LsarGetSystemAccessAccount
    /// </summary>
    public const ushort LsarGetSystemAccessAccount = 23;

    /// <summary>
    /// MS-LSAD: LsarSetSystemAccessAccount
    /// </summary>
    public const ushort LsarSetSystemAccessAccount = 24;

    /// <summary>
    /// MS-LSAD: LsarOpenTrustedDomain
    /// </summary>
    public const ushort LsarOpenTrustedDomain = 25;

    /// <summary>
    /// MS-LSAD: LsarQueryInfoTrustedDomain
    /// </summary>
    public const ushort LsarQueryInfoTrustedDomain = 26;

    /// <summary>
    /// MS-LSAD: LsarSetInformationTrustedDomain
    /// </summary>
    public const ushort LsarSetInformationTrustedDomain = 27;

    /// <summary>
    /// MS-LSAD: LsarOpenSecret
    /// </summary>
    public const ushort LsarOpenSecret = 28;

    /// <summary>
    /// MS-LSAD: LsarSetSecret
    /// </summary>
    public const ushort LsarSetSecret = 29;

    /// <summary>
    /// MS-LSAD: LsarQuerySecret
    /// </summary>
    public const ushort LsarQuerySecret = 30;

    /// <summary>
    /// MS-LSAD: LsarLookupPrivilegeValue
    /// </summary>
    public const ushort LsarLookupPrivilegeValue = 31;

    /// <summary>
    /// MS-LSAD: LsarLookupPrivilegeName
    /// </summary>
    public const ushort LsarLookupPrivilegeName = 32;

    /// <summary>
    /// MS-LSAD: LsarLookupPrivilegeDisplayName
    /// </summary>
    public const ushort LsarLookupPrivilegeDisplayName = 33;

    /// <summary>
    /// MS-LSAD: LsarDeleteObject
    /// </summary>
    public const ushort LsarDeleteObject = 34;

    /// <summary>
    /// MS-LSAD: LsarEnumerateAccountsWithUserRight
    /// </summary>
    public const ushort LsarEnumerateAccountsWithUserRight = 35;

    /// <summary>
    /// MS-LSAD: LsarEnumerateAccountRights
    /// </summary>
    public const ushort LsarEnumerateAccountRights = 36;

    /// <summary>
    /// MS-LSAD: LsarAddAccountRights
    /// </summary>
    public const ushort LsarAddAccountRights = 37;

    /// <summary>
    /// MS-LSAD: LsarRemoveAccountRights
    /// </summary>
    public const ushort LsarRemoveAccountRights = 38;

    /// <summary>
    /// MS-LSAD: LsarQueryTrustedDomainInfo
    /// </summary>
    public const ushort LsarQueryTrustedDomainInfo = 39;

    /// <summary>
    /// MS-LSAD: LsarSetTrustedDomainInfo
    /// </summary>
    public const ushort LsarSetTrustedDomainInfo = 40;

    /// <summary>
    /// MS-LSAD: LsarDeleteTrustedDomain
    /// </summary>
    public const ushort LsarDeleteTrustedDomain = 41;

    /// <summary>
    /// MS-LSAD: LsarStorePrivateData
    /// </summary>
    public const ushort LsarStorePrivateData = 42;

    /// <summary>
    /// MS-LSAD: LsarRetrievePrivateData
    /// </summary>
    public const ushort LsarRetrievePrivateData = 43;

    /// <summary>
    /// MS-LSAD: LsarOpenPolicy2
    /// </summary>
    public const ushort LsarOpenPolicy2 = 44;

    /// <summary>
    /// MS-LSAD: Lsar_LSA_TM_45
    /// </summary>
    public const ushort Lsar_LSA_TM_45 = 45;

    /// <summary>
    /// MS-LSAD: LsarQueryInformationPolicy2
    /// </summary>
    public const ushort LsarQueryInformationPolicy2 = 46;

    /// <summary>
    /// MS-LSAD: LsarSetInformationPolicy2
    /// </summary>
    public const ushort LsarSetInformationPolicy2 = 47;

    /// <summary>
    /// MS-LSAD: LsarQueryTrustedDomainInfoByName
    /// </summary>
    public const ushort LsarQueryTrustedDomainInfoByName = 48;

    /// <summary>
    /// MS-LSAD: LsarSetTrustedDomainInfoByName
    /// </summary>
    public const ushort LsarSetTrustedDomainInfoByName = 49;

    /// <summary>
    /// MS-LSAD: LsarEnumerateTrustedDomainsEx
    /// </summary>
    public const ushort LsarEnumerateTrustedDomainsEx = 50;

    /// <summary>
    /// MS-LSAD: LsarCreateTrustedDomainEx
    /// </summary>
    public const ushort LsarCreateTrustedDomainEx = 51;

    /// <summary>
    /// MS-LSAD: Opnum52NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum52NotUsedOnWire = 52;

    /// <summary>
    /// MS-LSAD: LsarQueryDomainInformationPolicy
    /// </summary>
    public const ushort LsarQueryDomainInformationPolicy = 53;

    /// <summary>
    /// MS-LSAD: LsarSetDomainInformationPolicy
    /// </summary>
    public const ushort LsarSetDomainInformationPolicy = 54;

    /// <summary>
    /// MS-LSAD: LsarOpenTrustedDomainByName
    /// </summary>
    public const ushort LsarOpenTrustedDomainByName = 55;

    /// <summary>
    /// MS-LSAD: Opnum56NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum56NotUsedOnWire = 56;

    /// <summary>
    /// MS-LSAD: Lsar_LSA_TM_57
    /// </summary>
    public const ushort Lsar_LSA_TM_57 = 57;

    /// <summary>
    /// MS-LSAD: Lsar_LSA_TM_58
    /// </summary>
    public const ushort Lsar_LSA_TM_58 = 58;

    /// <summary>
    /// MS-LSAD: LsarCreateTrustedDomainEx2
    /// </summary>
    public const ushort LsarCreateTrustedDomainEx2 = 59;

    /// <summary>
    /// MS-LSAD: Opnum60NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum60NotUsedOnWire = 60;

    /// <summary>
    /// MS-LSAD: Opnum61NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum61NotUsedOnWire = 61;

    /// <summary>
    /// MS-LSAD: Opnum62NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum62NotUsedOnWire = 62;

    /// <summary>
    /// MS-LSAD: Opnum63NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum63NotUsedOnWire = 63;

    /// <summary>
    /// MS-LSAD: Opnum64NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum64NotUsedOnWire = 64;

    /// <summary>
    /// MS-LSAD: Opnum65NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum65NotUsedOnWire = 65;

    /// <summary>
    /// MS-LSAD: Opnum66NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum66NotUsedOnWire = 66;

    /// <summary>
    /// MS-LSAD: Opnum67NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum67NotUsedOnWire = 67;

    /// <summary>
    /// MS-LSAD: Lsar_LSA_TM_68
    /// </summary>
    public const ushort Lsar_LSA_TM_68 = 68;

    /// <summary>
    /// MS-LSAD: Opnum69NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum69NotUsedOnWire = 69;

    /// <summary>
    /// MS-LSAD: Opnum70NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum70NotUsedOnWire = 70;

    /// <summary>
    /// MS-LSAD: Opnum71NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum71NotUsedOnWire = 71;

    /// <summary>
    /// MS-LSAD: Opnum72NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum72NotUsedOnWire = 72;

    /// <summary>
    /// MS-LSAD: LsarQueryForestTrustInformation
    /// </summary>
    public const ushort LsarQueryForestTrustInformation = 73;

    /// <summary>
    /// MS-LSAD: LsarSetForestTrustInformation
    /// </summary>
    public const ushort LsarSetForestTrustInformation = 74;

    /// <summary>
    /// MS-LSAD: Opnum75NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum75NotUsedOnWire = 75;

    /// <summary>
    /// MS-LSAD: LsarLookupSids3
    /// </summary>
    public const ushort LsarLookupSids3 = 76;

    /// <summary>
    /// MS-LSAD: LsarLookupNames4
    /// </summary>
    public const ushort LsarLookupNames4 = 77;

    /// <summary>
    /// MS-LSAD: Opnum78NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum78NotUsedOnWire = 78;

    /// <summary>
    /// MS-LSAD: Opnum79NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum79NotUsedOnWire = 79;

    /// <summary>
    /// MS-LSAD: Opnum80NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum80NotUsedOnWire = 80;

    /// <summary>
    /// MS-LSAD: Opnum81NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum81NotUsedOnWire = 81;

    /// <summary>
    /// MS-LSAD: Opnum82NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum82NotUsedOnWire = 82;

    /// <summary>
    /// MS-LSAD: Opnum83NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum83NotUsedOnWire = 83;

    /// <summary>
    /// MS-LSAD: Opnum84NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum84NotUsedOnWire = 84;

    /// <summary>
    /// MS-LSAD: Opnum85NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum85NotUsedOnWire = 85;

    /// <summary>
    /// MS-LSAD: Opnum86NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum86NotUsedOnWire = 86;

    /// <summary>
    /// MS-LSAD: Opnum87NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum87NotUsedOnWire = 87;

    /// <summary>
    /// MS-LSAD: Opnum88NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum88NotUsedOnWire = 88;

    /// <summary>
    /// MS-LSAD: Opnum89NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum89NotUsedOnWire = 89;

    /// <summary>
    /// MS-LSAD: Opnum90NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum90NotUsedOnWire = 90;

    /// <summary>
    /// MS-LSAD: Opnum91NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum91NotUsedOnWire = 91;

    /// <summary>
    /// MS-LSAD: Opnum92NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum92NotUsedOnWire = 92;

    /// <summary>
    /// MS-LSAD: Opnum93NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum93NotUsedOnWire = 93;

    /// <summary>
    /// MS-LSAD: Opnum94NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum94NotUsedOnWire = 94;

    /// <summary>
    /// MS-LSAD: Opnum95NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum95NotUsedOnWire = 95;

    /// <summary>
    /// MS-LSAD: Opnum96NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum96NotUsedOnWire = 96;

    /// <summary>
    /// MS-LSAD: Opnum97NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum97NotUsedOnWire = 97;

    /// <summary>
    /// MS-LSAD: Opnum98NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum98NotUsedOnWire = 98;

    /// <summary>
    /// MS-LSAD: Opnum99NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum99NotUsedOnWire = 99;

    /// <summary>
    /// MS-LSAD: Opnum100NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum100NotUsedOnWire = 100;

    /// <summary>
    /// MS-LSAD: Opnum101NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum101NotUsedOnWire = 101;

    /// <summary>
    /// MS-LSAD: Opnum102NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum102NotUsedOnWire = 102;

    /// <summary>
    /// MS-LSAD: Opnum103NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum103NotUsedOnWire = 103;

    /// <summary>
    /// MS-LSAD: Opnum104NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum104NotUsedOnWire = 104;

    /// <summary>
    /// MS-LSAD: Opnum105NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum105NotUsedOnWire = 105;

    /// <summary>
    /// MS-LSAD: Opnum106NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum106NotUsedOnWire = 106;

    /// <summary>
    /// MS-LSAD: Opnum107NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum107NotUsedOnWire = 107;

    /// <summary>
    /// MS-LSAD: Opnum108NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum108NotUsedOnWire = 108;

    /// <summary>
    /// MS-LSAD: Opnum109NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum109NotUsedOnWire = 109;

    /// <summary>
    /// MS-LSAD: Opnum110NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum110NotUsedOnWire = 110;

    /// <summary>
    /// MS-LSAD: Opnum111NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum111NotUsedOnWire = 111;

    /// <summary>
    /// MS-LSAD: Opnum112NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum112NotUsedOnWire = 112;

    /// <summary>
    /// MS-LSAD: Opnum113NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum113NotUsedOnWire = 113;

    /// <summary>
    /// MS-LSAD: Opnum114NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum114NotUsedOnWire = 114;

    /// <summary>
    /// MS-LSAD: Opnum115NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum115NotUsedOnWire = 115;

    /// <summary>
    /// MS-LSAD: Opnum116NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum116NotUsedOnWire = 116;

    /// <summary>
    /// MS-LSAD: Opnum117NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum117NotUsedOnWire = 117;

    /// <summary>
    /// MS-LSAD: Opnum118NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum118NotUsedOnWire = 118;

    /// <summary>
    /// MS-LSAD: Opnum119NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum119NotUsedOnWire = 119;

    /// <summary>
    /// MS-LSAD: Opnum120NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum120NotUsedOnWire = 120;

    /// <summary>
    /// MS-LSAD: Opnum121NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum121NotUsedOnWire = 121;

    /// <summary>
    /// MS-LSAD: Opnum122NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum122NotUsedOnWire = 122;

    /// <summary>
    /// MS-LSAD: Opnum123NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum123NotUsedOnWire = 123;

    /// <summary>
    /// MS-LSAD: Opnum124NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum124NotUsedOnWire = 124;

    /// <summary>
    /// MS-LSAD: Opnum125NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum125NotUsedOnWire = 125;

    /// <summary>
    /// MS-LSAD: Opnum126NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum126NotUsedOnWire = 126;

    /// <summary>
    /// MS-LSAD: Opnum127NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum127NotUsedOnWire = 127;

    /// <summary>
    /// MS-LSAD: Opnum128NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum128NotUsedOnWire = 128;

    /// <summary>
    /// MS-LSAD: LsarCreateTrustedDomainEx3
    /// </summary>
    public const ushort LsarCreateTrustedDomainEx3 = 129;

    /// <summary>
    /// MS-LSAD: LsarOpenPolicy3
    /// </summary>
    public const ushort LsarOpenPolicy3 = 130;

    /// <summary>
    /// MS-LSAD: Opnum131NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum131NotUsedOnWire = 131;

    /// <summary>
    /// MS-LSAD: LsarQueryForestTrustInformation2
    /// </summary>
    public const ushort LsarQueryForestTrustInformation2 = 132;

    /// <summary>
    /// MS-LSAD: LsarSetForestTrustInformation2
    /// </summary>
    public const ushort LsarSetForestTrustInformation2 = 133;

    /// <summary>
    /// MS-LSAD: Opnum134NotUsedOnWire
    /// </summary>
    public const ushort LSAD_Opnum134NotUsedOnWire = 134;

    /// <summary>
    /// MS-LSAD: LsarOpenPolicyWithCreds
    /// </summary>
    public const ushort LsarOpenPolicyWithCreds = 135;

    /// <summary>
    /// MS-LSAD: LsarOpenSecret2
    /// </summary>
    public const ushort LsarOpenSecret2 = 136;

    /// <summary>
    /// MS-LSAD: LsarCreateSecret2
    /// </summary>
    public const ushort LsarCreateSecret2 = 137;

    /// <summary>
    /// MS-LSAD: LsarSetSecret2
    /// </summary>
    public const ushort LsarSetSecret2 = 138;

    /// <summary>
    /// MS-LSAD: LsarQuerySecret2
    /// </summary>
    public const ushort LsarQuerySecret2 = 139;

    /// <summary>
    /// MS-LSAD: LsarStorePrivateData2
    /// </summary>
    public const ushort LsarStorePrivateData2 = 140;

    /// <summary>
    /// MS-LSAD: LsarRetrievePrivateData2
    /// </summary>
    public const ushort LsarRetrievePrivateData2 = 141;

    #endregion // MS-LSAD
    #region MS-NRPC

    /// <summary>
    /// MS-NRPC: NetrLogonUasLogon
    /// </summary>
    public const ushort NetrLogonUasLogon = 0;

    /// <summary>
    /// MS-NRPC: NetrLogonUasLogoff
    /// </summary>
    public const ushort NetrLogonUasLogoff = 1;

    /// <summary>
    /// MS-NRPC: NetrLogonSamLogon
    /// </summary>
    public const ushort NetrLogonSamLogon = 2;

    /// <summary>
    /// MS-NRPC: NetrLogonSamLogoff
    /// </summary>
    public const ushort NetrLogonSamLogoff = 3;

    /// <summary>
    /// MS-NRPC: NetrServerReqChallenge
    /// </summary>
    public const ushort NetrServerReqChallenge = 4;

    /// <summary>
    /// MS-NRPC: NetrServerAuthenticate
    /// </summary>
    public const ushort NetrServerAuthenticate = 5;

    /// <summary>
    /// MS-NRPC: NetrServerPasswordSet
    /// </summary>
    public const ushort NetrServerPasswordSet = 6;

    /// <summary>
    /// MS-NRPC: NetrDatabaseDeltas
    /// </summary>
    public const ushort NetrDatabaseDeltas = 7;

    /// <summary>
    /// MS-NRPC: NetrDatabaseSync
    /// </summary>
    public const ushort NetrDatabaseSync = 8;

    /// <summary>
    /// MS-NRPC: NetrAccountDeltas
    /// </summary>
    public const ushort NetrAccountDeltas = 9;

    /// <summary>
    /// MS-NRPC: NetrAccountSync
    /// </summary>
    public const ushort NetrAccountSync = 10;

    /// <summary>
    /// MS-NRPC: NetrGetDCName
    /// </summary>
    public const ushort NetrGetDCName = 11;

    /// <summary>
    /// MS-NRPC: NetrLogonControl
    /// </summary>
    public const ushort NetrLogonControl = 12;

    /// <summary>
    /// MS-NRPC: NetrGetAnyDCName
    /// </summary>
    public const ushort NetrGetAnyDCName = 13;

    /// <summary>
    /// MS-NRPC: NetrLogonControl2
    /// </summary>
    public const ushort NetrLogonControl2 = 14;

    /// <summary>
    /// MS-NRPC: NetrServerAuthenticate2
    /// </summary>
    public const ushort NetrServerAuthenticate2 = 15;

    /// <summary>
    /// MS-NRPC: NetrDatabaseSync2
    /// </summary>
    public const ushort NetrDatabaseSync2 = 16;

    /// <summary>
    /// MS-NRPC: NetrDatabaseRedo
    /// </summary>
    public const ushort NetrDatabaseRedo = 17;

    /// <summary>
    /// MS-NRPC: NetrLogonControl2Ex
    /// </summary>
    public const ushort NetrLogonControl2Ex = 18;

    /// <summary>
    /// MS-NRPC: NetrEnumerateTrustedDomains
    /// </summary>
    public const ushort NetrEnumerateTrustedDomains = 19;

    /// <summary>
    /// MS-NRPC: DsrGetDcName
    /// </summary>
    public const ushort DsrGetDcName = 20;

    /// <summary>
    /// MS-NRPC: NetrLogonGetCapabilities
    /// </summary>
    public const ushort NetrLogonGetCapabilities = 21;

    /// <summary>
    /// MS-NRPC: NetrLogonSetServiceBits
    /// </summary>
    public const ushort NetrLogonSetServiceBits = 22;

    /// <summary>
    /// MS-NRPC: NetrLogonGetTrustRid
    /// </summary>
    public const ushort NetrLogonGetTrustRid = 23;

    /// <summary>
    /// MS-NRPC: NetrLogonComputeServerDigest
    /// </summary>
    public const ushort NetrLogonComputeServerDigest = 24;

    /// <summary>
    /// MS-NRPC: NetrLogonComputeClientDigest
    /// </summary>
    public const ushort NetrLogonComputeClientDigest = 25;

    /// <summary>
    /// MS-NRPC: NetrServerAuthenticate3
    /// </summary>
    public const ushort NetrServerAuthenticate3 = 26;

    /// <summary>
    /// MS-NRPC: DsrGetDcNameEx
    /// </summary>
    public const ushort DsrGetDcNameEx = 27;

    /// <summary>
    /// MS-NRPC: DsrGetSiteName
    /// </summary>
    public const ushort DsrGetSiteName = 28;

    /// <summary>
    /// MS-NRPC: NetrLogonGetDomainInfo
    /// </summary>
    public const ushort NetrLogonGetDomainInfo = 29;

    /// <summary>
    /// MS-NRPC: NetrServerPasswordSet2
    /// </summary>
    public const ushort NetrServerPasswordSet2 = 30;

    /// <summary>
    /// MS-NRPC: NetrServerPasswordGet
    /// </summary>
    public const ushort NetrServerPasswordGet = 31;

    /// <summary>
    /// MS-NRPC: NetrLogonSendToSam
    /// </summary>
    public const ushort NetrLogonSendToSam = 32;

    /// <summary>
    /// MS-NRPC: DsrAddressToSiteNamesW
    /// </summary>
    public const ushort DsrAddressToSiteNamesW = 33;

    /// <summary>
    /// MS-NRPC: DsrGetDcNameEx2
    /// </summary>
    public const ushort DsrGetDcNameEx2 = 34;

    /// <summary>
    /// MS-NRPC: NetrLogonGetTimeServiceParentDomain
    /// </summary>
    public const ushort NetrLogonGetTimeServiceParentDomain = 35;

    /// <summary>
    /// MS-NRPC: NetrEnumerateTrustedDomainsEx
    /// </summary>
    public const ushort NetrEnumerateTrustedDomainsEx = 36;

    /// <summary>
    /// MS-NRPC: DsrAddressToSiteNamesExW
    /// </summary>
    public const ushort DsrAddressToSiteNamesExW = 37;

    /// <summary>
    /// MS-NRPC: DsrGetDcSiteCoverageW
    /// </summary>
    public const ushort DsrGetDcSiteCoverageW = 38;

    /// <summary>
    /// MS-NRPC: NetrLogonSamLogonEx
    /// </summary>
    public const ushort NetrLogonSamLogonEx = 39;

    /// <summary>
    /// MS-NRPC: DsrEnumerateDomainTrusts
    /// </summary>
    public const ushort DsrEnumerateDomainTrusts = 40;

    /// <summary>
    /// MS-NRPC: DsrDeregisterDnsHostRecords
    /// </summary>
    public const ushort DsrDeregisterDnsHostRecords = 41;

    /// <summary>
    /// MS-NRPC: NetrServerTrustPasswordsGet
    /// </summary>
    public const ushort NetrServerTrustPasswordsGet = 42;

    /// <summary>
    /// MS-NRPC: DsrGetForestTrustInformation
    /// </summary>
    public const ushort DsrGetForestTrustInformation = 43;

    /// <summary>
    /// MS-NRPC: NetrGetForestTrustInformation
    /// </summary>
    public const ushort NetrGetForestTrustInformation = 44;

    /// <summary>
    /// MS-NRPC: NetrLogonSamLogonWithFlags
    /// </summary>
    public const ushort NetrLogonSamLogonWithFlags = 45;

    /// <summary>
    /// MS-NRPC: NetrServerGetTrustInfo
    /// </summary>
    public const ushort NetrServerGetTrustInfo = 46;

    /// <summary>
    /// MS-NRPC: OpnumUnused47
    /// </summary>
    public const ushort NRPC_OpnumUnused47 = 47;

    /// <summary>
    /// MS-NRPC: DsrUpdateReadOnlyServerDnsRecords
    /// </summary>
    public const ushort DsrUpdateReadOnlyServerDnsRecords = 48;

    /// <summary>
    /// MS-NRPC: NetrChainSetClientAttributes
    /// </summary>
    public const ushort NetrChainSetClientAttributes = 49;

    /// <summary>
    /// MS-NRPC: NetrServerAuthenticateKerberos
    /// </summary>
    public const ushort NetrServerAuthenticateKerberos = 59;

    #endregion // MS-NRPC
}
