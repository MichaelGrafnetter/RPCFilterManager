#pragma warning disable CA1707 // Identifiers should not contain underscores
#pragma warning disable CA1711 // Identifiers should not have incorrect suffix

namespace DSInternals.Win32.RpcFilters;

/// <summary>
/// Well-known RPC protocol translator.
/// </summary>
public static partial class WellKnownProtocolTranslator
{
    #region MS-BKRP

    /// <summary>
    /// MS-BKRP: BackuprKey
    /// </summary>
    public const ushort BackuprKey = 0;

    #endregion // MS-BKRP
    #region MS-BPAU

    /// <summary>
    /// MS-BPAU: ExchangePublicKeys
    /// </summary>
    public const ushort ExchangePublicKeys = 0;

    #endregion // MS-BPAU
    #region MC-CCFG

    /// <summary>
    /// MC-CCFG: CleanupNode
    /// </summary>
    public const ushort CleanupNode = 0;

    #endregion // MC-CCFG
    #region MS-EFSR

    /// <summary>
    /// MS-EFSR: EfsRpcOpenFileRaw - Opens an encrypted object for backup or restore
    /// </summary>
    public const ushort EfsRpcOpenFileRaw = 0;

    /// <summary>
    /// MS-EFSR: EfsRpcReadFileRaw - Obtains marshaled data for an encrypted object
    /// </summary>
    public const ushort EfsRpcReadFileRaw = 1;

    /// <summary>
    /// MS-EFSR: EfsRpcWriteFileRaw - Creates an encrypted object from marshaled data
    /// </summary>
    public const ushort EfsRpcWriteFileRaw = 2;

    /// <summary>
    /// MS-EFSR: EfsRpcCloseRaw - Releases resources allocated by EfsRpcOpenFileRaw
    /// </summary>
    public const ushort EfsRpcCloseRaw = 3;

    /// <summary>
    /// MS-EFSR: EfsRpcEncryptFileSrv - Converts an object to encrypted state
    /// </summary>
    public const ushort EfsRpcEncryptFileSrv = 4;

    /// <summary>
    /// MS-EFSR: EfsRpcDecryptFileSrv - Converts an encrypted object to plaintext state
    /// </summary>
    public const ushort EfsRpcDecryptFileSrv = 5;

    /// <summary>
    /// MS-EFSR: EfsRpcQueryUsersOnFile - Queries metadata for X.509 certificates that can decrypt the object
    /// </summary>
    public const ushort EfsRpcQueryUsersOnFile = 6;

    /// <summary>
    /// MS-EFSR: EfsRpcQueryRecoveryAgents - Queries for data recovery agent X.509 certificates
    /// </summary>
    public const ushort EfsRpcQueryRecoveryAgents = 7;

    /// <summary>
    /// MS-EFSR: EfsRpcRemoveUsersFromFile - Revokes a user's access to an encrypted object
    /// </summary>
    public const ushort EfsRpcRemoveUsersFromFile = 8;

    /// <summary>
    /// MS-EFSR: EfsRpcAddUsersToFile - Grants users the ability to decrypt an object
    /// </summary>
    public const ushort EfsRpcAddUsersToFile = 9;

    /// <summary>
    /// MS-EFSR: Opnum10NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort EFSR_Opnum10NotUsedOnWire = 10;

    /// <summary>
    /// MS-EFSR: EfsRpcNotSupported - Deprecated (acts like EfsRpcDuplicateEncryptionInfoFile)
    /// </summary>
    public const ushort EfsRpcNotSupported = 11;

    /// <summary>
    /// MS-EFSR: EfsRpcFileKeyInfo - Queries and modifies information about encryption keys
    /// </summary>
    public const ushort EfsRpcFileKeyInfo = 12;

    /// <summary>
    /// MS-EFSR: EfsRpcDuplicateEncryptionInfoFile - Duplicates EFS metadata and attaches it to another object
    /// </summary>
    public const ushort EfsRpcDuplicateEncryptionInfoFile = 13;

    /// <summary>
    /// MS-EFSR: Opnum14NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort EFSR_Opnum14NotUsedOnWire = 14;

    /// <summary>
    /// MS-EFSR: EfsRpcAddUsersToFileEx - Grants users the ability to decrypt an object using an X.509 certificate
    /// </summary>
    public const ushort EfsRpcAddUsersToFileEx = 15;

    /// <summary>
    /// MS-EFSR: EfsRpcFileKeyInfoEx - Deprecated (acts like EfsRpcFileKeyInfo)
    /// </summary>
    public const ushort EfsRpcFileKeyInfoEx = 16;

    /// <summary>
    /// MS-EFSR: Opnum17NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort EFSR_Opnum17NotUsedOnWire = 17;

    /// <summary>
    /// MS-EFSR: EfsRpcGetEncryptedFileMetadata - Deprecated (retrieves EFS metadata)
    /// </summary>
    public const ushort EfsRpcGetEncryptedFileMetadata = 18;

    /// <summary>
    /// MS-EFSR: EfsRpcSetEncryptedFileMetadata - Deprecated (sets EFS metadata)
    /// </summary>
    public const ushort EfsRpcSetEncryptedFileMetadata = 19;

    /// <summary>
    /// MS-EFSR: EfsRpcFlushEfsCache - Flushes the logical cache holding sensitive EFS information
    /// </summary>
    public const ushort EfsRpcFlushEfsCache = 20;

    /// <summary>
    /// MS-EFSR: EfsRpcEncryptFileExSrv - Converts an object to encrypted state (supports DPAPI-NG and EFS Metadata Version 3)
    /// </summary>
    public const ushort EfsRpcEncryptFileExSrv = 21;

    /// <summary>
    /// MS-EFSR: EfsRpcQueryProtectors - Queries for DPAPI-NG protectors or RMS templates
    /// </summary>
    public const ushort EfsRpcQueryProtectors = 22;

    /// <summary>
    /// MS-EFSR: Opnum23NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort EFSR_Opnum23NotUsedOnWire = 23;

    /// <summary>
    /// MS-EFSR: Opnum24NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort EFSR_Opnum24NotUsedOnWire = 24;

    /// <summary>
    /// MS-EFSR: Opnum25NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort EFSR_Opnum25NotUsedOnWire = 25;

    /// <summary>
    /// MS-EFSR: Opnum26NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort EFSR_Opnum26NotUsedOnWire = 26;

    /// <summary>
    /// MS-EFSR: Opnum27NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort EFSR_Opnum27NotUsedOnWire = 27;

    /// <summary>
    /// MS-EFSR: Opnum28NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort EFSR_Opnum28NotUsedOnWire = 28;

    /// <summary>
    /// MS-EFSR: Opnum29NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort EFSR_Opnum29NotUsedOnWire = 29;

    /// <summary>
    /// MS-EFSR: Opnum30NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort EFSR_Opnum30NotUsedOnWire = 30;

    /// <summary>
    /// MS-EFSR: Opnum31NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort EFSR_Opnum31NotUsedOnWire = 31;

    /// <summary>
    /// MS-EFSR: Opnum32NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort EFSR_Opnum32NotUsedOnWire = 32;

    /// <summary>
    /// MS-EFSR: Opnum33NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort EFSR_Opnum33NotUsedOnWire = 33;

    /// <summary>
    /// MS-EFSR: Opnum34NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort EFSR_Opnum34NotUsedOnWire = 34;

    /// <summary>
    /// MS-EFSR: Opnum35NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort EFSR_Opnum35NotUsedOnWire = 35;

    /// <summary>
    /// MS-EFSR: Opnum36NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort EFSR_Opnum36NotUsedOnWire = 36;

    /// <summary>
    /// MS-EFSR: Opnum37NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort EFSR_Opnum37NotUsedOnWire = 37;

    /// <summary>
    /// MS-EFSR: Opnum38NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort EFSR_Opnum38NotUsedOnWire = 38;

    /// <summary>
    /// MS-EFSR: Opnum39NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort EFSR_Opnum39NotUsedOnWire = 39;

    /// <summary>
    /// MS-EFSR: Opnum40NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort EFSR_Opnum40NotUsedOnWire = 40;

    /// <summary>
    /// MS-EFSR: Opnum41NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort EFSR_Opnum41NotUsedOnWire = 41;

    /// <summary>
    /// MS-EFSR: Opnum42NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort EFSR_Opnum42NotUsedOnWire = 42;

    /// <summary>
    /// MS-EFSR: Opnum43NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort EFSR_Opnum43NotUsedOnWire = 43;

    /// <summary>
    /// MS-EFSR: Opnum44NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort EFSR_Opnum44NotUsedOnWire = 44;

    #endregion // MS-EFSR
    #region MS-EVEN

    /// <summary>
    /// MS-EVEN: ElfrClearELFW - Clears event logs
    /// </summary>
    public const ushort ElfrClearELFW = 0;

    /// <summary>
    /// MS-EVEN: ElfrBackupELFW - Creates a backup of a live event log
    /// </summary>
    public const ushort ElfrBackupELFW = 1;

    /// <summary>
    /// MS-EVEN: ElfrCloseEL - Closes context handles obtained by ElfrOpenELW/ElfrOpenELA/ElfrOpenBELW/ElfrOpenBELA
    /// </summary>
    public const ushort ElfrCloseEL = 2;

    /// <summary>
    /// MS-EVEN: ElfrDeregisterEventSource - Closes context handles obtained by ElfrRegisterEventSourceW/ElfrRegisterEventSourceA
    /// </summary>
    public const ushort ElfrDeregisterEventSource = 3;

    /// <summary>
    /// MS-EVEN: ElfrNumberOfRecords - Obtains the number of records in an event log
    /// </summary>
    public const ushort ElfrNumberOfRecords = 4;

    /// <summary>
    /// MS-EVEN: ElfrOldestRecord - Obtains the record number of the oldest record in an event log
    /// </summary>
    public const ushort ElfrOldestRecord = 5;

    /// <summary>
    /// MS-EVEN: ElfrChangeNotify - Reserved for local use (notifies local processes about changes to the event log)
    /// </summary>
    public const ushort EVEN_Opnum6NotUsedOnWire = 6;

    /// <summary>
    /// MS-EVEN: ElfrOpenELW - Opens a handle to a live event log for reading or clearing
    /// </summary>
    public const ushort ElfrOpenELW = 7;

    /// <summary>
    /// MS-EVEN: ElfrRegisterEventSourceW - Opens a handle to a live event log for writing
    /// </summary>
    public const ushort ElfrRegisterEventSourceW = 8;

    /// <summary>
    /// MS-EVEN: ElfrOpenBELW - Opens a handle to a previously backed up event log for reading
    /// </summary>
    public const ushort ElfrOpenBELW = 9;

    /// <summary>
    /// MS-EVEN: ElfrReadELW - Reads one or more events from an event log
    /// </summary>
    public const ushort ElfrReadELW = 10;

    /// <summary>
    /// MS-EVEN: ElfrReportEventW - Writes an event to an event log
    /// </summary>
    public const ushort ElfrReportEventW = 11;

    /// <summary>
    /// MS-EVEN: ElfrClearELFA - Clears an event log
    /// </summary>
    public const ushort ElfrClearELFA = 12;

    /// <summary>
    /// MS-EVEN: ElfrBackupELFA - Creates a backup of a live event log
    /// </summary>
    public const ushort ElfrBackupELFA = 13;

    /// <summary>
    /// MS-EVEN: ElfrOpenELA - Opens a handle to a live event log for reading or clearing
    /// </summary>
    public const ushort ElfrOpenELA = 14;

    /// <summary>
    /// MS-EVEN: ElfrRegisterEventSourceA - Opens a handle to a live event log for writing
    /// </summary>
    public const ushort ElfrRegisterEventSourceA = 15;

    /// <summary>
    /// MS-EVEN: ElfrOpenBELA - Opens a handle to a previously backed up event log for reading
    /// </summary>
    public const ushort ElfrOpenBELA = 16;

    /// <summary>
    /// MS-EVEN: ElfrReadELA - Reads one or more events from an event log
    /// </summary>
    public const ushort ElfrReadELA = 17;

    /// <summary>
    /// MS-EVEN: ElfrReportEventA - Writes an event to an event log
    /// </summary>
    public const ushort ElfrReportEventA = 18;

    /// <summary>
    /// MS-EVEN: Opnum19NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort EVEN_Opnum19NotUsedOnWire = 19;

    /// <summary>
    /// MS-EVEN: Opnum20NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort EVEN_Opnum20NotUsedOnWire = 20;

    /// <summary>
    /// MS-EVEN: Opnum21NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort EVEN_Opnum21NotUsedOnWire = 21;

    /// <summary>
    /// MS-EVEN: ElfrGetLogInformation - Gets information on an event log
    /// </summary>
    public const ushort ElfrGetLogInformation = 22;

    /// <summary>
    /// MS-EVEN: Opnum23NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort EVEN_Opnum23NotUsedOnWire = 23;

    /// <summary>
    /// MS-EVEN: ElfrReportEventAndSourceW - Writes a single event to an event log
    /// </summary>
    public const ushort ElfrReportEventAndSourceW = 24;

    /// <summary>
    /// MS-EVEN: ElfrReportEventExW - Writes an event to an event log
    /// </summary>
    public const ushort ElfrReportEventExW = 25;

    /// <summary>
    /// MS-EVEN: ElfrReportEventExA - Writes an event to an event log
    /// </summary>
    public const ushort ElfrReportEventExA = 26;

    #endregion // MS-EVEN
    #region MS-FSRVP

    /// <summary>
    /// MS-FSRVP: IsPathSupported
    /// </summary>
    public const ushort IsPathSupported = 8;

    /// <summary>
    /// MS-FSRVP: IsPathShadowCopied
    /// </summary>
    public const ushort IsPathShadowCopied = 9;

    #endregion // MS-FSRVP
    #region MS-PAN (IRPCAsyncNotify)

    /// <summary>
    /// MS-PAN (IRPCAsyncNotify): IRPCAsyncNotify_RegisterClient - Registers to receive notifications
    /// </summary>
    public const ushort IRPCAsyncNotify_RegisterClient = 0;

    /// <summary>
    /// MS-PAN (IRPCAsyncNotify): IRPCAsyncNotify_UnregisterClient - Unregisters remote objects
    /// </summary>
    public const ushort IRPCAsyncNotify_UnregisterClient = 1;

    /// <summary>
    /// MS-PAN (IRPCAsyncNotify): Opnum2NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort PAN_Opnum2NotUsedOnWire = 2;

    /// <summary>
    /// MS-PAN (IRPCAsyncNotify): IRPCAsyncNotify_GetNewChannel - Returns an array of pointers to print notification channels
    /// </summary>
    public const ushort IRPCAsyncNotify_GetNewChannel = 3;

    /// <summary>
    /// MS-PAN (IRPCAsyncNotify): IRPCAsyncNotify_GetNotificationSendResponse - Sends client response and returns next notification
    /// </summary>
    public const ushort IRPCAsyncNotify_GetNotificationSendResponse = 4;

    /// <summary>
    /// MS-PAN (IRPCAsyncNotify): IRPCAsyncNotify_GetNotification - Returns notification data from the server
    /// </summary>
    public const ushort IRPCAsyncNotify_GetNotification = 5;

    /// <summary>
    /// MS-PAN (IRPCAsyncNotify): IRPCAsyncNotify_CloseChannel - Sends a final response and closes the channel
    /// </summary>
    public const ushort IRPCAsyncNotify_CloseChannel = 6;

    #endregion // MS-PAN (IRPCAsyncNotify)
    #region MS-PAN (IRPCRemoteObject)

    /// <summary>
    /// MS-PAN (IRPCRemoteObject): IRPCRemoteObject_Create - Creates a remote object on a server
    /// </summary>
    public const ushort IRPCRemoteObject_Create = 0;

    /// <summary>
    /// MS-PAN (IRPCRemoteObject): IRPCRemoteObject_Delete - Destroys the specified remote object
    /// </summary>
    public const ushort IRPCRemoteObject_Delete = 1;

    #endregion // MS-PAN (IRPCRemoteObject)
    #region MS-PAR

    /// <summary>
    /// MS-PAR: RpcAsyncOpenPrinter - Opens a printer handle
    /// </summary>
    public const ushort RpcAsyncOpenPrinter = 0;

    /// <summary>
    /// MS-PAR: RpcAsyncAddPrinter - Adds a printer
    /// </summary>
    public const ushort RpcAsyncAddPrinter = 1;

    /// <summary>
    /// MS-PAR: RpcAsyncSetJob - Sets job parameters
    /// </summary>
    public const ushort RpcAsyncSetJob = 2;

    /// <summary>
    /// MS-PAR: RpcAsyncGetJob - Gets job information
    /// </summary>
    public const ushort RpcAsyncGetJob = 3;

    /// <summary>
    /// MS-PAR: RpcAsyncEnumJobs - Enumerates jobs
    /// </summary>
    public const ushort RpcAsyncEnumJobs = 4;

    /// <summary>
    /// MS-PAR: RpcAsyncAddJob - Adds a job
    /// </summary>
    public const ushort RpcAsyncAddJob = 5;

    /// <summary>
    /// MS-PAR: RpcAsyncScheduleJob - Schedules a job
    /// </summary>
    public const ushort RpcAsyncScheduleJob = 6;

    /// <summary>
    /// MS-PAR: RpcAsyncDeletePrinter - Deletes a printer
    /// </summary>
    public const ushort RpcAsyncDeletePrinter = 7;

    /// <summary>
    /// MS-PAR: RpcAsyncSetPrinter - Sets printer information
    /// </summary>
    public const ushort RpcAsyncSetPrinter = 8;

    /// <summary>
    /// MS-PAR: RpcAsyncGetPrinter - Gets printer information
    /// </summary>
    public const ushort RpcAsyncGetPrinter = 9;

    /// <summary>
    /// MS-PAR: RpcAsyncStartDocPrinter - Starts a document
    /// </summary>
    public const ushort RpcAsyncStartDocPrinter = 10;

    /// <summary>
    /// MS-PAR: RpcAsyncStartPagePrinter - Starts a page
    /// </summary>
    public const ushort RpcAsyncStartPagePrinter = 11;

    /// <summary>
    /// MS-PAR: RpcAsyncWritePrinter - Writes data to printer
    /// </summary>
    public const ushort RpcAsyncWritePrinter = 12;

    /// <summary>
    /// MS-PAR: RpcAsyncEndPagePrinter - Ends a page
    /// </summary>
    public const ushort RpcAsyncEndPagePrinter = 13;

    /// <summary>
    /// MS-PAR: RpcAsyncEndDocPrinter - Ends a document
    /// </summary>
    public const ushort RpcAsyncEndDocPrinter = 14;

    /// <summary>
    /// MS-PAR: RpcAsyncAbortPrinter - Aborts printer operation
    /// </summary>
    public const ushort RpcAsyncAbortPrinter = 15;

    /// <summary>
    /// MS-PAR: RpcAsyncGetPrinterData - Gets printer data
    /// </summary>
    public const ushort RpcAsyncGetPrinterData = 16;

    /// <summary>
    /// MS-PAR: RpcAsyncGetPrinterDataEx - Gets printer data (extended)
    /// </summary>
    public const ushort RpcAsyncGetPrinterDataEx = 17;

    /// <summary>
    /// MS-PAR: RpcAsyncSetPrinterData - Sets printer data
    /// </summary>
    public const ushort RpcAsyncSetPrinterData = 18;

    /// <summary>
    /// MS-PAR: RpcAsyncSetPrinterDataEx - Sets printer data (extended)
    /// </summary>
    public const ushort RpcAsyncSetPrinterDataEx = 19;

    /// <summary>
    /// MS-PAR: RpcAsyncClosePrinter - Closes printer handle
    /// </summary>
    public const ushort RpcAsyncClosePrinter = 20;

    /// <summary>
    /// MS-PAR: RpcAsyncAddForm - Adds a form
    /// </summary>
    public const ushort RpcAsyncAddForm = 21;

    /// <summary>
    /// MS-PAR: RpcAsyncDeleteForm - Deletes a form
    /// </summary>
    public const ushort RpcAsyncDeleteForm = 22;

    /// <summary>
    /// MS-PAR: RpcAsyncGetForm - Gets form information
    /// </summary>
    public const ushort RpcAsyncGetForm = 23;

    /// <summary>
    /// MS-PAR: RpcAsyncSetForm - Sets form information
    /// </summary>
    public const ushort RpcAsyncSetForm = 24;

    /// <summary>
    /// MS-PAR: RpcAsyncEnumForms - Enumerates forms
    /// </summary>
    public const ushort RpcAsyncEnumForms = 25;

    /// <summary>
    /// MS-PAR: RpcAsyncGetPrinterDriver - Gets printer driver
    /// </summary>
    public const ushort RpcAsyncGetPrinterDriver = 26;

    /// <summary>
    /// MS-PAR: RpcAsyncEnumPrinterData - Enumerates printer data
    /// </summary>
    public const ushort RpcAsyncEnumPrinterData = 27;

    /// <summary>
    /// MS-PAR: RpcAsyncEnumPrinterDataEx - Enumerates printer data (extended)
    /// </summary>
    public const ushort RpcAsyncEnumPrinterDataEx = 28;

    /// <summary>
    /// MS-PAR: RpcAsyncEnumPrinterKey - Enumerates printer registry keys
    /// </summary>
    public const ushort RpcAsyncEnumPrinterKey = 29;

    /// <summary>
    /// MS-PAR: RpcAsyncDeletePrinterData - Deletes printer data
    /// </summary>
    public const ushort RpcAsyncDeletePrinterData = 30;

    /// <summary>
    /// MS-PAR: RpcAsyncDeletePrinterDataEx - Deletes printer data (extended)
    /// </summary>
    public const ushort RpcAsyncDeletePrinterDataEx = 31;

    /// <summary>
    /// MS-PAR: RpcAsyncDeletePrinterKey - Deletes printer registry key
    /// </summary>
    public const ushort RpcAsyncDeletePrinterKey = 32;

    /// <summary>
    /// MS-PAR: RpcAsyncXcvData - Extensible printer port configuration data
    /// </summary>
    public const ushort RpcAsyncXcvData = 33;

    /// <summary>
    /// MS-PAR: RpcAsyncSendRecvBidiData - Sends/receives bidirectional data
    /// </summary>
    public const ushort RpcAsyncSendRecvBidiData = 34;

    /// <summary>
    /// MS-PAR: RpcAsyncCreatePrinterIC - Creates printer information context
    /// </summary>
    public const ushort RpcAsyncCreatePrinterIC = 35;

    /// <summary>
    /// MS-PAR: RpcAsyncPlayGdiScriptOnPrinterIC - Plays GDI script on printer IC
    /// </summary>
    public const ushort RpcAsyncPlayGdiScriptOnPrinterIC = 36;

    /// <summary>
    /// MS-PAR: RpcAsyncDeletePrinterIC - Deletes printer information context
    /// </summary>
    public const ushort RpcAsyncDeletePrinterIC = 37;

    /// <summary>
    /// MS-PAR: RpcAsyncEnumPrinters - Enumerates printers
    /// </summary>
    public const ushort RpcAsyncEnumPrinters = 38;

    /// <summary>
    /// MS-PAR: RpcAsyncAddPrinterDriver - Adds a printer driver
    /// </summary>
    public const ushort RpcAsyncAddPrinterDriver = 39;

    /// <summary>
    /// MS-PAR: RpcAsyncEnumPrinterDrivers - Enumerates printer drivers
    /// </summary>
    public const ushort RpcAsyncEnumPrinterDrivers = 40;

    /// <summary>
    /// MS-PAR: RpcAsyncGetPrinterDriverDirectory - Gets printer driver directory
    /// </summary>
    public const ushort RpcAsyncGetPrinterDriverDirectory = 41;

    /// <summary>
    /// MS-PAR: RpcAsyncDeletePrinterDriver - Deletes a printer driver
    /// </summary>
    public const ushort RpcAsyncDeletePrinterDriver = 42;

    /// <summary>
    /// MS-PAR: RpcAsyncDeletePrinterDriverEx - Deletes a printer driver (extended)
    /// </summary>
    public const ushort RpcAsyncDeletePrinterDriverEx = 43;

    /// <summary>
    /// MS-PAR: RpcAsyncAddPrintProcessor - Adds a print processor
    /// </summary>
    public const ushort RpcAsyncAddPrintProcessor = 44;

    /// <summary>
    /// MS-PAR: RpcAsyncEnumPrintProcessors - Enumerates print processors
    /// </summary>
    public const ushort RpcAsyncEnumPrintProcessors = 45;

    /// <summary>
    /// MS-PAR: RpcAsyncGetPrintProcessorDirectory - Gets print processor directory
    /// </summary>
    public const ushort RpcAsyncGetPrintProcessorDirectory = 46;

    /// <summary>
    /// MS-PAR: RpcAsyncEnumPorts - Enumerates ports
    /// </summary>
    public const ushort RpcAsyncEnumPorts = 47;

    /// <summary>
    /// MS-PAR: RpcAsyncEnumMonitors - Enumerates monitors
    /// </summary>
    public const ushort RpcAsyncEnumMonitors = 48;

    /// <summary>
    /// MS-PAR: RpcAsyncAddPort - Adds a port
    /// </summary>
    public const ushort RpcAsyncAddPort = 49;

    /// <summary>
    /// MS-PAR: RpcAsyncSetPort - Sets port information
    /// </summary>
    public const ushort RpcAsyncSetPort = 50;

    /// <summary>
    /// MS-PAR: RpcAsyncAddMonitor - Adds a monitor
    /// </summary>
    public const ushort RpcAsyncAddMonitor = 51;

    /// <summary>
    /// MS-PAR: RpcAsyncDeleteMonitor - Deletes a monitor
    /// </summary>
    public const ushort RpcAsyncDeleteMonitor = 52;

    /// <summary>
    /// MS-PAR: RpcAsyncDeletePrintProcessor - Deletes a print processor
    /// </summary>
    public const ushort RpcAsyncDeletePrintProcessor = 53;

    /// <summary>
    /// MS-PAR: RpcAsyncEnumPrintProcessorDatatypes - Enumerates print processor datatypes
    /// </summary>
    public const ushort RpcAsyncEnumPrintProcessorDatatypes = 54;

    /// <summary>
    /// MS-PAR: RpcAsyncAddPerMachineConnection - Adds per-machine connection
    /// </summary>
    public const ushort RpcAsyncAddPerMachineConnection = 55;

    /// <summary>
    /// MS-PAR: RpcAsyncDeletePerMachineConnection - Deletes per-machine connection
    /// </summary>
    public const ushort RpcAsyncDeletePerMachineConnection = 56;

    /// <summary>
    /// MS-PAR: RpcAsyncEnumPerMachineConnections - Enumerates per-machine connections
    /// </summary>
    public const ushort RpcAsyncEnumPerMachineConnections = 57;

    /// <summary>
    /// MS-PAR: RpcSyncRegisterForRemoteNotifications - Registers for remote notifications
    /// </summary>
    public const ushort RpcSyncRegisterForRemoteNotifications = 58;

    /// <summary>
    /// MS-PAR: RpcSyncUnRegisterForRemoteNotifications - Unregisters for remote notifications
    /// </summary>
    public const ushort RpcSyncUnRegisterForRemoteNotifications = 59;

    /// <summary>
    /// MS-PAR: RpcSyncRefreshRemoteNotifications - Refreshes remote notifications
    /// </summary>
    public const ushort RpcSyncRefreshRemoteNotifications = 60;

    /// <summary>
    /// MS-PAR: RpcAsyncGetRemoteNotifications - Gets remote notifications asynchronously
    /// </summary>
    public const ushort RpcAsyncGetRemoteNotifications = 61;

    /// <summary>
    /// MS-PAR: RpcAsyncInstallPrinterDriverFromPackage - Installs printer driver from package
    /// </summary>
    public const ushort RpcAsyncInstallPrinterDriverFromPackage = 62;

    /// <summary>
    /// MS-PAR: RpcAsyncUploadPrinterDriverPackage - Uploads printer driver package
    /// </summary>
    public const ushort RpcAsyncUploadPrinterDriverPackage = 63;

    /// <summary>
    /// MS-PAR: RpcAsyncGetCorePrinterDrivers - Gets core printer drivers
    /// </summary>
    public const ushort RpcAsyncGetCorePrinterDrivers = 64;

    /// <summary>
    /// MS-PAR: RpcAsyncCorePrinterDriverInstalled - Checks if core printer driver is installed
    /// </summary>
    public const ushort RpcAsyncCorePrinterDriverInstalled = 65;

    /// <summary>
    /// MS-PAR: RpcAsyncGetPrinterDriverPackagePath - Gets printer driver package path
    /// </summary>
    public const ushort RpcAsyncGetPrinterDriverPackagePath = 66;

    /// <summary>
    /// MS-PAR: RpcAsyncDeletePrinterDriverPackage - Deletes printer driver package
    /// </summary>
    public const ushort RpcAsyncDeletePrinterDriverPackage = 67;

    /// <summary>
    /// MS-PAR: RpcAsyncReadPrinter - Reads from printer
    /// </summary>
    public const ushort RpcAsyncReadPrinter = 68;

    /// <summary>
    /// MS-PAR: RpcAsyncResetPrinter - Resets printer
    /// </summary>
    public const ushort RpcAsyncResetPrinter = 69;

    /// <summary>
    /// MS-PAR: RpcAsyncGetJobNamedPropertyValue - Gets job named property value
    /// </summary>
    public const ushort RpcAsyncGetJobNamedPropertyValue = 70;

    /// <summary>
    /// MS-PAR: RpcAsyncSetJobNamedProperty - Sets job named property
    /// </summary>
    public const ushort RpcAsyncSetJobNamedProperty = 71;

    /// <summary>
    /// MS-PAR: RpcAsyncDeleteJobNamedProperty - Deletes job named property
    /// </summary>
    public const ushort RpcAsyncDeleteJobNamedProperty = 72;

    /// <summary>
    /// MS-PAR: RpcAsyncEnumJobNamedProperties - Enumerates job named properties
    /// </summary>
    public const ushort RpcAsyncEnumJobNamedProperties = 73;

    /// <summary>
    /// MS-PAR: RpcAsyncLogJobInfoForBranchOffice - Logs job info for branch office
    /// </summary>
    public const ushort RpcAsyncLogJobInfoForBranchOffice = 74;

    #endregion // MS-PAR
    #region MS-RPRN

    /// <summary>
    /// MS-RPRN: RpcEnumPrinters - Enumerates available printers
    /// </summary>
    public const ushort RpcEnumPrinters = 0;

    /// <summary>
    /// MS-RPRN: RpcOpenPrinter - Opens a handle to a printer
    /// </summary>
    public const ushort RpcOpenPrinter = 1;

    /// <summary>
    /// MS-RPRN: RpcSetJob - Sets job parameters
    /// </summary>
    public const ushort RpcSetJob = 2;

    /// <summary>
    /// MS-RPRN: RpcGetJob - Gets job information
    /// </summary>
    public const ushort RpcGetJob = 3;

    /// <summary>
    /// MS-RPRN: RpcEnumJobs - Enumerates jobs
    /// </summary>
    public const ushort RpcEnumJobs = 4;

    /// <summary>
    /// MS-RPRN: RpcAddPrinter - Adds a printer
    /// </summary>
    public const ushort RpcAddPrinter = 5;

    /// <summary>
    /// MS-RPRN: RpcDeletePrinter - Deletes a printer
    /// </summary>
    public const ushort RpcDeletePrinter = 6;

    /// <summary>
    /// MS-RPRN: RpcSetPrinter - Sets printer information
    /// </summary>
    public const ushort RpcSetPrinter = 7;

    /// <summary>
    /// MS-RPRN: RpcGetPrinter - Gets printer information
    /// </summary>
    public const ushort RpcGetPrinter = 8;

    /// <summary>
    /// MS-RPRN: RpcAddPrinterDriver - Adds a printer driver
    /// </summary>
    public const ushort RpcAddPrinterDriver = 9;

    /// <summary>
    /// MS-RPRN: RpcEnumPrinterDrivers - Enumerates printer drivers
    /// </summary>
    public const ushort RpcEnumPrinterDrivers = 10;

    /// <summary>
    /// MS-RPRN: RpcGetPrinterDriver - Gets printer driver information
    /// </summary>
    public const ushort RpcGetPrinterDriver = 11;

    /// <summary>
    /// MS-RPRN: RpcGetPrinterDriverDirectory - Gets printer driver directory
    /// </summary>
    public const ushort RpcGetPrinterDriverDirectory = 12;

    /// <summary>
    /// MS-RPRN: RpcDeletePrinterDriver - Deletes a printer driver
    /// </summary>
    public const ushort RpcDeletePrinterDriver = 13;

    /// <summary>
    /// MS-RPRN: RpcAddPrintProcessor - Adds a print processor
    /// </summary>
    public const ushort RpcAddPrintProcessor = 14;

    /// <summary>
    /// MS-RPRN: RpcEnumPrintProcessors - Enumerates print processors
    /// </summary>
    public const ushort RpcEnumPrintProcessors = 15;

    /// <summary>
    /// MS-RPRN: RpcGetPrintProcessorDirectory - Gets print processor directory
    /// </summary>
    public const ushort RpcGetPrintProcessorDirectory = 16;

    /// <summary>
    /// MS-RPRN: RpcStartDocPrinter - Starts a document
    /// </summary>
    public const ushort RpcStartDocPrinter = 17;

    /// <summary>
    /// MS-RPRN: RpcStartPagePrinter - Starts a page
    /// </summary>
    public const ushort RpcStartPagePrinter = 18;

    /// <summary>
    /// MS-RPRN: RpcWritePrinter - Writes data to printer
    /// </summary>
    public const ushort RpcWritePrinter = 19;

    /// <summary>
    /// MS-RPRN: RpcEndPagePrinter - Ends a page
    /// </summary>
    public const ushort RpcEndPagePrinter = 20;

    /// <summary>
    /// MS-RPRN: RpcAbortPrinter - Aborts printer operation
    /// </summary>
    public const ushort RpcAbortPrinter = 21;

    /// <summary>
    /// MS-RPRN: RpcReadPrinter - Reads data from printer
    /// </summary>
    public const ushort RpcReadPrinter = 22;

    /// <summary>
    /// MS-RPRN: RpcEndDocPrinter - Ends a document
    /// </summary>
    public const ushort RpcEndDocPrinter = 23;

    /// <summary>
    /// MS-RPRN: RpcAddJob - Adds a job
    /// </summary>
    public const ushort RpcAddJob = 24;

    /// <summary>
    /// MS-RPRN: RpcScheduleJob - Schedules a job
    /// </summary>
    public const ushort RpcScheduleJob = 25;

    /// <summary>
    /// MS-RPRN: RpcGetPrinterData - Gets printer data
    /// </summary>
    public const ushort RpcGetPrinterData = 26;

    /// <summary>
    /// MS-RPRN: RpcSetPrinterData - Sets printer data
    /// </summary>
    public const ushort RpcSetPrinterData = 27;

    /// <summary>
    /// MS-RPRN: RpcWaitForPrinterChange - Waits for printer change
    /// </summary>
    public const ushort RpcWaitForPrinterChange = 28;

    /// <summary>
    /// MS-RPRN: RpcClosePrinter - Closes printer handle
    /// </summary>
    public const ushort RpcClosePrinter = 29;

    /// <summary>
    /// MS-RPRN: RpcAddForm - Adds a form
    /// </summary>
    public const ushort RpcAddForm = 30;

    /// <summary>
    /// MS-RPRN: RpcDeleteForm - Deletes a form
    /// </summary>
    public const ushort RpcDeleteForm = 31;

    /// <summary>
    /// MS-RPRN: RpcGetForm - Gets form information
    /// </summary>
    public const ushort RpcGetForm = 32;

    /// <summary>
    /// MS-RPRN: RpcSetForm - Sets form information
    /// </summary>
    public const ushort RpcSetForm = 33;

    /// <summary>
    /// MS-RPRN: RpcEnumForms - Enumerates forms
    /// </summary>
    public const ushort RpcEnumForms = 34;

    /// <summary>
    /// MS-RPRN: RpcEnumPorts - Enumerates ports
    /// </summary>
    public const ushort RpcEnumPorts = 35;

    /// <summary>
    /// MS-RPRN: RpcEnumMonitors - Enumerates monitors
    /// </summary>
    public const ushort RpcEnumMonitors = 36;

    /// <summary>
    /// MS-RPRN: Opnum37NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort RPRN_Opnum37NotUsedOnWire = 37;

    /// <summary>
    /// MS-RPRN: Opnum38NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort RPRN_Opnum38NotUsedOnWire = 38;

    /// <summary>
    /// MS-RPRN: RpcDeletePort - Deletes a port
    /// </summary>
    public const ushort RpcDeletePort = 39;

    /// <summary>
    /// MS-RPRN: RpcCreatePrinterIC - Creates printer information context
    /// </summary>
    public const ushort RpcCreatePrinterIC = 40;

    /// <summary>
    /// MS-RPRN: RpcPlayGdiScriptOnPrinterIC - Plays GDI script on printer IC
    /// </summary>
    public const ushort RpcPlayGdiScriptOnPrinterIC = 41;

    /// <summary>
    /// MS-RPRN: RpcDeletePrinterIC - Deletes printer information context
    /// </summary>
    public const ushort RpcDeletePrinterIC = 42;

    /// <summary>
    /// MS-RPRN: Opnum43NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort RPRN_Opnum43NotUsedOnWire = 43;

    /// <summary>
    /// MS-RPRN: Opnum44NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort RPRN_Opnum44NotUsedOnWire = 44;

    /// <summary>
    /// MS-RPRN: Opnum45NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort RPRN_Opnum45NotUsedOnWire = 45;

    /// <summary>
    /// MS-RPRN: RpcAddMonitor - Adds a monitor
    /// </summary>
    public const ushort RpcAddMonitor = 46;

    /// <summary>
    /// MS-RPRN: RpcDeleteMonitor - Deletes a monitor
    /// </summary>
    public const ushort RpcDeleteMonitor = 47;

    /// <summary>
    /// MS-RPRN: RpcDeletePrintProcessor - Deletes a print processor
    /// </summary>
    public const ushort RpcDeletePrintProcessor = 48;

    /// <summary>
    /// MS-RPRN: Opnum49NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort RPRN_Opnum49NotUsedOnWire = 49;

    /// <summary>
    /// MS-RPRN: Opnum50NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort RPRN_Opnum50NotUsedOnWire = 50;

    /// <summary>
    /// MS-RPRN: RpcEnumPrintProcessorDatatypes - Enumerates print processor datatypes
    /// </summary>
    public const ushort RpcEnumPrintProcessorDatatypes = 51;

    /// <summary>
    /// MS-RPRN: RpcResetPrinter - Resets printer
    /// </summary>
    public const ushort RpcResetPrinter = 52;

    /// <summary>
    /// MS-RPRN: RpcGetPrinterDriver2 - Gets printer driver (version 2)
    /// </summary>
    public const ushort RpcGetPrinterDriver2 = 53;

    /// <summary>
    /// MS-RPRN: Opnum54NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort RPRN_Opnum54NotUsedOnWire = 54;

    /// <summary>
    /// MS-RPRN: Opnum55NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort RPRN_Opnum55NotUsedOnWire = 55;

    /// <summary>
    /// MS-RPRN: RpcFindClosePrinterChangeNotification - Closes printer change notification
    /// </summary>
    public const ushort RpcFindClosePrinterChangeNotification = 56;

    /// <summary>
    /// MS-RPRN: Opnum57NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort RPRN_Opnum57NotUsedOnWire = 57;

    /// <summary>
    /// MS-RPRN: RpcReplyOpenPrinter - Opens reply printer
    /// </summary>
    public const ushort RpcReplyOpenPrinter = 58;

    /// <summary>
    /// MS-RPRN: RpcRouterReplyPrinter - Router reply printer
    /// </summary>
    public const ushort RpcRouterReplyPrinter = 59;

    /// <summary>
    /// MS-RPRN: RpcReplyClosePrinter - Closes reply printer
    /// </summary>
    public const ushort RpcReplyClosePrinter = 60;

    /// <summary>
    /// MS-RPRN: RpcAddPortEx - Adds a port (extended)
    /// </summary>
    public const ushort RpcAddPortEx = 61;

    /// <summary>
    /// MS-RPRN: RpcRemoteFindFirstPrinterChangeNotification - Finds first printer change notification
    /// </summary>
    public const ushort RpcRemoteFindFirstPrinterChangeNotification = 62;

    /// <summary>
    /// MS-RPRN: Opnum63NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort RPRN_Opnum63NotUsedOnWire = 63;

    /// <summary>
    /// MS-RPRN: Opnum64NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort RPRN_Opnum64NotUsedOnWire = 64;

    /// <summary>
    /// MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx - Finds first printer change notification (extended)
    /// </summary>
    public const ushort RpcRemoteFindFirstPrinterChangeNotificationEx = 65;

    /// <summary>
    /// MS-RPRN: RpcRouterReplyPrinterEx - Router reply printer (extended)
    /// </summary>
    public const ushort RpcRouterReplyPrinterEx = 66;

    /// <summary>
    /// MS-RPRN: RpcRouterRefreshPrinterChangeNotification - Refreshes printer change notification
    /// </summary>
    public const ushort RpcRouterRefreshPrinterChangeNotification = 67;

    /// <summary>
    /// MS-RPRN: Opnum68NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort RPRN_Opnum68NotUsedOnWire = 68;

    /// <summary>
    /// MS-RPRN: RpcOpenPrinterEx - Opens a printer handle (extended)
    /// </summary>
    public const ushort RpcOpenPrinterEx = 69;

    /// <summary>
    /// MS-RPRN: RpcAddPrinterEx - Adds a printer (extended)
    /// </summary>
    public const ushort RpcAddPrinterEx = 70;

    /// <summary>
    /// MS-RPRN: RpcSetPort - Sets port information
    /// </summary>
    public const ushort RpcSetPort = 71;

    /// <summary>
    /// MS-RPRN: RpcEnumPrinterData - Enumerates printer data
    /// </summary>
    public const ushort RpcEnumPrinterData = 72;

    /// <summary>
    /// MS-RPRN: RpcDeletePrinterData - Deletes printer data
    /// </summary>
    public const ushort RpcDeletePrinterData = 73;

    /// <summary>
    /// MS-RPRN: Opnum74NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort RPRN_Opnum74NotUsedOnWire = 74;

    /// <summary>
    /// MS-RPRN: Opnum75NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort RPRN_Opnum75NotUsedOnWire = 75;

    /// <summary>
    /// MS-RPRN: Opnum76NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort RPRN_Opnum76NotUsedOnWire = 76;

    /// <summary>
    /// MS-RPRN: RpcSetPrinterDataEx - Sets printer data (extended)
    /// </summary>
    public const ushort RpcSetPrinterDataEx = 77;

    /// <summary>
    /// MS-RPRN: RpcGetPrinterDataEx - Gets printer data (extended)
    /// </summary>
    public const ushort RpcGetPrinterDataEx = 78;

    /// <summary>
    /// MS-RPRN: RpcEnumPrinterDataEx - Enumerates printer data (extended)
    /// </summary>
    public const ushort RpcEnumPrinterDataEx = 79;

    /// <summary>
    /// MS-RPRN: RpcEnumPrinterKey - Enumerates printer registry keys
    /// </summary>
    public const ushort RpcEnumPrinterKey = 80;

    /// <summary>
    /// MS-RPRN: RpcDeletePrinterDataEx - Deletes printer data (extended)
    /// </summary>
    public const ushort RpcDeletePrinterDataEx = 81;

    /// <summary>
    /// MS-RPRN: RpcDeletePrinterKey - Deletes printer registry key
    /// </summary>
    public const ushort RpcDeletePrinterKey = 82;

    /// <summary>
    /// MS-RPRN: Opnum83NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort RPRN_Opnum83NotUsedOnWire = 83;

    /// <summary>
    /// MS-RPRN: RpcDeletePrinterDriverEx - Deletes a printer driver (extended)
    /// </summary>
    public const ushort RpcDeletePrinterDriverEx = 84;

    /// <summary>
    /// MS-RPRN: RpcAddPerMachineConnection - Adds per-machine connection
    /// </summary>
    public const ushort RpcAddPerMachineConnection = 85;

    /// <summary>
    /// MS-RPRN: RpcDeletePerMachineConnection - Deletes per-machine connection
    /// </summary>
    public const ushort RpcDeletePerMachineConnection = 86;

    /// <summary>
    /// MS-RPRN: RpcEnumPerMachineConnections - Enumerates per-machine connections
    /// </summary>
    public const ushort RpcEnumPerMachineConnections = 87;

    /// <summary>
    /// MS-RPRN: RpcXcvData - Extensible printer port configuration data
    /// </summary>
    public const ushort RpcXcvData = 88;

    /// <summary>
    /// MS-RPRN: RpcAddPrinterDriverEx - Adds a printer driver (extended)
    /// </summary>
    public const ushort RpcAddPrinterDriverEx = 89;

    /// <summary>
    /// MS-RPRN: Opnum90NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort RPRN_Opnum90NotUsedOnWire = 90;

    /// <summary>
    /// MS-RPRN: Opnum91NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort RPRN_Opnum91NotUsedOnWire = 91;

    /// <summary>
    /// MS-RPRN: Opnum92NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort RPRN_Opnum92NotUsedOnWire = 92;

    /// <summary>
    /// MS-RPRN: Opnum93NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort RPRN_Opnum93NotUsedOnWire = 93;

    /// <summary>
    /// MS-RPRN: Opnum94NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort RPRN_Opnum94NotUsedOnWire = 94;

    /// <summary>
    /// MS-RPRN: Opnum95NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort RPRN_Opnum95NotUsedOnWire = 95;

    /// <summary>
    /// MS-RPRN: RpcFlushPrinter - Flushes printer
    /// </summary>
    public const ushort RpcFlushPrinter = 96;

    /// <summary>
    /// MS-RPRN: RpcSendRecvBidiData - Sends/receives bidirectional data
    /// </summary>
    public const ushort RpcSendRecvBidiData = 97;

    /// <summary>
    /// MS-RPRN: Opnum98NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort RPRN_Opnum98NotUsedOnWire = 98;

    /// <summary>
    /// MS-RPRN: Opnum99NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort RPRN_Opnum99NotUsedOnWire = 99;

    /// <summary>
    /// MS-RPRN: Opnum100NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort RPRN_Opnum100NotUsedOnWire = 100;

    /// <summary>
    /// MS-RPRN: Opnum101NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort RPRN_Opnum101NotUsedOnWire = 101;

    /// <summary>
    /// MS-RPRN: RpcGetCorePrinterDrivers - Gets core printer drivers
    /// </summary>
    public const ushort RpcGetCorePrinterDrivers = 102;

    /// <summary>
    /// MS-RPRN: Opnum103NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort RPRN_Opnum103NotUsedOnWire = 103;

    /// <summary>
    /// MS-RPRN: RpcGetPrinterDriverPackagePath - Gets printer driver package path
    /// </summary>
    public const ushort RpcGetPrinterDriverPackagePath = 104;

    /// <summary>
    /// MS-RPRN: Opnum105NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort RPRN_Opnum105NotUsedOnWire = 105;

    /// <summary>
    /// MS-RPRN: Opnum106NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort RPRN_Opnum106NotUsedOnWire = 106;

    /// <summary>
    /// MS-RPRN: Opnum107NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort RPRN_Opnum107NotUsedOnWire = 107;

    /// <summary>
    /// MS-RPRN: Opnum108NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort RPRN_Opnum108NotUsedOnWire = 108;

    /// <summary>
    /// MS-RPRN: Opnum109NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort RPRN_Opnum109NotUsedOnWire = 109;

    /// <summary>
    /// MS-RPRN: RpcGetJobNamedPropertyValue - Gets job named property value
    /// </summary>
    public const ushort RpcGetJobNamedPropertyValue = 110;

    /// <summary>
    /// MS-RPRN: RpcSetJobNamedProperty - Sets job named property
    /// </summary>
    public const ushort RpcSetJobNamedProperty = 111;

    /// <summary>
    /// MS-RPRN: RpcDeleteJobNamedProperty - Deletes job named property
    /// </summary>
    public const ushort RpcDeleteJobNamedProperty = 112;

    /// <summary>
    /// MS-RPRN: RpcEnumJobNamedProperties - Enumerates job named properties
    /// </summary>
    public const ushort RpcEnumJobNamedProperties = 113;

    /// <summary>
    /// MS-RPRN: Opnum114NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort RPRN_Opnum114NotUsedOnWire = 114;

    /// <summary>
    /// MS-RPRN: Opnum115NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort RPRN_Opnum115NotUsedOnWire = 115;

    /// <summary>
    /// MS-RPRN: RpcLogJobInfoForBranchOffice - Logs job info for branch office
    /// </summary>
    public const ushort RpcLogJobInfoForBranchOffice = 116;

    /// <summary>
    /// MS-RPRN: RpcRegeneratePrintDeviceCapabilities - Regenerates print device capabilities
    /// </summary>
    public const ushort RpcRegeneratePrintDeviceCapabilities = 117;

    /// <summary>
    /// MS-RPRN: Opnum118NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort RPRN_Opnum118NotUsedOnWire = 118;

    /// <summary>
    /// MS-RPRN: RpcIppCreateJobOnPrinter - Creates IPP job on printer
    /// </summary>
    public const ushort RpcIppCreateJobOnPrinter = 119;

    /// <summary>
    /// MS-RPRN: RpcIppGetJobAttributes - Gets IPP job attributes
    /// </summary>
    public const ushort RpcIppGetJobAttributes = 120;

    /// <summary>
    /// MS-RPRN: RpcIppSetJobAttributes - Sets IPP job attributes
    /// </summary>
    public const ushort RpcIppSetJobAttributes = 121;

    /// <summary>
    /// MS-RPRN: RpcIppGetPrinterAttributes - Gets IPP printer attributes
    /// </summary>
    public const ushort RpcIppGetPrinterAttributes = 122;

    /// <summary>
    /// MS-RPRN: RpcIppSetPrinterAttributes - Sets IPP printer attributes
    /// </summary>
    public const ushort RpcIppSetPrinterAttributes = 123;

    #endregion // MS-RPRN
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
    #region MS-WKST

    /// <summary>
    /// MS-WKST: NetrWkstaGetInfo
    /// </summary>
    public const ushort NetrWkstaGetInfo = 0;

    /// <summary>
    /// MS-WKST: NetrWkstaSetInfo
    /// </summary>
    public const ushort NetrWkstaSetInfo = 1;

    /// <summary>
    /// MS-WKST: NetrWkstaUserEnum
    /// </summary>
    public const ushort NetrWkstaUserEnum = 2;

    /// <summary>
    /// MS-WKST: Opnum3NotUsedOnWire (Reserved for local use)
    /// </summary>
    public const ushort WKST_Opnum3NotUsedOnWire = 3;

    /// <summary>
    /// MS-WKST: Opnum4NotUsedOnWire (Reserved for local use)
    /// </summary>
    public const ushort WKST_Opnum4NotUsedOnWire = 4;

    /// <summary>
    /// MS-WKST: NetrWkstaTransportEnum
    /// </summary>
    public const ushort NetrWkstaTransportEnum = 5;

    /// <summary>
    /// MS-WKST: NetrWkstaTransportAdd
    /// </summary>
    public const ushort NetrWkstaTransportAdd = 6;

    /// <summary>
    /// MS-WKST: NetrWkstaTransportDel
    /// </summary>
    public const ushort NetrWkstaTransportDel = 7;

    /// <summary>
    /// MS-WKST: NetrUseAdd
    /// </summary>
    public const ushort NetrUseAdd = 8;

    /// <summary>
    /// MS-WKST: NetrUseGetInfo
    /// </summary>
    public const ushort NetrUseGetInfo = 9;

    /// <summary>
    /// MS-WKST: NetrUseDel
    /// </summary>
    public const ushort NetrUseDel = 10;

    /// <summary>
    /// MS-WKST: NetrUseEnum
    /// </summary>
    public const ushort NetrUseEnum = 11;

    /// <summary>
    /// MS-WKST: Opnum12NotUsedOnWire (Reserved for local use)
    /// </summary>
    public const ushort WKST_Opnum12NotUsedOnWire = 12;

    /// <summary>
    /// MS-WKST: NetrWorkstationStatisticsGet
    /// </summary>
    public const ushort NetrWorkstationStatisticsGet = 13;

    /// <summary>
    /// MS-WKST: Opnum14NotUsedOnWire (Reserved for local use)
    /// </summary>
    public const ushort WKST_Opnum14NotUsedOnWire = 14;

    /// <summary>
    /// MS-WKST: Opnum15NotUsedOnWire (Reserved for local use)
    /// </summary>
    public const ushort WKST_Opnum15NotUsedOnWire = 15;

    /// <summary>
    /// MS-WKST: Opnum16NotUsedOnWire (Reserved for local use)
    /// </summary>
    public const ushort WKST_Opnum16NotUsedOnWire = 16;

    /// <summary>
    /// MS-WKST: Opnum17NotUsedOnWire (Reserved for local use)
    /// </summary>
    public const ushort WKST_Opnum17NotUsedOnWire = 17;

    /// <summary>
    /// MS-WKST: Opnum18NotUsedOnWire (Reserved for local use)
    /// </summary>
    public const ushort WKST_Opnum18NotUsedOnWire = 18;

    /// <summary>
    /// MS-WKST: Opnum19NotUsedOnWire (Reserved for local use)
    /// </summary>
    public const ushort WKST_Opnum19NotUsedOnWire = 19;

    /// <summary>
    /// MS-WKST: NetrGetJoinInformation
    /// </summary>
    public const ushort NetrGetJoinInformation = 20;

    /// <summary>
    /// MS-WKST: Opnum21NotUsedOnWire (Reserved for local use)
    /// </summary>
    public const ushort WKST_Opnum21NotUsedOnWire = 21;

    /// <summary>
    /// MS-WKST: NetrJoinDomain2
    /// </summary>
    public const ushort NetrJoinDomain2 = 22;

    /// <summary>
    /// MS-WKST: NetrUnjoinDomain2
    /// </summary>
    public const ushort NetrUnjoinDomain2 = 23;

    /// <summary>
    /// MS-WKST: NetrRenameMachineInDomain2
    /// </summary>
    public const ushort NetrRenameMachineInDomain2 = 24;

    /// <summary>
    /// MS-WKST: NetrValidateName2
    /// </summary>
    public const ushort NetrValidateName2 = 25;

    /// <summary>
    /// MS-WKST: NetrGetJoinableOUs2
    /// </summary>
    public const ushort NetrGetJoinableOUs2 = 26;

    /// <summary>
    /// MS-WKST: NetrAddAlternateComputerName
    /// </summary>
    public const ushort NetrAddAlternateComputerName = 27;

    /// <summary>
    /// MS-WKST: NetrRemoveAlternateComputerName
    /// </summary>
    public const ushort NetrRemoveAlternateComputerName = 28;

    /// <summary>
    /// MS-WKST: NetrSetPrimaryComputerName
    /// </summary>
    public const ushort NetrSetPrimaryComputerName = 29;

    /// <summary>
    /// MS-WKST: NetrEnumerateComputerNames
    /// </summary>
    public const ushort NetrEnumerateComputerNames = 30;

    #endregion // MS-WKST
    #region MS-DSSP

    /// <summary>
    /// MS-DSSP: DsRolerGetPrimaryDomainInformation
    /// </summary>
    public const ushort DsRolerGetPrimaryDomainInformation = 0;

    #endregion // MS-DSSP
    #region MS-EVEN6

    /// <summary>
    /// MS-EVEN6: EvtRpcRegisterRemoteSubscription
    /// </summary>
    public const ushort EvtRpcRegisterRemoteSubscription = 0;

    /// <summary>
    /// MS-EVEN6: EvtRpcRemoteSubscriptionNextAsync
    /// </summary>
    public const ushort EvtRpcRemoteSubscriptionNextAsync = 1;

    /// <summary>
    /// MS-EVEN6: EvtRpcRemoteSubscriptionNext
    /// </summary>
    public const ushort EvtRpcRemoteSubscriptionNext = 2;

    /// <summary>
    /// MS-EVEN6: EvtRpcRemoteSubscriptionWaitAsync
    /// </summary>
    public const ushort EvtRpcRemoteSubscriptionWaitAsync = 3;

    /// <summary>
    /// MS-EVEN6: EvtRpcRegisterControllableOperation
    /// </summary>
    public const ushort EvtRpcRegisterControllableOperation = 4;

    /// <summary>
    /// MS-EVEN6: EvtRpcRegisterLogQuery
    /// </summary>
    public const ushort EvtRpcRegisterLogQuery = 5;

    /// <summary>
    /// MS-EVEN6: EvtRpcClearLog
    /// </summary>
    public const ushort EvtRpcClearLog = 6;

    /// <summary>
    /// MS-EVEN6: EvtRpcExportLog
    /// </summary>
    public const ushort EvtRpcExportLog = 7;

    /// <summary>
    /// MS-EVEN6: EvtRpcLocalizeExportLog
    /// </summary>
    public const ushort EvtRpcLocalizeExportLog = 8;

    /// <summary>
    /// MS-EVEN6: EvtRpcMessageRender
    /// </summary>
    public const ushort EvtRpcMessageRender = 9;

    /// <summary>
    /// MS-EVEN6: EvtRpcMessageRenderDefault
    /// </summary>
    public const ushort EvtRpcMessageRenderDefault = 10;

    /// <summary>
    /// MS-EVEN6: EvtRpcQueryNext
    /// </summary>
    public const ushort EvtRpcQueryNext = 11;

    /// <summary>
    /// MS-EVEN6: EvtRpcQuerySeek
    /// </summary>
    public const ushort EvtRpcQuerySeek = 12;

    /// <summary>
    /// MS-EVEN6: EvtRpcClose
    /// </summary>
    public const ushort EvtRpcClose = 13;

    /// <summary>
    /// MS-EVEN6: EvtRpcCancel
    /// </summary>
    public const ushort EvtRpcCancel = 14;

    /// <summary>
    /// MS-EVEN6: EvtRpcAssertConfig
    /// </summary>
    public const ushort EvtRpcAssertConfig = 15;

    /// <summary>
    /// MS-EVEN6: EvtRpcRetractConfig
    /// </summary>
    public const ushort EvtRpcRetractConfig = 16;

    /// <summary>
    /// MS-EVEN6: EvtRpcOpenLogHandle
    /// </summary>
    public const ushort EvtRpcOpenLogHandle = 17;

    /// <summary>
    /// MS-EVEN6: EvtRpcGetLogFileInfo
    /// </summary>
    public const ushort EvtRpcGetLogFileInfo = 18;

    /// <summary>
    /// MS-EVEN6: EvtRpcGetChannelList
    /// </summary>
    public const ushort EvtRpcGetChannelList = 19;

    /// <summary>
    /// MS-EVEN6: EvtRpcGetChannelConfig
    /// </summary>
    public const ushort EvtRpcGetChannelConfig = 20;

    /// <summary>
    /// MS-EVEN6: EvtRpcPutChannelConfig
    /// </summary>
    public const ushort EvtRpcPutChannelConfig = 21;

    /// <summary>
    /// MS-EVEN6: EvtRpcGetPublisherList
    /// </summary>
    public const ushort EvtRpcGetPublisherList = 22;

    /// <summary>
    /// MS-EVEN6: EvtRpcGetPublisherListForChannel
    /// </summary>
    public const ushort EvtRpcGetPublisherListForChannel = 23;

    /// <summary>
    /// MS-EVEN6: EvtRpcGetPublisherMetadata
    /// </summary>
    public const ushort EvtRpcGetPublisherMetadata = 24;

    /// <summary>
    /// MS-EVEN6: EvtRpcGetPublisherResourceMetadata
    /// </summary>
    public const ushort EvtRpcGetPublisherResourceMetadata = 25;

    /// <summary>
    /// MS-EVEN6: EvtRpcGetEventMetadataEnum
    /// </summary>
    public const ushort EvtRpcGetEventMetadataEnum = 26;

    /// <summary>
    /// MS-EVEN6: EvtRpcGetNextEventMetadata
    /// </summary>
    public const ushort EvtRpcGetNextEventMetadata = 27;

    /// <summary>
    /// MS-EVEN6: EvtRpcGetClassicLogDisplayName
    /// </summary>
    public const ushort EvtRpcGetClassicLogDisplayName = 28;

    #endregion // MS-EVEN6
    #region MS-TSCH (ATSvc)

    /// <summary>
    /// MS-TSCH (ATSvc): NetrJobAdd - Adds a single AT task to the server's task store.
    /// </summary>
    public const ushort NetrJobAdd = 0;

    /// <summary>
    /// MS-TSCH (ATSvc): NetrJobDel - Deletes a specified range of tasks from the task store.
    /// </summary>
    public const ushort NetrJobDel = 1;

    /// <summary>
    /// MS-TSCH (ATSvc): NetrJobEnum - Returns an enumeration of all AT tasks on the specified server.
    /// </summary>
    public const ushort NetrJobEnum = 2;

    /// <summary>
    /// MS-TSCH (ATSvc): NetrJobGetInfo - Returns information for a specified ATSvc task.
    /// </summary>
    public const ushort NetrJobGetInfo = 3;

    #endregion // MS-TSCH (ATSvc)
    #region MS-TSCH (SASec)

    /// <summary>
    /// MS-TSCH (SASec): SASetAccountInformation - Sets the credentials under which the task MUST run.
    /// </summary>
    public const ushort SASetAccountInformation = 0;

    /// <summary>
    /// MS-TSCH (SASec): SASetNSAccountInformation - Configures the credentials under which all ATSvc tasks run.
    /// </summary>
    public const ushort SASetNSAccountInformation = 1;

    /// <summary>
    /// MS-TSCH (SASec): SAGetNSAccountInformation - Returns the ATSvc account name.
    /// </summary>
    public const ushort SAGetNSAccountInformation = 2;

    /// <summary>
    /// MS-TSCH (SASec): SAGetAccountInformation - Retrieves the account name for a specified task.
    /// </summary>
    public const ushort SAGetAccountInformation = 3;

    #endregion // MS-TSCH (SASec)
    #region MS-TSCH (ITaskSchedulerService)

    /// <summary>
    /// MS-TSCH (ITaskSchedulerService): SchRpcHighestVersion - Returns the highest version of the Task Scheduler Remoting Protocol supported by the server.
    /// </summary>
    public const ushort SchRpcHighestVersion = 0;

    /// <summary>
    /// MS-TSCH (ITaskSchedulerService): SchRpcRegisterTask - Registers a task with the server.
    /// </summary>
    public const ushort SchRpcRegisterTask = 1;

    /// <summary>
    /// MS-TSCH (ITaskSchedulerService): SchRpcRetrieveTask - Returns a task definition.
    /// </summary>
    public const ushort SchRpcRetrieveTask = 2;

    /// <summary>
    /// MS-TSCH (ITaskSchedulerService): SchRpcCreateFolder - Creates a new folder.
    /// </summary>
    public const ushort SchRpcCreateFolder = 3;

    /// <summary>
    /// MS-TSCH (ITaskSchedulerService): SchRpcSetSecurity - Sets a security descriptor on a task or folder.
    /// </summary>
    public const ushort SchRpcSetSecurity = 4;

    /// <summary>
    /// MS-TSCH (ITaskSchedulerService): SchRpcGetSecurity - Gets the security descriptor associated with a task or folder.
    /// </summary>
    public const ushort SchRpcGetSecurity = 5;

    /// <summary>
    /// MS-TSCH (ITaskSchedulerService): SchRpcEnumFolders - Retrieves a list of folders on the server.
    /// </summary>
    public const ushort SchRpcEnumFolders = 6;

    /// <summary>
    /// MS-TSCH (ITaskSchedulerService): SchRpcEnumTasks - Returns the list of tasks in a specific folder.
    /// </summary>
    public const ushort SchRpcEnumTasks = 7;

    /// <summary>
    /// MS-TSCH (ITaskSchedulerService): SchRpcEnumInstances - Returns a list of instances of a specified task that are currently running.
    /// </summary>
    public const ushort SchRpcEnumInstances = 8;

    /// <summary>
    /// MS-TSCH (ITaskSchedulerService): SchRpcGetInstanceInfo - Gets information about an instance of a running task.
    /// </summary>
    public const ushort SchRpcGetInstanceInfo = 9;

    /// <summary>
    /// MS-TSCH (ITaskSchedulerService): SchRpcStopInstance - Stops a specified instance of a task.
    /// </summary>
    public const ushort SchRpcStopInstance = 10;

    /// <summary>
    /// MS-TSCH (ITaskSchedulerService): SchRpcStop - Stops all currently running instances of a task specified by a path.
    /// </summary>
    public const ushort SchRpcStop = 11;

    /// <summary>
    /// MS-TSCH (ITaskSchedulerService): SchRpcRun - Runs a task specified by a path.
    /// </summary>
    public const ushort SchRpcRun = 12;

    /// <summary>
    /// MS-TSCH (ITaskSchedulerService): SchRpcDelete - Deletes a task or folder in the task store.
    /// </summary>
    public const ushort SchRpcDelete = 13;

    /// <summary>
    /// MS-TSCH (ITaskSchedulerService): SchRpcRename - Unused.
    /// </summary>
    public const ushort SchRpcRename = 14;

    /// <summary>
    /// MS-TSCH (ITaskSchedulerService): SchRpcScheduledRuntimes - Returns scheduled run times.
    /// </summary>
    public const ushort SchRpcScheduledRuntimes = 15;

    /// <summary>
    /// MS-TSCH (ITaskSchedulerService): SchRpcGetLastRunInfo - Returns information about the task's last run.
    /// </summary>
    public const ushort SchRpcGetLastRunInfo = 16;

    /// <summary>
    /// MS-TSCH (ITaskSchedulerService): SchRpcGetTaskInfo - Returns information about a specified task.
    /// </summary>
    public const ushort SchRpcGetTaskInfo = 17;

    /// <summary>
    /// MS-TSCH (ITaskSchedulerService): SchRpcGetNumberOfMissedRuns - Returns the number of times a task was scheduled to run but did not due to the server being unavailable.
    /// </summary>
    public const ushort SchRpcGetNumberOfMissedRuns = 18;

    /// <summary>
    /// MS-TSCH (ITaskSchedulerService): SchRpcEnableTask - Enables or disables a task.
    /// </summary>
    public const ushort SchRpcEnableTask = 19;

    #endregion // MS-TSCH (ITaskSchedulerService)
    #region MS-SRVS

    /// <summary>
    /// MS-SRVS: Opnum0NotUsedOnWire (Returns ERROR_NOT_SUPPORTED)
    /// </summary>
    public const ushort SRVS_Opnum0NotUsedOnWire = 0;

    /// <summary>
    /// MS-SRVS: Opnum1NotUsedOnWire (Returns ERROR_NOT_SUPPORTED)
    /// </summary>
    public const ushort SRVS_Opnum1NotUsedOnWire = 1;

    /// <summary>
    /// MS-SRVS: Opnum2NotUsedOnWire (Returns ERROR_NOT_SUPPORTED)
    /// </summary>
    public const ushort SRVS_Opnum2NotUsedOnWire = 2;

    /// <summary>
    /// MS-SRVS: Opnum3NotUsedOnWire (Returns ERROR_NOT_SUPPORTED)
    /// </summary>
    public const ushort SRVS_Opnum3NotUsedOnWire = 3;

    /// <summary>
    /// MS-SRVS: Opnum4NotUsedOnWire (Returns ERROR_NOT_SUPPORTED)
    /// </summary>
    public const ushort SRVS_Opnum4NotUsedOnWire = 4;

    /// <summary>
    /// MS-SRVS: Opnum5NotUsedOnWire (Returns ERROR_NOT_SUPPORTED)
    /// </summary>
    public const ushort SRVS_Opnum5NotUsedOnWire = 5;

    /// <summary>
    /// MS-SRVS: Opnum6NotUsedOnWire (Returns ERROR_NOT_SUPPORTED)
    /// </summary>
    public const ushort SRVS_Opnum6NotUsedOnWire = 6;

    /// <summary>
    /// MS-SRVS: Opnum7NotUsedOnWire (Returns ERROR_NOT_SUPPORTED)
    /// </summary>
    public const ushort SRVS_Opnum7NotUsedOnWire = 7;

    /// <summary>
    /// MS-SRVS: NetrConnectionEnum - Lists all connections made to a shared resource on the server.
    /// </summary>
    public const ushort NetrConnectionEnum = 8;

    /// <summary>
    /// MS-SRVS: NetrFileEnum - Returns information about some or all open files on a server.
    /// </summary>
    public const ushort NetrFileEnum = 9;

    /// <summary>
    /// MS-SRVS: NetrFileGetInfo
    /// </summary>
    public const ushort NetrFileGetInfo = 10;

    /// <summary>
    /// MS-SRVS: NetrFileClose
    /// </summary>
    public const ushort NetrFileClose = 11;

    /// <summary>
    /// MS-SRVS: NetrSessionEnum - Provides information about sessions that are established on a server.
    /// </summary>
    public const ushort NetrSessionEnum = 12;

    /// <summary>
    /// MS-SRVS: NetrSessionDel
    /// </summary>
    public const ushort NetrSessionDel = 13;

    /// <summary>
    /// MS-SRVS: NetrShareAdd
    /// </summary>
    public const ushort NetrShareAdd = 14;

    /// <summary>
    /// MS-SRVS: NetrShareEnum - Retrieves information about each shared resource on a server.
    /// </summary>
    public const ushort NetrShareEnum = 15;

    /// <summary>
    /// MS-SRVS: NetrShareGetInfo
    /// </summary>
    public const ushort NetrShareGetInfo = 16;

    /// <summary>
    /// MS-SRVS: NetrShareSetInfo
    /// </summary>
    public const ushort NetrShareSetInfo = 17;

    /// <summary>
    /// MS-SRVS: NetrShareDel
    /// </summary>
    public const ushort NetrShareDel = 18;

    /// <summary>
    /// MS-SRVS: NetrShareDelSticky
    /// </summary>
    public const ushort NetrShareDelSticky = 19;

    /// <summary>
    /// MS-SRVS: NetrShareCheck
    /// </summary>
    public const ushort NetrShareCheck = 20;

    /// <summary>
    /// MS-SRVS: NetrServerGetInfo - Retrieves current configuration information for the specified server.
    /// </summary>
    public const ushort NetrServerGetInfo = 21;

    /// <summary>
    /// MS-SRVS: NetrServerSetInfo
    /// </summary>
    public const ushort NetrServerSetInfo = 22;

    /// <summary>
    /// MS-SRVS: NetrServerDiskEnum
    /// </summary>
    public const ushort NetrServerDiskEnum = 23;

    /// <summary>
    /// MS-SRVS: NetrServerStatisticsGet
    /// </summary>
    public const ushort NetrServerStatisticsGet = 24;

    /// <summary>
    /// MS-SRVS: NetrServerTransportAdd
    /// </summary>
    public const ushort NetrServerTransportAdd = 25;

    /// <summary>
    /// MS-SRVS: NetrServerTransportEnum
    /// </summary>
    public const ushort NetrServerTransportEnum = 26;

    /// <summary>
    /// MS-SRVS: NetrServerTransportDel
    /// </summary>
    public const ushort NetrServerTransportDel = 27;

    /// <summary>
    /// MS-SRVS: NetrRemoteTOD
    /// </summary>
    public const ushort NetrRemoteTOD = 28;

    /// <summary>
    /// MS-SRVS: Opnum29NotUsedOnWire (Only used locally, never remotely)
    /// </summary>
    public const ushort SRVS_Opnum29NotUsedOnWire = 29;

    /// <summary>
    /// MS-SRVS: NetprPathType
    /// </summary>
    public const ushort NetprPathType = 30;

    /// <summary>
    /// MS-SRVS: NetprPathCanonicalize
    /// </summary>
    public const ushort NetprPathCanonicalize = 31;

    /// <summary>
    /// MS-SRVS: NetprPathCompare
    /// </summary>
    public const ushort NetprPathCompare = 32;

    /// <summary>
    /// MS-SRVS: NetprNameValidate
    /// </summary>
    public const ushort NetprNameValidate = 33;

    /// <summary>
    /// MS-SRVS: NetprNameCanonicalize
    /// </summary>
    public const ushort NetprNameCanonicalize = 34;

    /// <summary>
    /// MS-SRVS: NetprNameCompare
    /// </summary>
    public const ushort NetprNameCompare = 35;

    /// <summary>
    /// MS-SRVS: NetrShareEnumSticky
    /// </summary>
    public const ushort NetrShareEnumSticky = 36;

    /// <summary>
    /// MS-SRVS: NetrShareDelStart
    /// </summary>
    public const ushort NetrShareDelStart = 37;

    /// <summary>
    /// MS-SRVS: NetrShareDelCommit
    /// </summary>
    public const ushort NetrShareDelCommit = 38;

    /// <summary>
    /// MS-SRVS: NetrpGetFileSecurity
    /// </summary>
    public const ushort NetrpGetFileSecurity = 39;

    /// <summary>
    /// MS-SRVS: NetrpSetFileSecurity
    /// </summary>
    public const ushort NetrpSetFileSecurity = 40;

    /// <summary>
    /// MS-SRVS: NetrServerTransportAddEx
    /// </summary>
    public const ushort NetrServerTransportAddEx = 41;

    /// <summary>
    /// MS-SRVS: Opnum42NotUsedOnWire (Only used locally, never remotely)
    /// </summary>
    public const ushort SRVS_Opnum42NotUsedOnWire = 42;

    /// <summary>
    /// MS-SRVS: NetrDfsGetVersion
    /// </summary>
    public const ushort NetrDfsGetVersion = 43;

    /// <summary>
    /// MS-SRVS: NetrDfsCreateLocalPartition
    /// </summary>
    public const ushort NetrDfsCreateLocalPartition = 44;

    /// <summary>
    /// MS-SRVS: NetrDfsDeleteLocalPartition
    /// </summary>
    public const ushort NetrDfsDeleteLocalPartition = 45;

    /// <summary>
    /// MS-SRVS: NetrDfsSetLocalVolumeState
    /// </summary>
    public const ushort NetrDfsSetLocalVolumeState = 46;

    /// <summary>
    /// MS-SRVS: Opnum47NotUsedOnWire (Unsupported and not defined)
    /// </summary>
    public const ushort SRVS_Opnum47NotUsedOnWire = 47;

    /// <summary>
    /// MS-SRVS: NetrDfsCreateExitPoint
    /// </summary>
    public const ushort NetrDfsCreateExitPoint = 48;

    /// <summary>
    /// MS-SRVS: NetrDfsDeleteExitPoint
    /// </summary>
    public const ushort NetrDfsDeleteExitPoint = 49;

    /// <summary>
    /// MS-SRVS: NetrDfsModifyPrefix
    /// </summary>
    public const ushort NetrDfsModifyPrefix = 50;

    /// <summary>
    /// MS-SRVS: NetrDfsFixLocalVolume
    /// </summary>
    public const ushort NetrDfsFixLocalVolume = 51;

    /// <summary>
    /// MS-SRVS: NetrDfsManagerReportSiteInfo
    /// </summary>
    public const ushort NetrDfsManagerReportSiteInfo = 52;

    /// <summary>
    /// MS-SRVS: NetrServerTransportDelEx
    /// </summary>
    public const ushort NetrServerTransportDelEx = 53;

    /// <summary>
    /// MS-SRVS: NetrServerAliasAdd
    /// </summary>
    public const ushort NetrServerAliasAdd = 54;

    /// <summary>
    /// MS-SRVS: NetrServerAliasEnum
    /// </summary>
    public const ushort NetrServerAliasEnum = 55;

    /// <summary>
    /// MS-SRVS: NetrServerAliasDel
    /// </summary>
    public const ushort NetrServerAliasDel = 56;

    /// <summary>
    /// MS-SRVS: NetrShareDelEx
    /// </summary>
    public const ushort NetrShareDelEx = 57;

    #endregion // MS-SRVS
    #region MS-DCOM

    #region MS-DCOM (IUnknown)

    /// <summary>
    /// MS-DCOM (IUnknown): QueryInterface - Reserved for local use
    /// </summary>
    public const ushort IUnknown_QueryInterface = 0;

    /// <summary>
    /// MS-DCOM (IUnknown): AddRef - Reserved for local use
    /// </summary>
    public const ushort IUnknown_AddRef = 1;

    /// <summary>
    /// MS-DCOM (IUnknown): Release - Reserved for local use
    /// </summary>
    public const ushort IUnknown_Release = 2;

    #endregion // MS-DCOM (IUnknown)
    #region MS-DCOM (IRemUnknown/IRemUnknown2)

    /// <summary>
    /// MS-DCOM: RemQueryInterface
    /// </summary>
    public const ushort RemQueryInterface = 3;

    /// <summary>
    /// MS-DCOM: RemAddRef
    /// </summary>
    public const ushort RemAddRef = 4;

    /// <summary>
    /// MS-DCOM: RemRelease
    /// </summary>
    public const ushort RemRelease = 5;

    /// <summary>
    /// MS-DCOM: RemQueryInterface2 (IRemUnknown2 only)
    /// </summary>
    public const ushort RemQueryInterface2 = 6;

    #endregion // MS-DCOM (IRemUnknown/IRemUnknown2)
    #endregion // MS-DCOM
    #region MS-WMI

    /// <summary>
    /// MS-WMI (IWbemLevel1Login): EstablishPosition
    /// </summary>
    public const ushort EstablishPosition = 3;

    /// <summary>
    /// MS-WMI (IWbemLevel1Login): RequestChallenge
    /// </summary>
    public const ushort RequestChallenge = 4;

    /// <summary>
    /// MS-WMI (IWbemLevel1Login): WBEMLogin
    /// </summary>
    public const ushort WBEMLogin = 5;

    /// <summary>
    /// MS-WMI (IWbemLevel1Login): NTLMLogin
    /// </summary>
    public const ushort NTLMLogin = 6;

    /// <summary>
    /// MS-WMI (IWbemLoginClientID): SetClientInfo
    /// </summary>
    public const ushort SetClientInfo = 3;

    /// <summary>
    /// MS-WMI (IWbemServices): OpenNamespace
    /// </summary>
    public const ushort OpenNamespace = 3;

    /// <summary>
    /// MS-WMI (IWbemServices): CancelAsyncCall
    /// </summary>
    public const ushort CancelAsyncCall = 4;

    /// <summary>
    /// MS-WMI (IWbemServices): QueryObjectSink
    /// </summary>
    public const ushort QueryObjectSink = 5;

    /// <summary>
    /// MS-WMI (IWbemServices): GetObject
    /// </summary>
    public const ushort GetObject = 6;

    /// <summary>
    /// MS-WMI (IWbemServices): GetObjectAsync
    /// </summary>
    public const ushort GetObjectAsync = 7;

    /// <summary>
    /// MS-WMI (IWbemServices): PutClass
    /// </summary>
    public const ushort PutClass = 8;

    /// <summary>
    /// MS-WMI (IWbemServices): PutClassAsync
    /// </summary>
    public const ushort PutClassAsync = 9;

    /// <summary>
    /// MS-WMI (IWbemServices): DeleteClass
    /// </summary>
    public const ushort DeleteClass = 10;

    /// <summary>
    /// MS-WMI (IWbemServices): DeleteClassAsync
    /// </summary>
    public const ushort DeleteClassAsync = 11;

    /// <summary>
    /// MS-WMI (IWbemServices): CreateClassEnum
    /// </summary>
    public const ushort CreateClassEnum = 12;

    /// <summary>
    /// MS-WMI (IWbemServices): CreateClassEnumAsync
    /// </summary>
    public const ushort CreateClassEnumAsync = 13;

    /// <summary>
    /// MS-WMI (IWbemServices): PutInstance
    /// </summary>
    public const ushort PutInstance = 14;

    /// <summary>
    /// MS-WMI (IWbemServices): PutInstanceAsync
    /// </summary>
    public const ushort PutInstanceAsync = 15;

    /// <summary>
    /// MS-WMI (IWbemServices): DeleteInstance
    /// </summary>
    public const ushort DeleteInstance = 16;

    /// <summary>
    /// MS-WMI (IWbemServices): DeleteInstanceAsync
    /// </summary>
    public const ushort DeleteInstanceAsync = 17;

    /// <summary>
    /// MS-WMI (IWbemServices): CreateInstanceEnum
    /// </summary>
    public const ushort CreateInstanceEnum = 18;

    /// <summary>
    /// MS-WMI (IWbemServices): CreateInstanceEnumAsync
    /// </summary>
    public const ushort CreateInstanceEnumAsync = 19;

    /// <summary>
    /// MS-WMI (IWbemServices): ExecQuery
    /// </summary>
    public const ushort ExecQuery = 20;

    /// <summary>
    /// MS-WMI (IWbemServices): ExecQueryAsync
    /// </summary>
    public const ushort ExecQueryAsync = 21;

    /// <summary>
    /// MS-WMI (IWbemServices): ExecNotificationQuery
    /// </summary>
    public const ushort ExecNotificationQuery = 22;

    /// <summary>
    /// MS-WMI (IWbemServices): ExecNotificationQueryAsync
    /// </summary>
    public const ushort ExecNotificationQueryAsync = 23;

    /// <summary>
    /// MS-WMI (IWbemServices): ExecMethod
    /// </summary>
    public const ushort ExecMethod = 24;

    /// <summary>
    /// MS-WMI (IWbemServices): ExecMethodAsync
    /// </summary>
    public const ushort ExecMethodAsync = 25;

    /// <summary>
    /// MS-WMI (IWbemFetchSmartEnum): GetSmartEnum
    /// </summary>
    public const ushort GetSmartEnum = 3;

    /// <summary>
    /// MS-WMI (IWbemWCOSmartEnum): Next
    /// </summary>
    public const ushort Next = 3;

    /// <summary>
    /// MS-WMI (IWbemLoginHelper): SetEvent
    /// </summary>
    public const ushort SetEvent = 3;

    /// <summary>
    /// MS-WMI (IWbemObjectSink): Indicate
    /// </summary>
    public const ushort Indicate = 3;

    /// <summary>
    /// MS-WMI (IWbemObjectSink): SetStatus
    /// </summary>
    public const ushort SetStatus = 4;

    /// <summary>
    /// MS-WMI (IEnumWbemClassObject): Reset
    /// </summary>
    public const ushort Reset = 3;

    /// <summary>
    /// MS-WMI (IEnumWbemClassObject): Next
    /// </summary>
    public const ushort EnumNext = 4;

    /// <summary>
    /// MS-WMI (IEnumWbemClassObject): NextAsync
    /// </summary>
    public const ushort NextAsync = 5;

    /// <summary>
    /// MS-WMI (IEnumWbemClassObject): Clone
    /// </summary>
    public const ushort Clone = 6;

    /// <summary>
    /// MS-WMI (IEnumWbemClassObject): Skip
    /// </summary>
    public const ushort Skip = 7;

    /// <summary>
    /// MS-WMI (IWbemCallResult): GetResultObject
    /// </summary>
    public const ushort GetResultObject = 3;

    /// <summary>
    /// MS-WMI (IWbemCallResult): GetResultString
    /// </summary>
    public const ushort GetResultString = 4;

    /// <summary>
    /// MS-WMI (IWbemCallResult): GetResultServices
    /// </summary>
    public const ushort GetResultServices = 5;

    /// <summary>
    /// MS-WMI (IWbemCallResult): GetCallStatus
    /// </summary>
    public const ushort GetCallStatus = 6;

    /// <summary>
    /// MS-WMI (IWbemBackupRestore): Backup
    /// </summary>
    public const ushort Backup = 3;

    /// <summary>
    /// MS-WMI (IWbemBackupRestore): Restore
    /// </summary>
    public const ushort Restore = 4;

    /// <summary>
    /// MS-WMI (IWbemBackupRestoreEx): Pause
    /// </summary>
    public const ushort Pause = 5;

    /// <summary>
    /// MS-WMI (IWbemBackupRestoreEx): Resume
    /// </summary>
    public const ushort Resume = 6;

    /// <summary>
    /// MS-WMI (IWbemRefreshingServices): AddObjectToRefresher
    /// </summary>
    public const ushort AddObjectToRefresher = 3;

    /// <summary>
    /// MS-WMI (IWbemRefreshingServices): AddObjectToRefresherByTemplate
    /// </summary>
    public const ushort AddObjectToRefresherByTemplate = 4;

    /// <summary>
    /// MS-WMI (IWbemRefreshingServices): AddEnumToRefresher
    /// </summary>
    public const ushort AddEnumToRefresher = 5;

    /// <summary>
    /// MS-WMI (IWbemRefreshingServices): RemoveObjectFromRefresher
    /// </summary>
    public const ushort RemoveObjectFromRefresher = 6;

    /// <summary>
    /// MS-WMI (IWbemRefreshingServices): GetRemoteRefresher
    /// </summary>
    public const ushort GetRemoteRefresher = 7;

    /// <summary>
    /// MS-WMI (IWbemRefreshingServices): ReconnectRemoteRefresher
    /// </summary>
    public const ushort ReconnectRemoteRefresher = 8;

    /// <summary>
    /// MS-WMI (IWbemRemoteRefresher): RemoteRefresh
    /// </summary>
    public const ushort RemoteRefresh = 3;

    /// <summary>
    /// MS-WMI (IWbemRemoteRefresher): StopRefreshing
    /// </summary>
    public const ushort StopRefreshing = 4;

    /// <summary>
    /// MS-WMI (IWbemRemoteRefresher): Opnum5NotUsedOnWire
    /// </summary>
    public const ushort WMI_Opnum5NotUsedOnWire = 5;

    /// <summary>
    /// MS-WMI (IWbemShutdown): Shutdown
    /// </summary>
    public const ushort Shutdown = 3;

    /// <summary>
    /// MS-WMI (IUnsecuredApartment): CreateObjectStub
    /// </summary>
    public const ushort CreateObjectStub = 3;

    /// <summary>
    /// MS-WMI (IWbemUnsecuredApartment): CreateSinkStub
    /// </summary>
    public const ushort CreateSinkStub = 3;

    #endregion // MS-WMI
    #region MS-WCCE

    /// <summary>
    /// MS-WCCE (ICertRequestD): Request - Initiates the certificate issuance process
    /// </summary>
    public const ushort Request = 3;

    /// <summary>
    /// MS-WCCE (ICertRequestD): GetCACert - Returns property values on the CA
    /// </summary>
    public const ushort GetCACert = 4;

    /// <summary>
    /// MS-WCCE (ICertRequestD): Ping - Performs a request response test (ping) to the CA
    /// </summary>
    public const ushort WCCE_Ping = 5;

    /// <summary>
    /// MS-WCCE (ICertRequestD2): Request2 - Requests a certificate from the CA
    /// </summary>
    public const ushort Request2 = 6;

    /// <summary>
    /// MS-WCCE (ICertRequestD2): GetCAProperty - Retrieves a property value from the CA
    /// </summary>
    public const ushort GetCAProperty = 7;

    /// <summary>
    /// MS-WCCE (ICertRequestD2): GetCAPropertyInfo - Retrieves a set of property structures from the CA
    /// </summary>
    public const ushort GetCAPropertyInfo = 8;

    /// <summary>
    /// MS-WCCE (ICertRequestD2): Ping2 - Pings the CA
    /// </summary>
    public const ushort WCCE_Ping2 = 9;

    #endregion // MS-WCCE
    #region MS-CSRA

    /// <summary>
    /// MS-CSRA (ICertAdminD): SetExtension - Sets extensions for a specific request
    /// </summary>
    public const ushort ICertAdminD_SetExtension = 3;

    /// <summary>
    /// MS-CSRA (ICertAdminD): SetAttributes - Sets attributes for a specific request
    /// </summary>
    public const ushort ICertAdminD_SetAttributes = 4;

    /// <summary>
    /// MS-CSRA (ICertAdminD): ResubmitRequest - Resubmits a specific pending or denied request
    /// </summary>
    public const ushort ICertAdminD_ResubmitRequest = 5;

    /// <summary>
    /// MS-CSRA (ICertAdminD): DenyRequest - Denies a pending certificate request
    /// </summary>
    public const ushort ICertAdminD_DenyRequest = 6;

    /// <summary>
    /// MS-CSRA (ICertAdminD): IsValidCertificate - Verifies the certificate against the CA key
    /// </summary>
    public const ushort ICertAdminD_IsValidCertificate = 7;

    /// <summary>
    /// MS-CSRA (ICertAdminD): PublishCRL - Instructs a CA to publish a CRL
    /// </summary>
    public const ushort ICertAdminD_PublishCRL = 8;

    /// <summary>
    /// MS-CSRA (ICertAdminD): GetCRL - Retrieves the latest base or delta CRL
    /// </summary>
    public const ushort ICertAdminD_GetCRL = 9;

    /// <summary>
    /// MS-CSRA (ICertAdminD): RevokeCertificate - Revokes a certificate
    /// </summary>
    public const ushort ICertAdminD_RevokeCertificate = 10;

    /// <summary>
    /// MS-CSRA (ICertAdminD): EnumViewColumn - Enumerates the columns in a schema
    /// </summary>
    public const ushort ICertAdminD_EnumViewColumn = 11;

    /// <summary>
    /// MS-CSRA (ICertAdminD): GetViewDefaultColumnSet - Retrieves the default column set
    /// </summary>
    public const ushort ICertAdminD_GetViewDefaultColumnSet = 12;

    /// <summary>
    /// MS-CSRA (ICertAdminD): EnumAttributesOrExtensions - Enumerates attributes or extensions
    /// </summary>
    public const ushort ICertAdminD_EnumAttributesOrExtensions = 13;

    /// <summary>
    /// MS-CSRA (ICertAdminD): OpenView - Opens a view into the CA database
    /// </summary>
    public const ushort ICertAdminD_OpenView = 14;

    /// <summary>
    /// MS-CSRA (ICertAdminD): EnumView - Enumerates an open view
    /// </summary>
    public const ushort ICertAdminD_EnumView = 15;

    /// <summary>
    /// MS-CSRA (ICertAdminD): CloseView - Closes an open view
    /// </summary>
    public const ushort ICertAdminD_CloseView = 16;

    /// <summary>
    /// MS-CSRA (ICertAdminD): ServerControl - Controls the CA server
    /// </summary>
    public const ushort ICertAdminD_ServerControl = 17;

    /// <summary>
    /// MS-CSRA (ICertAdminD): Ping - Performs a request response test to the CA
    /// </summary>
    public const ushort ICertAdminD_Ping = 18;

    /// <summary>
    /// MS-CSRA (ICertAdminD): GetServerState - Retrieves the server state
    /// </summary>
    public const ushort ICertAdminD_GetServerState = 19;

    /// <summary>
    /// MS-CSRA (ICertAdminD): BackupPrepare - Prepares a CA database backup
    /// </summary>
    public const ushort ICertAdminD_BackupPrepare = 20;

    /// <summary>
    /// MS-CSRA (ICertAdminD): BackupEnd - Ends a CA database backup
    /// </summary>
    public const ushort ICertAdminD_BackupEnd = 21;

    /// <summary>
    /// MS-CSRA (ICertAdminD): BackupGetAttachmentInformation - Returns backup attachment information
    /// </summary>
    public const ushort ICertAdminD_BackupGetAttachmentInformation = 22;

    /// <summary>
    /// MS-CSRA (ICertAdminD): BackupGetBackupLogs - Returns backup log information
    /// </summary>
    public const ushort ICertAdminD_BackupGetBackupLogs = 23;

    /// <summary>
    /// MS-CSRA (ICertAdminD): BackupOpenFile - Opens a backup file for read
    /// </summary>
    public const ushort ICertAdminD_BackupOpenFile = 24;

    /// <summary>
    /// MS-CSRA (ICertAdminD): BackupReadFile - Reads data from an open backup file
    /// </summary>
    public const ushort ICertAdminD_BackupReadFile = 25;

    /// <summary>
    /// MS-CSRA (ICertAdminD): BackupCloseFile - Closes an open backup file
    /// </summary>
    public const ushort ICertAdminD_BackupCloseFile = 26;

    /// <summary>
    /// MS-CSRA (ICertAdminD): BackupTruncateLogs - Truncates CA database backup logs
    /// </summary>
    public const ushort ICertAdminD_BackupTruncateLogs = 27;

    /// <summary>
    /// MS-CSRA (ICertAdminD): ImportCertificate - Imports a certificate into the CA database
    /// </summary>
    public const ushort ICertAdminD_ImportCertificate = 28;

    /// <summary>
    /// MS-CSRA (ICertAdminD): BackupGetDynamicFiles - Returns dynamic file names for backup
    /// </summary>
    public const ushort ICertAdminD_BackupGetDynamicFiles = 29;

    /// <summary>
    /// MS-CSRA (ICertAdminD): RestoreGetDatabaseLocations - Returns database restore locations
    /// </summary>
    public const ushort ICertAdminD_RestoreGetDatabaseLocations = 30;

    /// <summary>
    /// MS-CSRA (ICertAdminD2): PublishCRLs - Instructs a CA to publish CRLs and delta CRLs
    /// </summary>
    public const ushort ICertAdminD2_PublishCRLs = 31;

    /// <summary>
    /// MS-CSRA (ICertAdminD2): GetCAProperty - Retrieves a property value from the CA
    /// </summary>
    public const ushort ICertAdminD2_GetCAProperty = 32;

    /// <summary>
    /// MS-CSRA (ICertAdminD2): SetCAProperty - Sets a property value on the CA
    /// </summary>
    public const ushort ICertAdminD2_SetCAProperty = 33;

    /// <summary>
    /// MS-CSRA (ICertAdminD2): GetCAPropertyInfo - Retrieves CA property information
    /// </summary>
    public const ushort ICertAdminD2_GetCAPropertyInfo = 34;

    /// <summary>
    /// MS-CSRA (ICertAdminD2): EnumViewColumnTable - Enumerates columns in a table view
    /// </summary>
    public const ushort ICertAdminD2_EnumViewColumnTable = 35;

    /// <summary>
    /// MS-CSRA (ICertAdminD2): GetCASecurity - Retrieves CA security descriptor
    /// </summary>
    public const ushort ICertAdminD2_GetCASecurity = 36;

    /// <summary>
    /// MS-CSRA (ICertAdminD2): SetCASecurity - Sets CA security descriptor
    /// </summary>
    public const ushort ICertAdminD2_SetCASecurity = 37;

    /// <summary>
    /// MS-CSRA (ICertAdminD2): Ping2 - Performs a request response test to the CA
    /// </summary>
    public const ushort ICertAdminD2_Ping2 = 38;

    /// <summary>
    /// MS-CSRA (ICertAdminD2): GetArchivedKey - Retrieves archived private key
    /// </summary>
    public const ushort ICertAdminD2_GetArchivedKey = 39;

    /// <summary>
    /// MS-CSRA (ICertAdminD2): GetAuditFilter - Retrieves audit filter settings
    /// </summary>
    public const ushort ICertAdminD2_GetAuditFilter = 40;

    /// <summary>
    /// MS-CSRA (ICertAdminD2): SetAuditFilter - Sets audit filter settings
    /// </summary>
    public const ushort ICertAdminD2_SetAuditFilter = 41;

    /// <summary>
    /// MS-CSRA (ICertAdminD2): GetOfficerRights - Retrieves officer rights
    /// </summary>
    public const ushort ICertAdminD2_GetOfficerRights = 42;

    /// <summary>
    /// MS-CSRA (ICertAdminD2): SetOfficerRights - Sets officer rights
    /// </summary>
    public const ushort ICertAdminD2_SetOfficerRights = 43;

    /// <summary>
    /// MS-CSRA (ICertAdminD2): GetConfigEntry - Retrieves a configuration entry
    /// </summary>
    public const ushort ICertAdminD2_GetConfigEntry = 44;

    /// <summary>
    /// MS-CSRA (ICertAdminD2): SetConfigEntry - Sets a configuration entry
    /// </summary>
    public const ushort ICertAdminD2_SetConfigEntry = 45;

    /// <summary>
    /// MS-CSRA (ICertAdminD2): ImportKey - Imports a key into the CA
    /// </summary>
    public const ushort ICertAdminD2_ImportKey = 46;

    /// <summary>
    /// MS-CSRA (ICertAdminD2): GetMyRoles - Retrieves the caller's roles
    /// </summary>
    public const ushort ICertAdminD2_GetMyRoles = 47;

    /// <summary>
    /// MS-CSRA (ICertAdminD2): DeleteRow - Deletes a row from the CA database
    /// </summary>
    public const ushort ICertAdminD2_DeleteRow = 48;

    #endregion // MS-CSRA
    #region MS-ICPR

    /// <summary>
    /// MS-ICPR (ICertPassage): CertServerRequest - Requests certificate services
    /// </summary>
    public const ushort CertServerRequest = 0;

    #endregion // MS-ICPR
    #region MS-DNSP

    /// <summary>
    /// MS-DNSP (DnsServer): R_DnssrvOperation - Performs DNS server operations
    /// </summary>
    public const ushort R_DnssrvOperation = 0;

    /// <summary>
    /// MS-DNSP (DnsServer): R_DnssrvQuery - Queries DNS server information
    /// </summary>
    public const ushort R_DnssrvQuery = 1;

    /// <summary>
    /// MS-DNSP (DnsServer): R_DnssrvComplexOperation - Performs complex DNS server operations
    /// </summary>
    public const ushort R_DnssrvComplexOperation = 2;

    /// <summary>
    /// MS-DNSP (DnsServer): R_DnssrvEnumRecords - Enumerates DNS records
    /// </summary>
    public const ushort R_DnssrvEnumRecords = 3;

    /// <summary>
    /// MS-DNSP (DnsServer): R_DnssrvUpdateRecord - Updates DNS records
    /// </summary>
    public const ushort R_DnssrvUpdateRecord = 4;

    /// <summary>
    /// MS-DNSP (DnsServer): R_DnssrvOperation2 - Performs DNS server operations (version 2)
    /// </summary>
    public const ushort R_DnssrvOperation2 = 5;

    /// <summary>
    /// MS-DNSP (DnsServer): R_DnssrvQuery2 - Queries DNS server information (version 2)
    /// </summary>
    public const ushort R_DnssrvQuery2 = 6;

    /// <summary>
    /// MS-DNSP (DnsServer): R_DnssrvComplexOperation2 - Performs complex operations (version 2)
    /// </summary>
    public const ushort R_DnssrvComplexOperation2 = 7;

    /// <summary>
    /// MS-DNSP (DnsServer): R_DnssrvEnumRecords2 - Enumerates DNS records (version 2)
    /// </summary>
    public const ushort R_DnssrvEnumRecords2 = 8;

    /// <summary>
    /// MS-DNSP (DnsServer): R_DnssrvUpdateRecord2 - Updates DNS records (version 2)
    /// </summary>
    public const ushort R_DnssrvUpdateRecord2 = 9;

    /// <summary>
    /// MS-DNSP (DnsServer): R_DnssrvUpdateRecord3 - Updates DNS records (version 3)
    /// </summary>
    public const ushort R_DnssrvUpdateRecord3 = 10;

    /// <summary>
    /// MS-DNSP (DnsServer): R_DnssrvEnumRecords3 - Enumerates DNS records (version 3)
    /// </summary>
    public const ushort R_DnssrvEnumRecords3 = 11;

    /// <summary>
    /// MS-DNSP (DnsServer): R_DnssrvOperation3 - Performs DNS server operations (version 3)
    /// </summary>
    public const ushort R_DnssrvOperation3 = 12;

    /// <summary>
    /// MS-DNSP (DnsServer): R_DnssrvQuery3 - Queries DNS server information (version 3)
    /// </summary>
    public const ushort R_DnssrvQuery3 = 13;

    /// <summary>
    /// MS-DNSP (DnsServer): R_DnssrvComplexOperation3 - Performs complex operations (version 3)
    /// </summary>
    public const ushort R_DnssrvComplexOperation3 = 14;

    /// <summary>
    /// MS-DNSP (DnsServer): R_DnssrvOperation4 - Performs DNS server operations (version 4)
    /// </summary>
    public const ushort R_DnssrvOperation4 = 15;

    /// <summary>
    /// MS-DNSP (DnsServer): R_DnssrvQuery4 - Queries DNS server information (version 4)
    /// </summary>
    public const ushort R_DnssrvQuery4 = 16;

    /// <summary>
    /// MS-DNSP (DnsServer): R_DnssrvUpdateRecord4 - Updates DNS records (version 4)
    /// </summary>
    public const ushort R_DnssrvUpdateRecord4 = 17;

    /// <summary>
    /// MS-DNSP (DnsServer): R_DnssrvEnumRecords4 - Enumerates DNS records (version 4)
    /// </summary>
    public const ushort R_DnssrvEnumRecords4 = 18;

    #endregion // MS-DNSP
    #region MS-RSP

    /// <summary>
    /// MS-RSP (InitShutdown): BaseInitiateShutdown - Initiates system shutdown
    /// </summary>
    public const ushort BaseInitiateShutdown = 0;

    /// <summary>
    /// MS-RSP (InitShutdown): BaseAbortShutdown - Aborts a pending system shutdown
    /// </summary>
    public const ushort BaseAbortShutdown = 1;

    /// <summary>
    /// MS-RSP (InitShutdown): BaseInitiateShutdownEx - Initiates system shutdown with extended options
    /// </summary>
    public const ushort BaseInitiateShutdownEx = 2;

    /// <summary>
    /// MS-RSP (WindowsShutdown): WsdrInitiateShutdown - Initiates system shutdown
    /// </summary>
    public const ushort WsdrInitiateShutdown = 0;

    /// <summary>
    /// MS-RSP (WindowsShutdown): WsdrAbortShutdown - Aborts a pending system shutdown
    /// </summary>
    public const ushort WsdrAbortShutdown = 1;

    /// <summary>
    /// MS-RSP (WinReg): BaseInitiateSystemShutdown - Initiates system shutdown via WinReg
    /// </summary>
    public const ushort BaseInitiateSystemShutdown = 24;

    /// <summary>
    /// MS-RSP (WinReg): BaseAbortSystemShutdown - Aborts system shutdown via WinReg
    /// </summary>
    public const ushort BaseAbortSystemShutdown = 25;

    /// <summary>
    /// MS-RSP (WinReg): BaseInitiateSystemShutdownEx - Initiates system shutdown with extended options via WinReg
    /// </summary>
    public const ushort BaseInitiateSystemShutdownEx = 30;

    #endregion // MS-RSP
    #region MS-W32T

    /// <summary>
    /// MS-W32T (W32Time): W32TimeSync - Synchronizes time with a time source
    /// </summary>
    public const ushort W32TimeSync = 0;

    /// <summary>
    /// MS-W32T (W32Time): W32TimeGetNetlogonServiceBits - Gets Netlogon service bits
    /// </summary>
    public const ushort W32TimeGetNetlogonServiceBits = 1;

    /// <summary>
    /// MS-W32T (W32Time): W32TimeQueryProviderStatus - Queries time provider status
    /// </summary>
    public const ushort W32TimeQueryProviderStatus = 2;

    /// <summary>
    /// MS-W32T (W32Time): W32TimeQuerySource - Queries the current time source
    /// </summary>
    public const ushort W32TimeQuerySource = 3;

    /// <summary>
    /// MS-W32T (W32Time): W32TimeQueryProviderConfiguration - Queries provider configuration
    /// </summary>
    public const ushort W32TimeQueryProviderConfiguration = 4;

    /// <summary>
    /// MS-W32T (W32Time): W32TimeQueryConfiguration - Queries time service configuration
    /// </summary>
    public const ushort W32TimeQueryConfiguration = 5;

    /// <summary>
    /// MS-W32T (W32Time): W32TimeQueryStatus - Queries time service status
    /// </summary>
    public const ushort W32TimeQueryStatus = 6;

    /// <summary>
    /// MS-W32T (W32Time): W32TimeLog - Sends diagnostic information to the service
    /// </summary>
    public const ushort W32TimeLog = 7;

    #endregion // MS-W32T
    #region MS-DHCPM (dhcpsrv)

    /// <summary>
    /// MS-DHCPM (dhcpsrv): R_DhcpCreateSubnet - Creates a subnet
    /// </summary>
    public const ushort R_DhcpCreateSubnet = 0;

    /// <summary>
    /// MS-DHCPM (dhcpsrv): R_DhcpSetSubnetInfo - Sets subnet information
    /// </summary>
    public const ushort R_DhcpSetSubnetInfo = 1;

    /// <summary>
    /// MS-DHCPM (dhcpsrv): R_DhcpGetSubnetInfo - Gets subnet information
    /// </summary>
    public const ushort R_DhcpGetSubnetInfo = 2;

    /// <summary>
    /// MS-DHCPM (dhcpsrv): R_DhcpEnumSubnets - Enumerates subnets
    /// </summary>
    public const ushort R_DhcpEnumSubnets = 3;

    /// <summary>
    /// MS-DHCPM (dhcpsrv): R_DhcpAddSubnetElement - Adds a subnet element
    /// </summary>
    public const ushort R_DhcpAddSubnetElement = 4;

    /// <summary>
    /// MS-DHCPM (dhcpsrv): R_DhcpEnumSubnetElements - Enumerates subnet elements
    /// </summary>
    public const ushort R_DhcpEnumSubnetElements = 5;

    /// <summary>
    /// MS-DHCPM (dhcpsrv): R_DhcpRemoveSubnetElement - Removes a subnet element
    /// </summary>
    public const ushort R_DhcpRemoveSubnetElement = 6;

    /// <summary>
    /// MS-DHCPM (dhcpsrv): R_DhcpDeleteSubnet - Deletes a subnet
    /// </summary>
    public const ushort R_DhcpDeleteSubnet = 7;

    /// <summary>
    /// MS-DHCPM (dhcpsrv): R_DhcpCreateOption - Creates an option definition
    /// </summary>
    public const ushort R_DhcpCreateOption = 8;

    /// <summary>
    /// MS-DHCPM (dhcpsrv): R_DhcpSetOptionInfo - Sets option information
    /// </summary>
    public const ushort R_DhcpSetOptionInfo = 9;

    /// <summary>
    /// MS-DHCPM (dhcpsrv): R_DhcpGetOptionInfo - Gets option information
    /// </summary>
    public const ushort R_DhcpGetOptionInfo = 10;

    /// <summary>
    /// MS-DHCPM (dhcpsrv): R_DhcpRemoveOption - Removes an option definition
    /// </summary>
    public const ushort R_DhcpRemoveOption = 11;

    /// <summary>
    /// MS-DHCPM (dhcpsrv): R_DhcpSetOptionValue - Sets an option value
    /// </summary>
    public const ushort R_DhcpSetOptionValue = 12;

    /// <summary>
    /// MS-DHCPM (dhcpsrv): R_DhcpGetOptionValue - Gets an option value
    /// </summary>
    public const ushort R_DhcpGetOptionValue = 13;

    /// <summary>
    /// MS-DHCPM (dhcpsrv): R_DhcpEnumOptionValues - Enumerates option values
    /// </summary>
    public const ushort R_DhcpEnumOptionValues = 14;

    /// <summary>
    /// MS-DHCPM (dhcpsrv): R_DhcpRemoveOptionValue - Removes an option value
    /// </summary>
    public const ushort R_DhcpRemoveOptionValue = 15;

    /// <summary>
    /// MS-DHCPM (dhcpsrv): R_DhcpCreateClientInfo - Creates client information
    /// </summary>
    public const ushort R_DhcpCreateClientInfo = 16;

    /// <summary>
    /// MS-DHCPM (dhcpsrv): R_DhcpSetClientInfo - Sets client information
    /// </summary>
    public const ushort R_DhcpSetClientInfo = 17;

    /// <summary>
    /// MS-DHCPM (dhcpsrv): R_DhcpGetClientInfo - Gets client information
    /// </summary>
    public const ushort R_DhcpGetClientInfo = 18;

    /// <summary>
    /// MS-DHCPM (dhcpsrv): R_DhcpDeleteClientInfo - Deletes client information
    /// </summary>
    public const ushort R_DhcpDeleteClientInfo = 19;

    /// <summary>
    /// MS-DHCPM (dhcpsrv): R_DhcpEnumSubnetClients - Enumerates subnet clients
    /// </summary>
    public const ushort R_DhcpEnumSubnetClients = 20;

    /// <summary>
    /// MS-DHCPM (dhcpsrv): R_DhcpGetClientOptions - Gets client options
    /// </summary>
    public const ushort R_DhcpGetClientOptions = 21;

    /// <summary>
    /// MS-DHCPM (dhcpsrv): R_DhcpGetMibInfo - Gets MIB information
    /// </summary>
    public const ushort R_DhcpGetMibInfo = 22;

    /// <summary>
    /// MS-DHCPM (dhcpsrv): R_DhcpEnumOptions - Enumerates options
    /// </summary>
    public const ushort R_DhcpEnumOptions = 23;

    /// <summary>
    /// MS-DHCPM (dhcpsrv): R_DhcpSetOptionValues - Sets option values
    /// </summary>
    public const ushort R_DhcpSetOptionValues = 24;

    /// <summary>
    /// MS-DHCPM (dhcpsrv): R_DhcpServerSetConfig - Sets server configuration
    /// </summary>
    public const ushort R_DhcpServerSetConfig = 25;

    /// <summary>
    /// MS-DHCPM (dhcpsrv): R_DhcpServerGetConfig - Gets server configuration
    /// </summary>
    public const ushort R_DhcpServerGetConfig = 26;

    /// <summary>
    /// MS-DHCPM (dhcpsrv): R_DhcpScanDatabase - Scans database for inconsistencies
    /// </summary>
    public const ushort R_DhcpScanDatabase = 27;

    /// <summary>
    /// MS-DHCPM (dhcpsrv): R_DhcpGetVersion - Gets DHCP server version
    /// </summary>
    public const ushort R_DhcpGetVersion = 28;

    #endregion // MS-DHCPM (dhcpsrv)
    #region MS-DHCPM (dhcpsrv2)

    /// <summary>
    /// MS-DHCPM (dhcpsrv2): R_DhcpEnumSubnetClientsV5 - Enumerates subnet clients (version 5)
    /// </summary>
    public const ushort R_DhcpEnumSubnetClientsV5 = 0;

    /// <summary>
    /// MS-DHCPM (dhcpsrv2): R_DhcpSetMScopeInfo - Sets multicast scope information
    /// </summary>
    public const ushort R_DhcpSetMScopeInfo = 1;

    /// <summary>
    /// MS-DHCPM (dhcpsrv2): R_DhcpGetMScopeInfo - Gets multicast scope information
    /// </summary>
    public const ushort R_DhcpGetMScopeInfo = 2;

    /// <summary>
    /// MS-DHCPM (dhcpsrv2): R_DhcpEnumMScopes - Enumerates multicast scopes
    /// </summary>
    public const ushort R_DhcpEnumMScopes = 3;

    /// <summary>
    /// MS-DHCPM (dhcpsrv2): R_DhcpCreateSubnetV6 - Creates an IPv6 subnet
    /// </summary>
    public const ushort R_DhcpCreateSubnetV6 = 57;

    /// <summary>
    /// MS-DHCPM (dhcpsrv2): R_DhcpEnumSubnetsV6 - Enumerates IPv6 subnets
    /// </summary>
    public const ushort R_DhcpEnumSubnetsV6 = 58;

    /// <summary>
    /// MS-DHCPM (dhcpsrv2): R_DhcpV4FailoverCreateRelationship - Creates a failover relationship
    /// </summary>
    public const ushort R_DhcpV4FailoverCreateRelationship = 89;

    /// <summary>
    /// MS-DHCPM (dhcpsrv2): R_DhcpV4FailoverDeleteRelationship - Deletes a failover relationship
    /// </summary>
    public const ushort R_DhcpV4FailoverDeleteRelationship = 91;

    /// <summary>
    /// MS-DHCPM (dhcpsrv2): R_DhcpV4CreatePolicy - Creates a DHCP policy
    /// </summary>
    public const ushort R_DhcpV4CreatePolicy = 108;

    /// <summary>
    /// MS-DHCPM (dhcpsrv2): R_DhcpV4GetPolicy - Gets a DHCP policy
    /// </summary>
    public const ushort R_DhcpV4GetPolicy = 109;

    /// <summary>
    /// MS-DHCPM (dhcpsrv2): R_DhcpV4SetPolicy - Sets a DHCP policy
    /// </summary>
    public const ushort R_DhcpV4SetPolicy = 110;

    /// <summary>
    /// MS-DHCPM (dhcpsrv2): R_DhcpV4DeletePolicy - Deletes a DHCP policy
    /// </summary>
    public const ushort R_DhcpV4DeletePolicy = 111;

    #endregion // MS-DHCPM (dhcpsrv2)
    #region MS-FAX

    /// <summary>
    /// MS-FAX (fax): FAX_GetServicePrinters - Gets service printers
    /// </summary>
    public const ushort FAX_GetServicePrinters = 0;

    /// <summary>
    /// MS-FAX (fax): FAX_ConnectionRefCount - Manages connection reference count
    /// </summary>
    public const ushort FAX_ConnectionRefCount = 1;

    /// <summary>
    /// MS-FAX (fax): FAX_OpenPort - Opens a fax port
    /// </summary>
    public const ushort FAX_OpenPort = 2;

    /// <summary>
    /// MS-FAX (fax): FAX_ClosePort - Closes a fax port
    /// </summary>
    public const ushort FAX_ClosePort = 3;

    /// <summary>
    /// MS-FAX (fax): FAX_EnumJobs - Enumerates fax jobs
    /// </summary>
    public const ushort FAX_EnumJobs = 4;

    /// <summary>
    /// MS-FAX (fax): FAX_GetJob - Gets fax job information
    /// </summary>
    public const ushort FAX_GetJob = 5;

    /// <summary>
    /// MS-FAX (fax): FAX_SetJob - Sets fax job information
    /// </summary>
    public const ushort FAX_SetJob = 6;

    /// <summary>
    /// MS-FAX (fax): FAX_GetPageData - Gets page data
    /// </summary>
    public const ushort FAX_GetPageData = 7;

    /// <summary>
    /// MS-FAX (fax): FAX_GetDeviceStatus - Gets device status
    /// </summary>
    public const ushort FAX_GetDeviceStatus = 8;

    /// <summary>
    /// MS-FAX (fax): FAX_Abort - Aborts a fax operation
    /// </summary>
    public const ushort FAX_Abort = 9;

    /// <summary>
    /// MS-FAX (fax): FAX_EnumPorts - Enumerates fax ports
    /// </summary>
    public const ushort FAX_EnumPorts = 10;

    /// <summary>
    /// MS-FAX (fax): FAX_GetPort - Gets fax port information
    /// </summary>
    public const ushort FAX_GetPort = 11;

    /// <summary>
    /// MS-FAX (fax): FAX_SetPort - Sets fax port information
    /// </summary>
    public const ushort FAX_SetPort = 12;

    /// <summary>
    /// MS-FAX (fax): FAX_EnumRoutingMethods - Enumerates routing methods
    /// </summary>
    public const ushort FAX_EnumRoutingMethods = 13;

    /// <summary>
    /// MS-FAX (fax): FAX_EnableRoutingMethod - Enables a routing method
    /// </summary>
    public const ushort FAX_EnableRoutingMethod = 14;

    /// <summary>
    /// MS-FAX (fax): FAX_GetRoutingInfo - Gets routing information
    /// </summary>
    public const ushort FAX_GetRoutingInfo = 15;

    /// <summary>
    /// MS-FAX (fax): FAX_SetRoutingInfo - Sets routing information
    /// </summary>
    public const ushort FAX_SetRoutingInfo = 16;

    /// <summary>
    /// MS-FAX (fax): FAX_SendDocumentEx - Sends a fax document (extended)
    /// </summary>
    public const ushort FAX_SendDocumentEx = 27;

    /// <summary>
    /// MS-FAX (fax): FAX_GetConfiguration - Gets fax configuration
    /// </summary>
    public const ushort FAX_GetConfiguration = 19;

    /// <summary>
    /// MS-FAX (fax): FAX_SetConfiguration - Sets fax configuration
    /// </summary>
    public const ushort FAX_SetConfiguration = 20;

    /// <summary>
    /// MS-FAX (fax): FAX_GetSecurity - Gets security information
    /// </summary>
    public const ushort FAX_GetSecurity = 23;

    /// <summary>
    /// MS-FAX (fax): FAX_SetSecurity - Sets security information
    /// </summary>
    public const ushort FAX_SetSecurity = 24;

    /// <summary>
    /// MS-FAX (fax): FAX_ConnectFaxServer - Connects to fax server
    /// </summary>
    public const ushort FAX_ConnectFaxServer = 80;

    #endregion // MS-FAX
    #region MS-FRS2

    /// <summary>
    /// MS-FRS2 (FrsTransport): CheckConnectivity - Checks connectivity to the server
    /// </summary>
    public const ushort CheckConnectivity = 0;

    /// <summary>
    /// MS-FRS2 (FrsTransport): EstablishConnection - Establishes a connection to the server
    /// </summary>
    public const ushort EstablishConnection = 1;

    /// <summary>
    /// MS-FRS2 (FrsTransport): EstablishSession - Establishes a replication session
    /// </summary>
    public const ushort EstablishSession = 2;

    /// <summary>
    /// MS-FRS2 (FrsTransport): RequestUpdates - Requests replication updates
    /// </summary>
    public const ushort RequestUpdates = 3;

    /// <summary>
    /// MS-FRS2 (FrsTransport): RequestVersionVector - Requests version vector
    /// </summary>
    public const ushort RequestVersionVector = 4;

    /// <summary>
    /// MS-FRS2 (FrsTransport): AsyncPoll - Asynchronous polling for updates
    /// </summary>
    public const ushort AsyncPoll = 5;

    /// <summary>
    /// MS-FRS2 (FrsTransport): RequestRecords - Requests replication records
    /// </summary>
    public const ushort RequestRecords = 6;

    /// <summary>
    /// MS-FRS2 (FrsTransport): UpdateCancel - Cancels an update request
    /// </summary>
    public const ushort UpdateCancel = 7;

    /// <summary>
    /// MS-FRS2 (FrsTransport): RawGetFileData - Gets raw file data
    /// </summary>
    public const ushort RawGetFileData = 8;

    /// <summary>
    /// MS-FRS2 (FrsTransport): RdcGetSignatures - Gets RDC signatures
    /// </summary>
    public const ushort RdcGetSignatures = 9;

    /// <summary>
    /// MS-FRS2 (FrsTransport): RdcPushSourceNeeds - Pushes RDC source needs
    /// </summary>
    public const ushort RdcPushSourceNeeds = 10;

    /// <summary>
    /// MS-FRS2 (FrsTransport): RdcGetFileData - Gets RDC file data
    /// </summary>
    public const ushort RdcGetFileData = 11;

    /// <summary>
    /// MS-FRS2 (FrsTransport): RdcClose - Closes RDC transfer
    /// </summary>
    public const ushort RdcClose = 12;

    /// <summary>
    /// MS-FRS2 (FrsTransport): InitializeFileTransferAsync - Initializes async file transfer
    /// </summary>
    public const ushort InitializeFileTransferAsync = 13;

    /// <summary>
    /// MS-FRS2 (FrsTransport): Opnum14NotUsedOnWire - Reserved
    /// </summary>
    public const ushort FRS2_Opnum14NotUsedOnWire = 14;

    /// <summary>
    /// MS-FRS2 (FrsTransport): RawGetFileDataAsync - Gets raw file data asynchronously
    /// </summary>
    public const ushort RawGetFileDataAsync = 15;

    /// <summary>
    /// MS-FRS2 (FrsTransport): RdcGetFileDataAsync - Gets RDC file data asynchronously
    /// </summary>
    public const ushort RdcGetFileDataAsync = 16;

    /// <summary>
    /// MS-FRS2 (FrsTransport): RdcFileDataTransferKeepAlive - Keep alive for RDC file transfer
    /// </summary>
    public const ushort RdcFileDataTransferKeepAlive = 17;

    #endregion // MS-FRS2
    #region MS-NSPI

    /// <summary>
    /// MS-NSPI: NspiBind - Initiates a session with the server
    /// </summary>
    public const ushort NspiBind = 0;

    /// <summary>
    /// MS-NSPI: NspiUnbind - Terminates a session with the server
    /// </summary>
    public const ushort NspiUnbind = 1;

    /// <summary>
    /// MS-NSPI: NspiUpdateStat - Updates the STAT block
    /// </summary>
    public const ushort NspiUpdateStat = 2;

    /// <summary>
    /// MS-NSPI: NspiQueryRows - Returns rows from a table
    /// </summary>
    public const ushort NspiQueryRows = 3;

    /// <summary>
    /// MS-NSPI: NspiSeekEntries - Seeks to an entry in a table
    /// </summary>
    public const ushort NspiSeekEntries = 4;

    /// <summary>
    /// MS-NSPI: NspiGetMatches - Returns rows matching a restriction
    /// </summary>
    public const ushort NspiGetMatches = 5;

    /// <summary>
    /// MS-NSPI: NspiResortRestriction - Applies a different sort order
    /// </summary>
    public const ushort NspiResortRestriction = 6;

    /// <summary>
    /// MS-NSPI: NspiDNToMId - Maps a DN to a Minimal Entry ID
    /// </summary>
    public const ushort NspiDNToMId = 7;

    /// <summary>
    /// MS-NSPI: NspiGetPropList - Returns a list of properties
    /// </summary>
    public const ushort NspiGetPropList = 8;

    /// <summary>
    /// MS-NSPI: NspiGetProps - Returns specific properties
    /// </summary>
    public const ushort NspiGetProps = 9;

    /// <summary>
    /// MS-NSPI: NspiCompareMIds - Compares two Minimal Entry IDs
    /// </summary>
    public const ushort NspiCompareMIds = 10;

    /// <summary>
    /// MS-NSPI: NspiModProps - Modifies properties of an object
    /// </summary>
    public const ushort NspiModProps = 11;

    /// <summary>
    /// MS-NSPI: NspiGetSpecialTable - Returns a special table
    /// </summary>
    public const ushort NspiGetSpecialTable = 12;

    /// <summary>
    /// MS-NSPI: NspiGetTemplateInfo - Returns template information
    /// </summary>
    public const ushort NspiGetTemplateInfo = 13;

    /// <summary>
    /// MS-NSPI: NspiModLinkAtt - Modifies link attribute values
    /// </summary>
    public const ushort NspiModLinkAtt = 14;

    /// <summary>
    /// MS-NSPI: Opnum15NotUsedOnWire - Reserved
    /// </summary>
    public const ushort NSPI_Opnum15NotUsedOnWire = 15;

    /// <summary>
    /// MS-NSPI: NspiQueryColumns - Returns a list of all columns
    /// </summary>
    public const ushort NspiQueryColumns = 16;

    /// <summary>
    /// MS-NSPI: NspiGetNamesFromIDs - Returns property names for property IDs
    /// </summary>
    public const ushort NspiGetNamesFromIDs = 17;

    /// <summary>
    /// MS-NSPI: NspiGetIDsFromNames - Returns property IDs for property names
    /// </summary>
    public const ushort NspiGetIDsFromNames = 18;

    /// <summary>
    /// MS-NSPI: NspiResolveNames - Resolves names to address book entries
    /// </summary>
    public const ushort NspiResolveNames = 19;

    /// <summary>
    /// MS-NSPI: NspiResolveNamesW - Resolves names (Unicode) to address book entries
    /// </summary>
    public const ushort NspiResolveNamesW = 20;

    #endregion // MS-NSPI
    #region MS-SWN

    /// <summary>
    /// MS-SWN (Witness): WitnessrGetInterfaceList - Gets list of available interfaces
    /// </summary>
    public const ushort WitnessrGetInterfaceList = 0;

    /// <summary>
    /// MS-SWN (Witness): WitnessrRegister - Registers for notifications
    /// </summary>
    public const ushort WitnessrRegister = 1;

    /// <summary>
    /// MS-SWN (Witness): WitnessrUnRegister - Unregisters from notifications
    /// </summary>
    public const ushort WitnessrUnRegister = 2;

    /// <summary>
    /// MS-SWN (Witness): WitnessrAsyncNotify - Receives notifications asynchronously
    /// </summary>
    public const ushort WitnessrAsyncNotify = 3;

    /// <summary>
    /// MS-SWN (Witness): WitnessrRegisterEx - Extended registration for notifications
    /// </summary>
    public const ushort WitnessrRegisterEx = 4;

    /// <summary>
    /// MS-SWN (Witness): WitnessrUnRegisterEx - Extended unregistration (reserved)
    /// </summary>
    public const ushort WitnessrUnRegisterEx = 5;

    #endregion // MS-SWN
    #region MS-CMPO

    /// <summary>
    /// MS-CMPO (IXnRemote): Poke - Signals the partner to examine the state of the session
    /// </summary>
    public const ushort IXnRemote_Poke = 0;

    /// <summary>
    /// MS-CMPO (IXnRemote): BuildContext - Initializes session context between partners
    /// </summary>
    public const ushort IXnRemote_BuildContext = 1;

    /// <summary>
    /// MS-CMPO (IXnRemote): NegotiateResources - Negotiates resources for a transaction
    /// </summary>
    public const ushort IXnRemote_NegotiateResources = 2;

    /// <summary>
    /// MS-CMPO (IXnRemote): SendReceive - Sends a message to the transaction manager partner
    /// </summary>
    public const ushort IXnRemote_SendReceive = 3;

    /// <summary>
    /// MS-CMPO (IXnRemote): TearDownContext - Releases session context between partners
    /// </summary>
    public const ushort IXnRemote_TearDownContext = 4;

    /// <summary>
    /// MS-CMPO (IXnRemote): BeginTearDown - Begins asynchronous release of session context
    /// </summary>
    public const ushort IXnRemote_BeginTearDown = 5;

    /// <summary>
    /// MS-CMPO (IXnRemote): PokeW - Signals partner to examine session state (Unicode)
    /// </summary>
    public const ushort IXnRemote_PokeW = 6;

    /// <summary>
    /// MS-CMPO (IXnRemote): BuildContextW - Initializes session context (Unicode)
    /// </summary>
    public const ushort IXnRemote_BuildContextW = 7;

    #endregion // MS-CMPO
    #region MS-DLTM

    /// <summary>
    /// MS-DLTM: LnkSvrMessage - Primary message processing method for Central Manager
    /// </summary>
    public const ushort LnkSvrMessage = 0;

    /// <summary>
    /// MS-DLTM: LnkSvrMessageCallback - Callback for receiving asynchronous messages
    /// </summary>
    public const ushort LnkSvrMessageCallback = 1;

    #endregion // MS-DLTM
    #region MS-DLTW

    /// <summary>
    /// MS-DLTW: Opnum0NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort DLTW_Opnum0NotUsedOnWire = 0;

    /// <summary>
    /// MS-DLTW: Opnum1NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort DLTW_Opnum1NotUsedOnWire = 1;

    /// <summary>
    /// MS-DLTW: Opnum2NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort DLTW_Opnum2NotUsedOnWire = 2;

    /// <summary>
    /// MS-DLTW: Opnum3NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort DLTW_Opnum3NotUsedOnWire = 3;

    /// <summary>
    /// MS-DLTW: Opnum4NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort DLTW_Opnum4NotUsedOnWire = 4;

    /// <summary>
    /// MS-DLTW: Opnum5NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort DLTW_Opnum5NotUsedOnWire = 5;

    /// <summary>
    /// MS-DLTW: Opnum6NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort DLTW_Opnum6NotUsedOnWire = 6;

    /// <summary>
    /// MS-DLTW: Opnum7NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort DLTW_Opnum7NotUsedOnWire = 7;

    /// <summary>
    /// MS-DLTW: Opnum8NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort DLTW_Opnum8NotUsedOnWire = 8;

    /// <summary>
    /// MS-DLTW: Opnum9NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort DLTW_Opnum9NotUsedOnWire = 9;

    /// <summary>
    /// MS-DLTW: Opnum10NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort DLTW_Opnum10NotUsedOnWire = 10;

    /// <summary>
    /// MS-DLTW: Opnum11NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort DLTW_Opnum11NotUsedOnWire = 11;

    /// <summary>
    /// MS-DLTW: LnkSearchMachine - Searches for file link on the workstation
    /// </summary>
    public const ushort LnkSearchMachine = 12;

    #endregion // MS-DLTW
    #region MS-FRS1 (NtFrsApi)

    /// <summary>
    /// MS-FRS1 (NtFrsApi): Opnum0NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort NtFrsApi_Opnum0NotUsedOnWire = 0;

    /// <summary>
    /// MS-FRS1 (NtFrsApi): Opnum1NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort NtFrsApi_Opnum1NotUsedOnWire = 1;

    /// <summary>
    /// MS-FRS1 (NtFrsApi): Opnum2NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort NtFrsApi_Opnum2NotUsedOnWire = 2;

    /// <summary>
    /// MS-FRS1 (NtFrsApi): Opnum3NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort NtFrsApi_Opnum3NotUsedOnWire = 3;

    /// <summary>
    /// MS-FRS1 (NtFrsApi): NtFrsApi_Rpc_StartPromotionParent - Starts promotion operation
    /// </summary>
    public const ushort NtFrsApi_Rpc_StartPromotionParent = 4;

    /// <summary>
    /// MS-FRS1 (NtFrsApi): NtFrsApi_Rpc_PromotionStatusW - Gets promotion status
    /// </summary>
    public const ushort NtFrsApi_Rpc_PromotionStatusW = 5;

    /// <summary>
    /// MS-FRS1 (NtFrsApi): Opnum6NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort NtFrsApi_Opnum6NotUsedOnWire = 6;

    /// <summary>
    /// MS-FRS1 (NtFrsApi): NtFrsApi_Rpc_WriterCommand - Sends a command to the FRS writer
    /// </summary>
    public const ushort NtFrsApi_Rpc_WriterCommand = 7;

    /// <summary>
    /// MS-FRS1 (NtFrsApi): NtFrsApi_Rpc_Set_DsPollingIntervalW - Sets DS polling interval
    /// </summary>
    public const ushort NtFrsApi_Rpc_Set_DsPollingIntervalW = 8;

    /// <summary>
    /// MS-FRS1 (NtFrsApi): NtFrsApi_Rpc_Get_DsPollingIntervalW - Gets DS polling interval
    /// </summary>
    public const ushort NtFrsApi_Rpc_Get_DsPollingIntervalW = 9;

    /// <summary>
    /// MS-FRS1 (NtFrsApi): NtFrsApi_Rpc_InfoW - Gets replication information
    /// </summary>
    public const ushort NtFrsApi_Rpc_InfoW = 10;

    #endregion // MS-FRS1 (NtFrsApi)
    #region MS-FRS1 (frsrpc)

    /// <summary>
    /// MS-FRS1 (frsrpc): FrsRpcSendCommPkt - Sends a communication packet to a replication partner
    /// </summary>
    public const ushort FrsRpcSendCommPkt = 0;

    /// <summary>
    /// MS-FRS1 (frsrpc): FrsRpcVerifyPromotionParent - Verifies promotion parent configuration
    /// </summary>
    public const ushort FrsRpcVerifyPromotionParent = 1;

    /// <summary>
    /// MS-FRS1 (frsrpc): FrsRpcStartPromotionParent - Starts the promotion parent operation
    /// </summary>
    public const ushort FrsRpcStartPromotionParent = 2;

    /// <summary>
    /// MS-FRS1 (frsrpc): FrsNOP - No operation (reserved)
    /// </summary>
    public const ushort FrsNOP = 3;

    #endregion // MS-FRS1 (frsrpc)
    #region MS-IRP

    /// <summary>
    /// MS-IRP: R_InetInfoGetVersion - Gets the version of the internet information server
    /// </summary>
    public const ushort R_InetInfoGetVersion = 0;

    /// <summary>
    /// MS-IRP: R_InetInfoGetAdminInformation - Gets admin information for a service
    /// </summary>
    public const ushort R_InetInfoGetAdminInformation = 1;

    /// <summary>
    /// MS-IRP: R_InetInfoGetSites - Gets the list of sites
    /// </summary>
    public const ushort R_InetInfoGetSites = 2;

    /// <summary>
    /// MS-IRP: R_InetInfoSetAdminInformation - Sets admin information for a service
    /// </summary>
    public const ushort R_InetInfoSetAdminInformation = 3;

    /// <summary>
    /// MS-IRP: R_InetInfoGetGlobalAdminInformation - Gets global admin information
    /// </summary>
    public const ushort R_InetInfoGetGlobalAdminInformation = 4;

    /// <summary>
    /// MS-IRP: R_InetInfoSetGlobalAdminInformation - Sets global admin information
    /// </summary>
    public const ushort R_InetInfoSetGlobalAdminInformation = 5;

    /// <summary>
    /// MS-IRP: R_InetInfoQueryStatistics - Queries service statistics
    /// </summary>
    public const ushort R_InetInfoQueryStatistics = 6;

    /// <summary>
    /// MS-IRP: R_InetInfoClearStatistics - Clears service statistics
    /// </summary>
    public const ushort R_InetInfoClearStatistics = 7;

    /// <summary>
    /// MS-IRP: R_InetInfoFlushMemoryCache - Flushes the memory cache
    /// </summary>
    public const ushort R_InetInfoFlushMemoryCache = 8;

    /// <summary>
    /// MS-IRP: R_InetInfoGetServerCapabilities - Gets server capabilities
    /// </summary>
    public const ushort R_InetInfoGetServerCapabilities = 9;

    /// <summary>
    /// MS-IRP: R_W3QueryStatistics2 - Queries W3 service statistics (version 2)
    /// </summary>
    public const ushort R_W3QueryStatistics2 = 10;

    /// <summary>
    /// MS-IRP: R_W3ClearStatistics2 - Clears W3 service statistics (version 2)
    /// </summary>
    public const ushort R_W3ClearStatistics2 = 11;

    /// <summary>
    /// MS-IRP: R_FtpQueryStatistics2 - Queries FTP service statistics (version 2)
    /// </summary>
    public const ushort R_FtpQueryStatistics2 = 12;

    /// <summary>
    /// MS-IRP: R_FtpClearStatistics2 - Clears FTP service statistics (version 2)
    /// </summary>
    public const ushort R_FtpClearStatistics2 = 13;

    /// <summary>
    /// MS-IRP: R_IISEnumerateUsers - Enumerates connected users
    /// </summary>
    public const ushort R_IISEnumerateUsers = 14;

    /// <summary>
    /// MS-IRP: R_IISDisconnectUser - Disconnects a user
    /// </summary>
    public const ushort R_IISDisconnectUser = 15;

    #endregion // MS-IRP
    #region MS-LREC

    /// <summary>
    /// MS-LREC: RpcNetEventOpenSession - Opens a live event capture session
    /// </summary>
    public const ushort RpcNetEventOpenSession = 0;

    /// <summary>
    /// MS-LREC: RpcNetEventReceiveData - Receives event data from the session
    /// </summary>
    public const ushort RpcNetEventReceiveData = 1;

    /// <summary>
    /// MS-LREC: RpcNetEventCloseSession - Closes the event capture session
    /// </summary>
    public const ushort RpcNetEventCloseSession = 2;

    #endregion // MS-LREC
    #region MS-MQDS (dscomm)

    /// <summary>
    /// MS-MQDS (dscomm): S_DSCreateObject - Creates an MSMQ directory object
    /// </summary>
    public const ushort S_DSCreateObject = 0;

    /// <summary>
    /// MS-MQDS (dscomm): S_DSDeleteObject - Deletes an MSMQ directory object
    /// </summary>
    public const ushort S_DSDeleteObject = 1;

    /// <summary>
    /// MS-MQDS (dscomm): S_DSGetProps - Gets properties of an MSMQ object
    /// </summary>
    public const ushort S_DSGetProps = 2;

    /// <summary>
    /// MS-MQDS (dscomm): S_DSSetProps - Sets properties of an MSMQ object
    /// </summary>
    public const ushort S_DSSetProps = 3;

    /// <summary>
    /// MS-MQDS (dscomm): S_DSGetObjectSecurity - Gets security descriptor of an object
    /// </summary>
    public const ushort S_DSGetObjectSecurity = 4;

    /// <summary>
    /// MS-MQDS (dscomm): S_DSSetObjectSecurity - Sets security descriptor of an object
    /// </summary>
    public const ushort S_DSSetObjectSecurity = 5;

    /// <summary>
    /// MS-MQDS (dscomm): S_DSLookupBegin - Begins a lookup operation
    /// </summary>
    public const ushort S_DSLookupBegin = 6;

    /// <summary>
    /// MS-MQDS (dscomm): S_DSLookupNext - Gets next result in a lookup
    /// </summary>
    public const ushort S_DSLookupNext = 7;

    /// <summary>
    /// MS-MQDS (dscomm): S_DSLookupEnd - Ends a lookup operation
    /// </summary>
    public const ushort S_DSLookupEnd = 8;

    /// <summary>
    /// MS-MQDS (dscomm): Opnum9NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort MQDS_Opnum9NotUsedOnWire = 9;

    /// <summary>
    /// MS-MQDS (dscomm): S_DSDeleteObjectGuid - Deletes an object by GUID
    /// </summary>
    public const ushort S_DSDeleteObjectGuid = 10;

    /// <summary>
    /// MS-MQDS (dscomm): S_DSGetPropsGuid - Gets properties by GUID
    /// </summary>
    public const ushort S_DSGetPropsGuid = 11;

    /// <summary>
    /// MS-MQDS (dscomm): S_DSSetPropsGuid - Sets properties by GUID
    /// </summary>
    public const ushort S_DSSetPropsGuid = 12;

    /// <summary>
    /// MS-MQDS (dscomm): S_DSGetObjectSecurityGuid - Gets security by GUID
    /// </summary>
    public const ushort S_DSGetObjectSecurityGuid = 13;

    /// <summary>
    /// MS-MQDS (dscomm): S_DSSetObjectSecurityGuid - Sets security by GUID
    /// </summary>
    public const ushort S_DSSetObjectSecurityGuid = 14;

    /// <summary>
    /// MS-MQDS (dscomm): Opnum15NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort MQDS_Opnum15NotUsedOnWire = 15;

    /// <summary>
    /// MS-MQDS (dscomm): Opnum16NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort MQDS_Opnum16NotUsedOnWire = 16;

    /// <summary>
    /// MS-MQDS (dscomm): Opnum17NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort MQDS_Opnum17NotUsedOnWire = 17;

    /// <summary>
    /// MS-MQDS (dscomm): Opnum18NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort MQDS_Opnum18NotUsedOnWire = 18;

    /// <summary>
    /// MS-MQDS (dscomm): S_DSQMSetMachineProperties - Sets machine properties for QM
    /// </summary>
    public const ushort S_DSQMSetMachineProperties = 19;

    /// <summary>
    /// MS-MQDS (dscomm): S_DSCreateServersCache - Creates server cache
    /// </summary>
    public const ushort S_DSCreateServersCache = 20;

    /// <summary>
    /// MS-MQDS (dscomm): S_DSQMGetObjectSecurity - Gets object security for QM
    /// </summary>
    public const ushort S_DSQMGetObjectSecurity = 21;

    /// <summary>
    /// MS-MQDS (dscomm): S_DSValidateServer - Validates server
    /// </summary>
    public const ushort S_DSValidateServer = 22;

    /// <summary>
    /// MS-MQDS (dscomm): S_DSCloseServerHandle - Closes server handle
    /// </summary>
    public const ushort S_DSCloseServerHandle = 23;

    /// <summary>
    /// MS-MQDS (dscomm): Opnum24NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort MQDS_Opnum24NotUsedOnWire = 24;

    /// <summary>
    /// MS-MQDS (dscomm): Opnum25NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort MQDS_Opnum25NotUsedOnWire = 25;

    /// <summary>
    /// MS-MQDS (dscomm): Opnum26NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort MQDS_Opnum26NotUsedOnWire = 26;

    /// <summary>
    /// MS-MQDS (dscomm): S_DSGetServerPort - Gets server port number
    /// </summary>
    public const ushort S_DSGetServerPort = 27;

    #endregion // MS-MQDS (dscomm)
    #region MS-MQMP (qmcomm)

    /// <summary>
    /// MS-MQMP (qmcomm): Opnum0NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort MQMP_Opnum0NotUsedOnWire = 0;

    /// <summary>
    /// MS-MQMP (qmcomm): R_QMGetRemoteQueueName - Gets remote queue name
    /// </summary>
    public const ushort R_QMGetRemoteQueueName = 1;

    /// <summary>
    /// MS-MQMP (qmcomm): R_QMOpenRemoteQueue - Opens a remote queue
    /// </summary>
    public const ushort R_QMOpenRemoteQueue = 2;

    /// <summary>
    /// MS-MQMP (qmcomm): R_QMCloseRemoteQueueContext - Closes remote queue context
    /// </summary>
    public const ushort R_QMCloseRemoteQueueContext = 3;

    /// <summary>
    /// MS-MQMP (qmcomm): R_QMCreateRemoteCursor - Creates a cursor on a remote queue
    /// </summary>
    public const ushort R_QMCreateRemoteCursor = 4;

    /// <summary>
    /// MS-MQMP (qmcomm): R_QMCreateObjectInternal - Creates an MSMQ object
    /// </summary>
    public const ushort R_QMCreateObjectInternal = 5;

    /// <summary>
    /// MS-MQMP (qmcomm): R_QMSetObjectSecurityInternal - Sets object security
    /// </summary>
    public const ushort R_QMSetObjectSecurityInternal = 6;

    /// <summary>
    /// MS-MQMP (qmcomm): R_QMGetObjectSecurityInternal - Gets object security
    /// </summary>
    public const ushort R_QMGetObjectSecurityInternal = 7;

    /// <summary>
    /// MS-MQMP (qmcomm): R_QMDeleteObject - Deletes an object
    /// </summary>
    public const ushort R_QMDeleteObject = 8;

    /// <summary>
    /// MS-MQMP (qmcomm): R_QMGetObjectProperties - Gets object properties
    /// </summary>
    public const ushort R_QMGetObjectProperties = 9;

    /// <summary>
    /// MS-MQMP (qmcomm): R_QMSetObjectProperties - Sets object properties
    /// </summary>
    public const ushort R_QMSetObjectProperties = 10;

    /// <summary>
    /// MS-MQMP (qmcomm): R_QMObjectPathToObjectFormat - Converts path to format name
    /// </summary>
    public const ushort R_QMObjectPathToObjectFormat = 11;

    /// <summary>
    /// MS-MQMP (qmcomm): R_QMGetTmWhereabouts - Gets TM whereabouts for transactions
    /// </summary>
    public const ushort R_QMGetTmWhereabouts = 12;

    /// <summary>
    /// MS-MQMP (qmcomm): R_QMEnlistTransaction - Enlists in a transaction
    /// </summary>
    public const ushort R_QMEnlistTransaction = 13;

    /// <summary>
    /// MS-MQMP (qmcomm): R_QMEnlistInternalTransaction - Enlists in internal transaction
    /// </summary>
    public const ushort R_QMEnlistInternalTransaction = 14;

    /// <summary>
    /// MS-MQMP (qmcomm): R_QMCommitTransaction - Commits a transaction
    /// </summary>
    public const ushort R_QMCommitTransaction = 15;

    /// <summary>
    /// MS-MQMP (qmcomm): R_QMAbortTransaction - Aborts a transaction
    /// </summary>
    public const ushort R_QMAbortTransaction = 16;

    /// <summary>
    /// MS-MQMP (qmcomm): rpc_QMOpenQueueInternal - Opens a queue internally
    /// </summary>
    public const ushort rpc_QMOpenQueueInternal = 17;

    /// <summary>
    /// MS-MQMP (qmcomm): rpc_ACCloseHandle - Closes an access control handle
    /// </summary>
    public const ushort rpc_ACCloseHandle = 18;

    /// <summary>
    /// MS-MQMP (qmcomm): rpc_ACSetCursorProperties - Sets cursor properties
    /// </summary>
    public const ushort rpc_ACSetCursorProperties = 19;

    /// <summary>
    /// MS-MQMP (qmcomm): rpc_ACHandleToFormatName - Converts handle to format name
    /// </summary>
    public const ushort rpc_ACHandleToFormatName = 20;

    /// <summary>
    /// MS-MQMP (qmcomm): rpc_ACPurgeQueue - Purges a queue
    /// </summary>
    public const ushort rpc_ACPurgeQueue = 21;

    /// <summary>
    /// MS-MQMP (qmcomm): R_QMQueryQMRegistryInternal - Queries QM registry
    /// </summary>
    public const ushort R_QMQueryQMRegistryInternal = 22;

    /// <summary>
    /// MS-MQMP (qmcomm): R_QMGetRTQMServerPort - Gets RTQM server port
    /// </summary>
    public const ushort R_QMGetRTQMServerPort = 23;

    /// <summary>
    /// MS-MQMP (qmcomm): R_QMAttachProcess - Attaches a process
    /// </summary>
    public const ushort R_QMAttachProcess = 24;

    /// <summary>
    /// MS-MQMP (qmcomm): R_QMGetSecurityContext - Gets security context
    /// </summary>
    public const ushort R_QMGetSecurityContext = 25;

    /// <summary>
    /// MS-MQMP (qmcomm): R_QMOpenRemoteQueue2 - Opens remote queue (version 2)
    /// </summary>
    public const ushort R_QMOpenRemoteQueue2 = 26;

    /// <summary>
    /// MS-MQMP (qmcomm): R_QMCreateRemoteCursor2 - Creates remote cursor (version 2)
    /// </summary>
    public const ushort R_QMCreateRemoteCursor2 = 27;

    /// <summary>
    /// MS-MQMP (qmcomm): R_QMSetCursorProperties2 - Sets cursor properties (version 2)
    /// </summary>
    public const ushort R_QMSetCursorProperties2 = 28;

    /// <summary>
    /// MS-MQMP (qmcomm): rpc_ACSetCursorProperties2 - AC set cursor properties (version 2)
    /// </summary>
    public const ushort rpc_ACSetCursorProperties2 = 29;

    /// <summary>
    /// MS-MQMP (qmcomm): rpc_ACSendMessage - Sends a message
    /// </summary>
    public const ushort rpc_ACSendMessage = 30;

    /// <summary>
    /// MS-MQMP (qmcomm): rpc_ACReceiveMessage - Receives a message
    /// </summary>
    public const ushort rpc_ACReceiveMessage = 31;

    #endregion // MS-MQMP (qmcomm)
    #region MS-MQMP (qmcomm2)

    /// <summary>
    /// MS-MQMP (qmcomm2): QMSendMessageInternalEx - Sends message (extended)
    /// </summary>
    public const ushort QMSendMessageInternalEx = 0;

    /// <summary>
    /// MS-MQMP (qmcomm2): rpc_ACSendMessageEx - AC send message (extended)
    /// </summary>
    public const ushort rpc_ACSendMessageEx = 1;

    /// <summary>
    /// MS-MQMP (qmcomm2): rpc_ACReceiveMessageEx - AC receive message (extended)
    /// </summary>
    public const ushort rpc_ACReceiveMessageEx = 2;

    /// <summary>
    /// MS-MQMP (qmcomm2): rpc_ACCreateCursorEx - AC create cursor (extended)
    /// </summary>
    public const ushort rpc_ACCreateCursorEx = 3;

    #endregion // MS-MQMP (qmcomm2)
    #region MS-MQMR

    /// <summary>
    /// MS-MQMR (qmmgmt): R_QMMgmtGetInfo - Gets management information
    /// </summary>
    public const ushort R_QMMgmtGetInfo = 0;

    /// <summary>
    /// MS-MQMR (qmmgmt): R_QMMgmtAction - Performs a management action
    /// </summary>
    public const ushort R_QMMgmtAction = 1;

    #endregion // MS-MQMR
    #region MS-MQQP

    /// <summary>
    /// MS-MQQP (qm2qm): RemoteQMStartReceive - Starts receiving messages
    /// </summary>
    public const ushort RemoteQMStartReceive = 0;

    /// <summary>
    /// MS-MQQP (qm2qm): RemoteQMEndReceive - Ends receiving messages
    /// </summary>
    public const ushort RemoteQMEndReceive = 1;

    /// <summary>
    /// MS-MQQP (qm2qm): RemoteQMOpenQueue - Opens a queue remotely
    /// </summary>
    public const ushort RemoteQMOpenQueue = 2;

    /// <summary>
    /// MS-MQQP (qm2qm): RemoteQMCloseQueue - Closes a queue remotely
    /// </summary>
    public const ushort RemoteQMCloseQueue = 3;

    /// <summary>
    /// MS-MQQP (qm2qm): RemoteQMCloseCursor - Closes a cursor remotely
    /// </summary>
    public const ushort RemoteQMCloseCursor = 4;

    /// <summary>
    /// MS-MQQP (qm2qm): RemoteQMCancelReceive - Cancels a pending receive
    /// </summary>
    public const ushort RemoteQMCancelReceive = 5;

    /// <summary>
    /// MS-MQQP (qm2qm): RemoteQMPurgeQueue - Purges a queue remotely
    /// </summary>
    public const ushort RemoteQMPurgeQueue = 6;

    /// <summary>
    /// MS-MQQP (qm2qm): RemoteQMGetQMQMServerPort - Gets QM-to-QM server port
    /// </summary>
    public const ushort RemoteQMGetQMQMServerPort = 7;

    /// <summary>
    /// MS-MQQP (qm2qm): RemoteQMStartReceive2 - Starts receiving (version 2)
    /// </summary>
    public const ushort RemoteQMStartReceive2 = 8;

    /// <summary>
    /// MS-MQQP (qm2qm): RemoteQMStartReceiveByLookupId - Starts receive by lookup ID
    /// </summary>
    public const ushort RemoteQMStartReceiveByLookupId = 9;

    /// <summary>
    /// MS-MQQP (qm2qm): RemoteQMStartReceiveByLookupId2 - Starts receive by lookup ID (version 2)
    /// </summary>
    public const ushort RemoteQMStartReceiveByLookupId2 = 10;

    #endregion // MS-MQQP
    #region MS-MQRR

    /// <summary>
    /// MS-MQRR (RemoteRead): R_GetServerPort - Gets the server port
    /// </summary>
    public const ushort R_GetServerPort = 0;

    /// <summary>
    /// MS-MQRR (RemoteRead): R_OpenQueue - Opens a queue
    /// </summary>
    public const ushort R_OpenQueue = 1;

    /// <summary>
    /// MS-MQRR (RemoteRead): R_CloseQueue - Closes a queue
    /// </summary>
    public const ushort R_CloseQueue = 2;

    /// <summary>
    /// MS-MQRR (RemoteRead): R_CreateCursor - Creates a cursor
    /// </summary>
    public const ushort R_CreateCursor = 3;

    /// <summary>
    /// MS-MQRR (RemoteRead): R_CloseCursor - Closes a cursor
    /// </summary>
    public const ushort R_CloseCursor = 4;

    /// <summary>
    /// MS-MQRR (RemoteRead): R_PurgeQueue - Purges a queue
    /// </summary>
    public const ushort R_PurgeQueue = 5;

    /// <summary>
    /// MS-MQRR (RemoteRead): Opnum6NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort MQRR_Opnum6NotUsedOnWire = 6;

    /// <summary>
    /// MS-MQRR (RemoteRead): R_StartReceive - Starts receiving messages
    /// </summary>
    public const ushort R_StartReceive = 7;

    /// <summary>
    /// MS-MQRR (RemoteRead): R_CancelReceive - Cancels a pending receive
    /// </summary>
    public const ushort R_CancelReceive = 8;

    /// <summary>
    /// MS-MQRR (RemoteRead): R_EndReceive - Ends receiving messages
    /// </summary>
    public const ushort R_EndReceive = 9;

    /// <summary>
    /// MS-MQRR (RemoteRead): R_MoveMessage - Moves a message between queues
    /// </summary>
    public const ushort R_MoveMessage = 10;

    /// <summary>
    /// MS-MQRR (RemoteRead): Opnum11NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort MQRR_Opnum11NotUsedOnWire = 11;

    /// <summary>
    /// MS-MQRR (RemoteRead): Opnum12NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort MQRR_Opnum12NotUsedOnWire = 12;

    /// <summary>
    /// MS-MQRR (RemoteRead): R_StartTransactionalReceive - Starts transactional receive
    /// </summary>
    public const ushort R_StartTransactionalReceive = 13;

    /// <summary>
    /// MS-MQRR (RemoteRead): R_SetUserAcknowledgementClass - Sets user acknowledgement class
    /// </summary>
    public const ushort R_SetUserAcknowledgementClass = 14;

    /// <summary>
    /// MS-MQRR (RemoteRead): R_EndTransactionalReceive - Ends transactional receive
    /// </summary>
    public const ushort R_EndTransactionalReceive = 15;

    #endregion // MS-MQRR
    #region MS-MSRP (msgsvc)

    /// <summary>
    /// MS-MSRP (msgsvc): NetrMessageNameAdd - Adds a message name
    /// </summary>
    public const ushort NetrMessageNameAdd = 0;

    /// <summary>
    /// MS-MSRP (msgsvc): NetrMessageNameEnum - Enumerates message names
    /// </summary>
    public const ushort NetrMessageNameEnum = 1;

    /// <summary>
    /// MS-MSRP (msgsvc): NetrMessageNameGetInfo - Gets message name info
    /// </summary>
    public const ushort NetrMessageNameGetInfo = 2;

    /// <summary>
    /// MS-MSRP (msgsvc): NetrMessageNameDel - Deletes a message name
    /// </summary>
    public const ushort NetrMessageNameDel = 3;

    #endregion // MS-MSRP (msgsvc)
    #region MS-MSRP (msgsvcsend)

    /// <summary>
    /// MS-MSRP (msgsvcsend): NetrSendMessage - Sends a message
    /// </summary>
    public const ushort NetrSendMessage = 0;

    #endregion // MS-MSRP (msgsvcsend)
    #region MS-OCSPA

    /// <summary>
    /// MS-OCSPA (IOCSPAdminD): Opnum0NotUsedOnWire - Reserved (QueryInterface)
    /// </summary>
    public const ushort IOCSPAdminD_Opnum0NotUsedOnWire = 0;

    /// <summary>
    /// MS-OCSPA (IOCSPAdminD): Opnum1NotUsedOnWire - Reserved (AddRef)
    /// </summary>
    public const ushort IOCSPAdminD_Opnum1NotUsedOnWire = 1;

    /// <summary>
    /// MS-OCSPA (IOCSPAdminD): Opnum2NotUsedOnWire - Reserved (Release)
    /// </summary>
    public const ushort IOCSPAdminD_Opnum2NotUsedOnWire = 2;

    /// <summary>
    /// MS-OCSPA (IOCSPAdminD): GetOCSPProperty - Gets an OCSP property
    /// </summary>
    public const ushort GetOCSPProperty = 3;

    /// <summary>
    /// MS-OCSPA (IOCSPAdminD): SetOCSPProperty - Sets an OCSP property
    /// </summary>
    public const ushort SetOCSPProperty = 4;

    /// <summary>
    /// MS-OCSPA (IOCSPAdminD): GetCAConfigInformation - Gets CA config information
    /// </summary>
    public const ushort GetCAConfigInformation = 5;

    /// <summary>
    /// MS-OCSPA (IOCSPAdminD): SetCAConfigInformation - Sets CA config information
    /// </summary>
    public const ushort SetCAConfigInformation = 6;

    /// <summary>
    /// MS-OCSPA (IOCSPAdminD): GetSecurity - Gets security descriptor
    /// </summary>
    public const ushort OCSPA_GetSecurity = 7;

    /// <summary>
    /// MS-OCSPA (IOCSPAdminD): SetSecurity - Sets security descriptor
    /// </summary>
    public const ushort OCSPA_SetSecurity = 8;

    /// <summary>
    /// MS-OCSPA (IOCSPAdminD): GetSigningCertificates - Gets signing certificates
    /// </summary>
    public const ushort GetSigningCertificates = 9;

    /// <summary>
    /// MS-OCSPA (IOCSPAdminD): GetHashAlgorithms - Gets supported hash algorithms
    /// </summary>
    public const ushort GetHashAlgorithms = 10;

    /// <summary>
    /// MS-OCSPA (IOCSPAdminD): GetMyRoles - Gets caller's roles
    /// </summary>
    public const ushort GetMyRoles = 11;

    /// <summary>
    /// MS-OCSPA (IOCSPAdminD): Ping - Pings the OCSP server
    /// </summary>
    public const ushort OCSPA_Ping = 12;

    #endregion // MS-OCSPA
    #region MS-PCQ

    /// <summary>
    /// MS-PCQ (PerflibV2): PerflibV2EnumerateCounterSet - Enumerates counter sets
    /// </summary>
    public const ushort PerflibV2EnumerateCounterSet = 0;

    /// <summary>
    /// MS-PCQ (PerflibV2): PerflibV2QueryCounterSetRegistrationInfo - Queries registration info
    /// </summary>
    public const ushort PerflibV2QueryCounterSetRegistrationInfo = 1;

    /// <summary>
    /// MS-PCQ (PerflibV2): PerflibV2EnumerateCounterSetInstances - Enumerates counter set instances
    /// </summary>
    public const ushort PerflibV2EnumerateCounterSetInstances = 2;

    /// <summary>
    /// MS-PCQ (PerflibV2): PerflibV2OpenQueryHandle - Opens a query handle
    /// </summary>
    public const ushort PerflibV2OpenQueryHandle = 3;

    /// <summary>
    /// MS-PCQ (PerflibV2): PerflibV2CloseQueryHandle - Closes a query handle
    /// </summary>
    public const ushort PerflibV2CloseQueryHandle = 4;

    /// <summary>
    /// MS-PCQ (PerflibV2): PerflibV2QueryCounterInfo - Queries counter information
    /// </summary>
    public const ushort PerflibV2QueryCounterInfo = 5;

    /// <summary>
    /// MS-PCQ (PerflibV2): PerflibV2QueryCounterData - Queries counter data
    /// </summary>
    public const ushort PerflibV2QueryCounterData = 6;

    /// <summary>
    /// MS-PCQ (PerflibV2): PerflibV2ValidateCounters - Validates counter paths
    /// </summary>
    public const ushort PerflibV2ValidateCounters = 7;

    #endregion // MS-PCQ
    #region MS-RAA

    /// <summary>
    /// MS-RAA (authzr): AuthzrFreeContext - Frees an authorization context
    /// </summary>
    public const ushort AuthzrFreeContext = 0;

    /// <summary>
    /// MS-RAA (authzr): AuthzrInitializeContextFromSid - Initializes context from SID
    /// </summary>
    public const ushort AuthzrInitializeContextFromSid = 1;

    /// <summary>
    /// MS-RAA (authzr): AuthzrInitializeCompoundContext - Initializes compound context
    /// </summary>
    public const ushort AuthzrInitializeCompoundContext = 2;

    /// <summary>
    /// MS-RAA (authzr): AuthzrAccessCheck - Performs access check
    /// </summary>
    public const ushort AuthzrAccessCheck = 3;

    /// <summary>
    /// MS-RAA (authzr): AuthzGetInformationFromContext - Gets context information
    /// </summary>
    public const ushort AuthzGetInformationFromContext = 4;

    /// <summary>
    /// MS-RAA (authzr): AuthzrModifyClaims - Modifies claims in context
    /// </summary>
    public const ushort AuthzrModifyClaims = 5;

    /// <summary>
    /// MS-RAA (authzr): AuthzrModifySids - Modifies SIDs in context
    /// </summary>
    public const ushort AuthzrModifySids = 6;

    #endregion // MS-RAA
    #region MS-RAIW (winsif)

    /// <summary>
    /// MS-RAIW (winsif): R_WinsRecordAction - Performs record action
    /// </summary>
    public const ushort R_WinsRecordAction = 0;

    /// <summary>
    /// MS-RAIW (winsif): R_WinsStatus - Gets WINS status
    /// </summary>
    public const ushort R_WinsStatus = 1;

    /// <summary>
    /// MS-RAIW (winsif): R_WinsTrigger - Triggers replication
    /// </summary>
    public const ushort R_WinsTrigger = 2;

    /// <summary>
    /// MS-RAIW (winsif): R_WinsDoStaticInit - Performs static initialization
    /// </summary>
    public const ushort R_WinsDoStaticInit = 3;

    /// <summary>
    /// MS-RAIW (winsif): R_WinsDoScavenging - Performs scavenging
    /// </summary>
    public const ushort R_WinsDoScavenging = 4;

    /// <summary>
    /// MS-RAIW (winsif): R_WinsGetDbRecs - Gets database records
    /// </summary>
    public const ushort R_WinsGetDbRecs = 5;

    /// <summary>
    /// MS-RAIW (winsif): R_WinsTerm - Terminates WINS
    /// </summary>
    public const ushort R_WinsTerm = 6;

    /// <summary>
    /// MS-RAIW (winsif): R_WinsBackup - Backs up WINS database
    /// </summary>
    public const ushort R_WinsBackup = 7;

    /// <summary>
    /// MS-RAIW (winsif): R_WinsDelDbRecs - Deletes database records
    /// </summary>
    public const ushort R_WinsDelDbRecs = 8;

    /// <summary>
    /// MS-RAIW (winsif): R_WinsPullRange - Pulls records in a range
    /// </summary>
    public const ushort R_WinsPullRange = 9;

    /// <summary>
    /// MS-RAIW (winsif): R_WinsSetPriorityClass - Sets priority class
    /// </summary>
    public const ushort R_WinsSetPriorityClass = 10;

    /// <summary>
    /// MS-RAIW (winsif): R_WinsResetCounters - Resets counters
    /// </summary>
    public const ushort R_WinsResetCounters = 11;

    /// <summary>
    /// MS-RAIW (winsif): R_WinsWorkerThdUpd - Updates worker thread
    /// </summary>
    public const ushort R_WinsWorkerThdUpd = 12;

    /// <summary>
    /// MS-RAIW (winsif): R_WinsGetNameAndAdd - Gets name and address
    /// </summary>
    public const ushort R_WinsGetNameAndAdd = 13;

    /// <summary>
    /// MS-RAIW (winsif): R_WinsGetBrowserNames_Old - Gets browser names (old)
    /// </summary>
    public const ushort R_WinsGetBrowserNames_Old = 14;

    /// <summary>
    /// MS-RAIW (winsif): R_WinsDeleteWins - Deletes WINS records
    /// </summary>
    public const ushort R_WinsDeleteWins = 15;

    /// <summary>
    /// MS-RAIW (winsif): R_WinsSetFlags - Sets WINS flags
    /// </summary>
    public const ushort R_WinsSetFlags = 16;

    /// <summary>
    /// MS-RAIW (winsif): R_WinsGetBrowserNames - Gets browser names
    /// </summary>
    public const ushort R_WinsGetBrowserNames = 17;

    /// <summary>
    /// MS-RAIW (winsif): R_WinsGetDbRecsByName - Gets database records by name
    /// </summary>
    public const ushort R_WinsGetDbRecsByName = 18;

    /// <summary>
    /// MS-RAIW (winsif): R_WinsStatusNew - Gets WINS status (new)
    /// </summary>
    public const ushort R_WinsStatusNew = 19;

    /// <summary>
    /// MS-RAIW (winsif): R_WinsStatusWHdl - Gets WINS status with handle
    /// </summary>
    public const ushort R_WinsStatusWHdl = 20;

    /// <summary>
    /// MS-RAIW (winsif): R_WinsDoScavengingNew - Performs scavenging (new)
    /// </summary>
    public const ushort R_WinsDoScavengingNew = 21;

    #endregion // MS-RAIW (winsif)
    #region MS-RAIW (winsi2)

    /// <summary>
    /// MS-RAIW (winsi2): R_WinsTombstoneDbRecs - Tombstones database records
    /// </summary>
    public const ushort R_WinsTombstoneDbRecs = 0;

    /// <summary>
    /// MS-RAIW (winsi2): R_WinsCheckAccess - Checks access rights
    /// </summary>
    public const ushort R_WinsCheckAccess = 1;

    #endregion // MS-RAIW (winsi2)
    #region MS-RPCL

    /// <summary>
    /// MS-RPCL (LocToLoc): I_nsi_lookup_begin - Begins a name service lookup
    /// </summary>
    public const ushort I_nsi_lookup_begin = 0;

    /// <summary>
    /// MS-RPCL (LocToLoc): I_nsi_lookup_done - Completes a name service lookup
    /// </summary>
    public const ushort I_nsi_lookup_done = 1;

    /// <summary>
    /// MS-RPCL (LocToLoc): I_nsi_lookup_next - Gets next lookup result
    /// </summary>
    public const ushort I_nsi_lookup_next = 2;

    /// <summary>
    /// MS-RPCL (LocToLoc): I_nsi_entry_object_inq_next - Gets next object inquiry result
    /// </summary>
    public const ushort I_nsi_entry_object_inq_next = 3;

    /// <summary>
    /// MS-RPCL (LocToLoc): I_nsi_ping_locator - Pings the locator
    /// </summary>
    public const ushort I_nsi_ping_locator = 4;

    /// <summary>
    /// MS-RPCL (LocToLoc): I_nsi_entry_object_inq_done - Completes object inquiry
    /// </summary>
    public const ushort I_nsi_entry_object_inq_done = 5;

    /// <summary>
    /// MS-RPCL (LocToLoc): I_nsi_entry_object_inq_begin - Begins object inquiry
    /// </summary>
    public const ushort I_nsi_entry_object_inq_begin = 6;

    #endregion // MS-RPCL
    #region MS-RRASM (dimsvc)

    /// <summary>
    /// MS-RRASM (dimsvc): RMprAdminServerGetInfo - Gets server info
    /// </summary>
    public const ushort RMprAdminServerGetInfo = 0;

    /// <summary>
    /// MS-RRASM (dimsvc): RRasAdminConnectionEnum - Enumerates connections
    /// </summary>
    public const ushort RRasAdminConnectionEnum = 1;

    /// <summary>
    /// MS-RRASM (dimsvc): RRasAdminConnectionGetInfo - Gets connection info
    /// </summary>
    public const ushort RRasAdminConnectionGetInfo = 2;

    /// <summary>
    /// MS-RRASM (dimsvc): RRasAdminConnectionClearStats - Clears connection stats
    /// </summary>
    public const ushort RRasAdminConnectionClearStats = 3;

    /// <summary>
    /// MS-RRASM (dimsvc): RRasAdminPortEnum - Enumerates ports
    /// </summary>
    public const ushort RRasAdminPortEnum = 4;

    /// <summary>
    /// MS-RRASM (dimsvc): RRasAdminPortGetInfo - Gets port info
    /// </summary>
    public const ushort RRasAdminPortGetInfo = 5;

    /// <summary>
    /// MS-RRASM (dimsvc): RRasAdminPortClearStats - Clears port stats
    /// </summary>
    public const ushort RRasAdminPortClearStats = 6;

    /// <summary>
    /// MS-RRASM (dimsvc): RRasAdminPortReset - Resets a port
    /// </summary>
    public const ushort RRasAdminPortReset = 7;

    /// <summary>
    /// MS-RRASM (dimsvc): RRasAdminPortDisconnect - Disconnects a port
    /// </summary>
    public const ushort RRasAdminPortDisconnect = 8;

    /// <summary>
    /// MS-RRASM (dimsvc): RRouterInterfaceTransportSetGlobalInfo - Sets global transport info
    /// </summary>
    public const ushort RRouterInterfaceTransportSetGlobalInfo = 9;

    /// <summary>
    /// MS-RRASM (dimsvc): RRouterInterfaceTransportGetGlobalInfo - Gets global transport info
    /// </summary>
    public const ushort RRouterInterfaceTransportGetGlobalInfo = 10;

    /// <summary>
    /// MS-RRASM (dimsvc): RRouterInterfaceGetHandle - Gets interface handle
    /// </summary>
    public const ushort RRouterInterfaceGetHandle = 11;

    /// <summary>
    /// MS-RRASM (dimsvc): RRouterInterfaceCreate - Creates an interface
    /// </summary>
    public const ushort RRouterInterfaceCreate = 12;

    /// <summary>
    /// MS-RRASM (dimsvc): RRouterInterfaceGetInfo - Gets interface info
    /// </summary>
    public const ushort RRouterInterfaceGetInfo = 13;

    /// <summary>
    /// MS-RRASM (dimsvc): RRouterInterfaceSetInfo - Sets interface info
    /// </summary>
    public const ushort RRouterInterfaceSetInfo = 14;

    /// <summary>
    /// MS-RRASM (dimsvc): RRouterInterfaceDelete - Deletes an interface
    /// </summary>
    public const ushort RRouterInterfaceDelete = 15;

    /// <summary>
    /// MS-RRASM (dimsvc): RRouterInterfaceTransportRemove - Removes interface transport
    /// </summary>
    public const ushort RRouterInterfaceTransportRemove = 16;

    /// <summary>
    /// MS-RRASM (dimsvc): RRouterInterfaceTransportAdd - Adds interface transport
    /// </summary>
    public const ushort RRouterInterfaceTransportAdd = 17;

    /// <summary>
    /// MS-RRASM (dimsvc): RRouterInterfaceTransportGetInfo - Gets interface transport info
    /// </summary>
    public const ushort RRouterInterfaceTransportGetInfo = 18;

    /// <summary>
    /// MS-RRASM (dimsvc): RRouterInterfaceTransportSetInfo - Sets interface transport info
    /// </summary>
    public const ushort RRouterInterfaceTransportSetInfo = 19;

    /// <summary>
    /// MS-RRASM (dimsvc): RRouterInterfaceEnum - Enumerates interfaces
    /// </summary>
    public const ushort RRouterInterfaceEnum = 20;

    /// <summary>
    /// MS-RRASM (dimsvc): RRouterInterfaceConnect - Connects an interface
    /// </summary>
    public const ushort RRouterInterfaceConnect = 21;

    /// <summary>
    /// MS-RRASM (dimsvc): RRouterInterfaceDisconnect - Disconnects an interface
    /// </summary>
    public const ushort RRouterInterfaceDisconnect = 22;

    /// <summary>
    /// MS-RRASM (dimsvc): RRouterInterfaceUpdateRoutes - Updates interface routes
    /// </summary>
    public const ushort RRouterInterfaceUpdateRoutes = 23;

    /// <summary>
    /// MS-RRASM (dimsvc): RRouterInterfaceQueryUpdateResult - Queries update result
    /// </summary>
    public const ushort RRouterInterfaceQueryUpdateResult = 24;

    /// <summary>
    /// MS-RRASM (dimsvc): RRouterInterfaceUpdatePhonebookInfo - Updates phonebook info
    /// </summary>
    public const ushort RRouterInterfaceUpdatePhonebookInfo = 25;

    /// <summary>
    /// MS-RRASM (dimsvc): RMIBEntryCreate - Creates MIB entry
    /// </summary>
    public const ushort RMIBEntryCreate = 26;

    /// <summary>
    /// MS-RRASM (dimsvc): RMIBEntryDelete - Deletes MIB entry
    /// </summary>
    public const ushort RMIBEntryDelete = 27;

    /// <summary>
    /// MS-RRASM (dimsvc): RMIBEntrySet - Sets MIB entry
    /// </summary>
    public const ushort RMIBEntrySet = 28;

    /// <summary>
    /// MS-RRASM (dimsvc): RMIBEntryGet - Gets MIB entry
    /// </summary>
    public const ushort RMIBEntryGet = 29;

    /// <summary>
    /// MS-RRASM (dimsvc): RMIBEntryGetFirst - Gets first MIB entry
    /// </summary>
    public const ushort RMIBEntryGetFirst = 30;

    /// <summary>
    /// MS-RRASM (dimsvc): RMIBEntryGetNext - Gets next MIB entry
    /// </summary>
    public const ushort RMIBEntryGetNext = 31;

    /// <summary>
    /// MS-RRASM (dimsvc): RMIBGetTrapInfo - Gets MIB trap info
    /// </summary>
    public const ushort RMIBGetTrapInfo = 32;

    /// <summary>
    /// MS-RRASM (dimsvc): RMIBSetTrapInfo - Sets MIB trap info
    /// </summary>
    public const ushort RMIBSetTrapInfo = 33;

    /// <summary>
    /// MS-RRASM (dimsvc): RRasAdminConnectionNotification - Connection notification
    /// </summary>
    public const ushort RRasAdminConnectionNotification = 34;

    /// <summary>
    /// MS-RRASM (dimsvc): RRasAdminSendUserMessage - Sends user message
    /// </summary>
    public const ushort RRasAdminSendUserMessage = 35;

    /// <summary>
    /// MS-RRASM (dimsvc): RRouterDeviceEnum - Enumerates devices
    /// </summary>
    public const ushort RRouterDeviceEnum = 36;

    /// <summary>
    /// MS-RRASM (dimsvc): RRouterInterfaceTransportCreate - Creates interface transport
    /// </summary>
    public const ushort RRouterInterfaceTransportCreate = 37;

    /// <summary>
    /// MS-RRASM (dimsvc): RRouterInterfaceDeviceGetInfo - Gets interface device info
    /// </summary>
    public const ushort RRouterInterfaceDeviceGetInfo = 38;

    /// <summary>
    /// MS-RRASM (dimsvc): RRouterInterfaceDeviceSetInfo - Sets interface device info
    /// </summary>
    public const ushort RRouterInterfaceDeviceSetInfo = 39;

    /// <summary>
    /// MS-RRASM (dimsvc): RRouterInterfaceSetCredentialsEx - Sets credentials (extended)
    /// </summary>
    public const ushort RRouterInterfaceSetCredentialsEx = 40;

    /// <summary>
    /// MS-RRASM (dimsvc): RRouterInterfaceGetCredentialsEx - Gets credentials (extended)
    /// </summary>
    public const ushort RRouterInterfaceGetCredentialsEx = 41;

    /// <summary>
    /// MS-RRASM (dimsvc): RRasAdminConnectionRemoveQuarantine - Removes quarantine
    /// </summary>
    public const ushort RRasAdminConnectionRemoveQuarantine = 42;

    /// <summary>
    /// MS-RRASM (dimsvc): RMprAdminServerSetInfo - Sets server info
    /// </summary>
    public const ushort RMprAdminServerSetInfo = 43;

    /// <summary>
    /// MS-RRASM (dimsvc): RMprAdminServerGetInfoEx - Gets server info (extended)
    /// </summary>
    public const ushort RMprAdminServerGetInfoEx = 44;

    /// <summary>
    /// MS-RRASM (dimsvc): RRasAdminConnectionEnumEx - Enumerates connections (extended)
    /// </summary>
    public const ushort RRasAdminConnectionEnumEx = 45;

    /// <summary>
    /// MS-RRASM (dimsvc): RRasAdminConnectionGetInfoEx - Gets connection info (extended)
    /// </summary>
    public const ushort RRasAdminConnectionGetInfoEx = 46;

    /// <summary>
    /// MS-RRASM (dimsvc): RMprAdminServerSetInfoEx - Sets server info (extended)
    /// </summary>
    public const ushort RMprAdminServerSetInfoEx = 47;

    /// <summary>
    /// MS-RRASM (dimsvc): RRasAdminUpdateConnection - Updates connection
    /// </summary>
    public const ushort RRasAdminUpdateConnection = 48;

    /// <summary>
    /// MS-RRASM (dimsvc): RRouterInterfaceSetCredentialsLocal - Sets local credentials
    /// </summary>
    public const ushort RRouterInterfaceSetCredentialsLocal = 49;

    /// <summary>
    /// MS-RRASM (dimsvc): RRouterInterfaceGetCredentialsLocal - Gets local credentials
    /// </summary>
    public const ushort RRouterInterfaceGetCredentialsLocal = 50;

    /// <summary>
    /// MS-RRASM (dimsvc): RRouterInterfaceGetCustomInfoEx - Gets custom info (extended)
    /// </summary>
    public const ushort RRouterInterfaceGetCustomInfoEx = 51;

    /// <summary>
    /// MS-RRASM (dimsvc): RRouterInterfaceSetCustomInfoEx - Sets custom info (extended)
    /// </summary>
    public const ushort RRouterInterfaceSetCustomInfoEx = 52;

    #endregion // MS-RRASM (dimsvc)
    #region MS-RRASM (rasrpc)

    /// <summary>
    /// MS-RRASM (rasrpc): Opnum0NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort RASRPC_Opnum0NotUsedOnWire = 0;

    /// <summary>
    /// MS-RRASM (rasrpc): Opnum1NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort RASRPC_Opnum1NotUsedOnWire = 1;

    /// <summary>
    /// MS-RRASM (rasrpc): Opnum2NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort RASRPC_Opnum2NotUsedOnWire = 2;

    /// <summary>
    /// MS-RRASM (rasrpc): Opnum3NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort RASRPC_Opnum3NotUsedOnWire = 3;

    /// <summary>
    /// MS-RRASM (rasrpc): Opnum4NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort RASRPC_Opnum4NotUsedOnWire = 4;

    /// <summary>
    /// MS-RRASM (rasrpc): RasRpcDeleteEntry - Deletes a phonebook entry
    /// </summary>
    public const ushort RasRpcDeleteEntry = 5;

    /// <summary>
    /// MS-RRASM (rasrpc): Opnum6NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort RASRPC_Opnum6NotUsedOnWire = 6;

    /// <summary>
    /// MS-RRASM (rasrpc): Opnum7NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort RASRPC_Opnum7NotUsedOnWire = 7;

    /// <summary>
    /// MS-RRASM (rasrpc): Opnum8NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort RASRPC_Opnum8NotUsedOnWire = 8;

    /// <summary>
    /// MS-RRASM (rasrpc): RasRpcGetUserPreferences - Gets user preferences
    /// </summary>
    public const ushort RasRpcGetUserPreferences = 9;

    /// <summary>
    /// MS-RRASM (rasrpc): RasRpcSetUserPreferences - Sets user preferences
    /// </summary>
    public const ushort RasRpcSetUserPreferences = 10;

    /// <summary>
    /// MS-RRASM (rasrpc): RasRpcGetSystemDirectory - Gets system directory
    /// </summary>
    public const ushort RasRpcGetSystemDirectory = 11;

    /// <summary>
    /// MS-RRASM (rasrpc): RasRpcSubmitRequest - Submits a request
    /// </summary>
    public const ushort RasRpcSubmitRequest = 12;

    /// <summary>
    /// MS-RRASM (rasrpc): Opnum13NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort RASRPC_Opnum13NotUsedOnWire = 13;

    /// <summary>
    /// MS-RRASM (rasrpc): RasRpcGetInstalledProtocolsEx - Gets installed protocols
    /// </summary>
    public const ushort RasRpcGetInstalledProtocolsEx = 14;

    /// <summary>
    /// MS-RRASM (rasrpc): RasRpcGetVersion - Gets RAS version
    /// </summary>
    public const ushort RasRpcGetVersion = 15;

    #endregion // MS-RRASM (rasrpc)
    #region MS-TRP (tapsrv)

    /// <summary>
    /// MS-TRP (tapsrv): ClientAttach - Attaches client to telephony server
    /// </summary>
    public const ushort ClientAttach = 0;

    /// <summary>
    /// MS-TRP (tapsrv): ClientRequest - Sends request from client to server
    /// </summary>
    public const ushort ClientRequest = 1;

    /// <summary>
    /// MS-TRP (tapsrv): ClientDetach - Detaches client from telephony server
    /// </summary>
    public const ushort ClientDetach = 2;

    #endregion // MS-TRP (tapsrv)
    #region MS-TRP (remotesp)

    /// <summary>
    /// MS-TRP (remotesp): RemoteSPAttach - Attaches remote service provider
    /// </summary>
    public const ushort RemoteSPAttach = 0;

    /// <summary>
    /// MS-TRP (remotesp): RemoteSPEventProc - Event procedure for remote SP
    /// </summary>
    public const ushort RemoteSPEventProc = 1;

    /// <summary>
    /// MS-TRP (remotesp): RemoteSPDetach - Detaches remote service provider
    /// </summary>
    public const ushort RemoteSPDetach = 2;

    #endregion // MS-TRP (remotesp)
    #region MS-TSGU

    /// <summary>
    /// MS-TSGU: Opnum0NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort TSGU_Opnum0NotUsedOnWire = 0;

    /// <summary>
    /// MS-TSGU: TsProxyCreateTunnel - Creates a tunnel
    /// </summary>
    public const ushort TsProxyCreateTunnel = 1;

    /// <summary>
    /// MS-TSGU: TsProxyAuthorizeTunnel - Authorizes a tunnel
    /// </summary>
    public const ushort TsProxyAuthorizeTunnel = 2;

    /// <summary>
    /// MS-TSGU: TsProxyMakeTunnelCall - Makes a tunnel call
    /// </summary>
    public const ushort TsProxyMakeTunnelCall = 3;

    /// <summary>
    /// MS-TSGU: TsProxyCreateChannel - Creates a channel
    /// </summary>
    public const ushort TsProxyCreateChannel = 4;

    /// <summary>
    /// MS-TSGU: Opnum5NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort TSGU_Opnum5NotUsedOnWire = 5;

    /// <summary>
    /// MS-TSGU: TsProxyCloseChannel - Closes a channel
    /// </summary>
    public const ushort TsProxyCloseChannel = 6;

    /// <summary>
    /// MS-TSGU: TsProxyCloseTunnel - Closes a tunnel
    /// </summary>
    public const ushort TsProxyCloseTunnel = 7;

    /// <summary>
    /// MS-TSGU: TsProxySetupReceivePipe - Sets up receive pipe
    /// </summary>
    public const ushort TsProxySetupReceivePipe = 8;

    /// <summary>
    /// MS-TSGU: TsProxySendToServer - Sends data to server
    /// </summary>
    public const ushort TsProxySendToServer = 9;

    #endregion // MS-TSGU
    #region MS-TSRAP

    /// <summary>
    /// MS-TSRAP: Opnum0NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort TSRAP_Opnum0NotUsedOnWire = 0;

    /// <summary>
    /// MS-TSRAP: Opnum1NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort TSRAP_Opnum1NotUsedOnWire = 1;

    /// <summary>
    /// MS-TSRAP: Opnum2NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort TSRAP_Opnum2NotUsedOnWire = 2;

    /// <summary>
    /// MS-TSRAP: Opnum3NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort TSRAP_Opnum3NotUsedOnWire = 3;

    /// <summary>
    /// MS-TSRAP: Opnum4NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort TSRAP_Opnum4NotUsedOnWire = 4;

    /// <summary>
    /// MS-TSRAP: Opnum5NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort TSRAP_Opnum5NotUsedOnWire = 5;

    /// <summary>
    /// MS-TSRAP: Opnum6NotUsedOnWire - Reserved for local use
    /// </summary>
    public const ushort TSRAP_Opnum6NotUsedOnWire = 6;

    /// <summary>
    /// MS-TSRAP: GetTelnetSessions - Gets telnet sessions
    /// </summary>
    public const ushort GetTelnetSessions = 7;

    /// <summary>
    /// MS-TSRAP: TerminateSession - Terminates a session
    /// </summary>
    public const ushort TerminateSession = 8;

    /// <summary>
    /// MS-TSRAP: SendMsgToASession - Sends message to a session
    /// </summary>
    public const ushort SendMsgToASession = 9;

    #endregion // MS-TSRAP
    #region MS-WDSC

    /// <summary>
    /// MS-WDSC: WdsRpcMessage - Processes WDS RPC message
    /// </summary>
    public const ushort WdsRpcMessage = 0;

    #endregion // MS-WDSC
    #region MS-FASP

    /// <summary>
    /// MS-FASP (RemoteFW): RRPC_FWOpenPolicyStore - Opens policy store
    /// </summary>
    public const ushort RRPC_FWOpenPolicyStore = 0;

    /// <summary>
    /// MS-FASP (RemoteFW): RRPC_FWClosePolicyStore - Closes policy store
    /// </summary>
    public const ushort RRPC_FWClosePolicyStore = 1;

    /// <summary>
    /// MS-FASP (RemoteFW): RRPC_FWRestoreDefaults - Restores default settings
    /// </summary>
    public const ushort RRPC_FWRestoreDefaults = 2;

    /// <summary>
    /// MS-FASP (RemoteFW): RRPC_FWGetGlobalConfig - Gets global configuration
    /// </summary>
    public const ushort RRPC_FWGetGlobalConfig = 3;

    /// <summary>
    /// MS-FASP (RemoteFW): RRPC_FWSetGlobalConfig - Sets global configuration
    /// </summary>
    public const ushort RRPC_FWSetGlobalConfig = 4;

    /// <summary>
    /// MS-FASP (RemoteFW): RRPC_FWAddFirewallRule - Adds a firewall rule
    /// </summary>
    public const ushort RRPC_FWAddFirewallRule = 5;

    /// <summary>
    /// MS-FASP (RemoteFW): RRPC_FWSetFirewallRule - Sets a firewall rule
    /// </summary>
    public const ushort RRPC_FWSetFirewallRule = 6;

    /// <summary>
    /// MS-FASP (RemoteFW): RRPC_FWDeleteFirewallRule - Deletes a firewall rule
    /// </summary>
    public const ushort RRPC_FWDeleteFirewallRule = 7;

    /// <summary>
    /// MS-FASP (RemoteFW): RRPC_FWDeleteAllFirewallRules - Deletes all firewall rules
    /// </summary>
    public const ushort RRPC_FWDeleteAllFirewallRules = 8;

    /// <summary>
    /// MS-FASP (RemoteFW): RRPC_FWEnumFirewallRules - Enumerates firewall rules
    /// </summary>
    public const ushort RRPC_FWEnumFirewallRules = 9;

    /// <summary>
    /// MS-FASP (RemoteFW): RRPC_FWGetConfig - Gets configuration
    /// </summary>
    public const ushort RRPC_FWGetConfig = 10;

    /// <summary>
    /// MS-FASP (RemoteFW): RRPC_FWSetConfig - Sets configuration
    /// </summary>
    public const ushort RRPC_FWSetConfig = 11;

    /// <summary>
    /// MS-FASP (RemoteFW): RRPC_FWAddConnectionSecurityRule - Adds connection security rule
    /// </summary>
    public const ushort RRPC_FWAddConnectionSecurityRule = 12;

    /// <summary>
    /// MS-FASP (RemoteFW): RRPC_FWSetConnectionSecurityRule - Sets connection security rule
    /// </summary>
    public const ushort RRPC_FWSetConnectionSecurityRule = 13;

    /// <summary>
    /// MS-FASP (RemoteFW): RRPC_FWDeleteConnectionSecurityRule - Deletes connection security rule
    /// </summary>
    public const ushort RRPC_FWDeleteConnectionSecurityRule = 14;

    /// <summary>
    /// MS-FASP (RemoteFW): RRPC_FWDeleteAllConnectionSecurityRules - Deletes all connection security rules
    /// </summary>
    public const ushort RRPC_FWDeleteAllConnectionSecurityRules = 15;

    /// <summary>
    /// MS-FASP (RemoteFW): RRPC_FWEnumConnectionSecurityRules - Enumerates connection security rules
    /// </summary>
    public const ushort RRPC_FWEnumConnectionSecurityRules = 16;

    /// <summary>
    /// MS-FASP (RemoteFW): RRPC_FWAddAuthenticationSet - Adds authentication set
    /// </summary>
    public const ushort RRPC_FWAddAuthenticationSet = 17;

    /// <summary>
    /// MS-FASP (RemoteFW): RRPC_FWSetAuthenticationSet - Sets authentication set
    /// </summary>
    public const ushort RRPC_FWSetAuthenticationSet = 18;

    /// <summary>
    /// MS-FASP (RemoteFW): RRPC_FWDeleteAuthenticationSet - Deletes authentication set
    /// </summary>
    public const ushort RRPC_FWDeleteAuthenticationSet = 19;

    /// <summary>
    /// MS-FASP (RemoteFW): RRPC_FWDeleteAllAuthenticationSets - Deletes all authentication sets
    /// </summary>
    public const ushort RRPC_FWDeleteAllAuthenticationSets = 20;

    /// <summary>
    /// MS-FASP (RemoteFW): RRPC_FWEnumAuthenticationSets - Enumerates authentication sets
    /// </summary>
    public const ushort RRPC_FWEnumAuthenticationSets = 21;

    /// <summary>
    /// MS-FASP (RemoteFW): RRPC_FWAddCryptoSet - Adds crypto set
    /// </summary>
    public const ushort RRPC_FWAddCryptoSet = 22;

    /// <summary>
    /// MS-FASP (RemoteFW): RRPC_FWSetCryptoSet - Sets crypto set
    /// </summary>
    public const ushort RRPC_FWSetCryptoSet = 23;

    /// <summary>
    /// MS-FASP (RemoteFW): RRPC_FWDeleteCryptoSet - Deletes crypto set
    /// </summary>
    public const ushort RRPC_FWDeleteCryptoSet = 24;

    /// <summary>
    /// MS-FASP (RemoteFW): RRPC_FWDeleteAllCryptoSets - Deletes all crypto sets
    /// </summary>
    public const ushort RRPC_FWDeleteAllCryptoSets = 25;

    /// <summary>
    /// MS-FASP (RemoteFW): RRPC_FWEnumCryptoSets - Enumerates crypto sets
    /// </summary>
    public const ushort RRPC_FWEnumCryptoSets = 26;

    /// <summary>
    /// MS-FASP (RemoteFW): RRPC_FWEnumPhase1SAs - Enumerates phase 1 SAs
    /// </summary>
    public const ushort RRPC_FWEnumPhase1SAs = 27;

    /// <summary>
    /// MS-FASP (RemoteFW): RRPC_FWEnumPhase2SAs - Enumerates phase 2 SAs
    /// </summary>
    public const ushort RRPC_FWEnumPhase2SAs = 28;

    /// <summary>
    /// MS-FASP (RemoteFW): RRPC_FWDeletePhase1SAs - Deletes phase 1 SAs
    /// </summary>
    public const ushort RRPC_FWDeletePhase1SAs = 29;

    /// <summary>
    /// MS-FASP (RemoteFW): RRPC_FWDeletePhase2SAs - Deletes phase 2 SAs
    /// </summary>
    public const ushort RRPC_FWDeletePhase2SAs = 30;

    /// <summary>
    /// MS-FASP (RemoteFW): RRPC_FWEnumProducts - Enumerates firewall products
    /// </summary>
    public const ushort RRPC_FWEnumProducts = 31;

    /// <summary>
    /// MS-FASP (RemoteFW): RRPC_FWAddMainModeRule - Adds main mode rule
    /// </summary>
    public const ushort RRPC_FWAddMainModeRule = 32;

    /// <summary>
    /// MS-FASP (RemoteFW): RRPC_FWSetMainModeRule - Sets main mode rule
    /// </summary>
    public const ushort RRPC_FWSetMainModeRule = 33;

    /// <summary>
    /// MS-FASP (RemoteFW): RRPC_FWDeleteMainModeRule - Deletes main mode rule
    /// </summary>
    public const ushort RRPC_FWDeleteMainModeRule = 34;

    /// <summary>
    /// MS-FASP (RemoteFW): RRPC_FWDeleteAllMainModeRules - Deletes all main mode rules
    /// </summary>
    public const ushort RRPC_FWDeleteAllMainModeRules = 35;

    /// <summary>
    /// MS-FASP (RemoteFW): RRPC_FWEnumMainModeRules - Enumerates main mode rules
    /// </summary>
    public const ushort RRPC_FWEnumMainModeRules = 36;

    /// <summary>
    /// MS-FASP (RemoteFW): RRPC_FWQueryFirewallRules - Queries firewall rules
    /// </summary>
    public const ushort RRPC_FWQueryFirewallRules = 37;

    /// <summary>
    /// MS-FASP (RemoteFW): RRPC_FWQueryConnectionSecurityRules2_10 - Queries connection security rules (2.10)
    /// </summary>
    public const ushort RRPC_FWQueryConnectionSecurityRules2_10 = 38;

    /// <summary>
    /// MS-FASP (RemoteFW): RRPC_FWQueryMainModeRules - Queries main mode rules
    /// </summary>
    public const ushort RRPC_FWQueryMainModeRules = 39;

    /// <summary>
    /// MS-FASP (RemoteFW): RRPC_FWQueryAuthenticationSets - Queries authentication sets
    /// </summary>
    public const ushort RRPC_FWQueryAuthenticationSets = 40;

    /// <summary>
    /// MS-FASP (RemoteFW): RRPC_FWQueryCryptoSets - Queries crypto sets
    /// </summary>
    public const ushort RRPC_FWQueryCryptoSets = 41;

    /// <summary>
    /// MS-FASP (RemoteFW): RRPC_FWEnumNetworks - Enumerates networks
    /// </summary>
    public const ushort RRPC_FWEnumNetworks = 42;

    /// <summary>
    /// MS-FASP (RemoteFW): RRPC_FWEnumAdapters - Enumerates adapters
    /// </summary>
    public const ushort RRPC_FWEnumAdapters = 43;

    /// <summary>
    /// MS-FASP (RemoteFW): RRPC_FWGetGlobalConfig2_10 - Gets global configuration (2.10)
    /// </summary>
    public const ushort RRPC_FWGetGlobalConfig2_10 = 44;

    /// <summary>
    /// MS-FASP (RemoteFW): RRPC_FWGetConfig2_10 - Gets configuration (2.10)
    /// </summary>
    public const ushort RRPC_FWGetConfig2_10 = 45;

    #endregion // MS-FASP
    #region MS-PLA (ITraceDataProvider)

    // ITraceDataProvider interface methods (IDispatch base ends at opnum 6)

    /// <summary>
    /// MS-PLA (ITraceDataProvider): get_DisplayName - Gets provider display name
    /// </summary>
    public const ushort get_DisplayName = 7;

    /// <summary>
    /// MS-PLA (ITraceDataProvider): put_DisplayName - Sets provider display name
    /// </summary>
    public const ushort put_DisplayName = 8;

    /// <summary>
    /// MS-PLA (ITraceDataProvider): get_Guid - Gets provider GUID
    /// </summary>
    public const ushort get_Guid = 9;

    /// <summary>
    /// MS-PLA (ITraceDataProvider): put_Guid - Sets provider GUID
    /// </summary>
    public const ushort put_Guid = 10;

    /// <summary>
    /// MS-PLA (ITraceDataProvider): get_Level - Gets trace level
    /// </summary>
    public const ushort get_Level = 11;

    /// <summary>
    /// MS-PLA (ITraceDataProvider): get_KeywordsAny - Gets keywords any mask
    /// </summary>
    public const ushort get_KeywordsAny = 12;

    /// <summary>
    /// MS-PLA (ITraceDataProvider): get_KeywordsAll - Gets keywords all mask
    /// </summary>
    public const ushort get_KeywordsAll = 13;

    /// <summary>
    /// MS-PLA (ITraceDataProvider): get_Properties - Gets provider properties
    /// </summary>
    public const ushort get_Properties = 14;

    /// <summary>
    /// MS-PLA (ITraceDataProvider): get_FilterEnabled - Gets filter enabled state
    /// </summary>
    public const ushort get_FilterEnabled = 15;

    /// <summary>
    /// MS-PLA (ITraceDataProvider): put_FilterEnabled - Sets filter enabled state
    /// </summary>
    public const ushort put_FilterEnabled = 16;

    /// <summary>
    /// MS-PLA (ITraceDataProvider): get_FilterType - Gets filter type
    /// </summary>
    public const ushort get_FilterType = 17;

    /// <summary>
    /// MS-PLA (ITraceDataProvider): put_FilterType - Sets filter type
    /// </summary>
    public const ushort put_FilterType = 18;

    /// <summary>
    /// MS-PLA (ITraceDataProvider): get_FilterData - Gets filter data
    /// </summary>
    public const ushort get_FilterData = 19;

    /// <summary>
    /// MS-PLA (ITraceDataProvider): put_FilterData - Sets filter data
    /// </summary>
    public const ushort put_FilterData = 20;

    /// <summary>
    /// MS-PLA (ITraceDataProvider): Query - Queries provider by name
    /// </summary>
    public const ushort Query = 21;

    /// <summary>
    /// MS-PLA (ITraceDataProvider): Resolve - Resolves provider from another object
    /// </summary>
    public const ushort Resolve = 22;

    /// <summary>
    /// MS-PLA (ITraceDataProvider): SetSecurity - Sets security descriptor
    /// </summary>
    public const ushort PLA_SetSecurity = 23;

    /// <summary>
    /// MS-PLA (ITraceDataProvider): GetSecurity - Gets security descriptor
    /// </summary>
    public const ushort PLA_GetSecurity = 24;

    /// <summary>
    /// MS-PLA (ITraceDataProvider): GetRegisteredProcesses - Gets registered processes
    /// </summary>
    public const ushort GetRegisteredProcesses = 25;

    #endregion // MS-PLA
}
