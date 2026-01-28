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
    public const ushort Ping = 5;

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
    public const ushort Ping2 = 9;

    #endregion // MS-WCCE
}
