# <a id="DSInternals_Win32_RpcFilters_WellKnownOperation"></a> Enum WellKnownOperation

Namespace: [DSInternals.Win32.RpcFilters](DSInternals.Win32.RpcFilters.md)  
Assembly: DSInternals.Win32.RpcFilters.dll  

Well-known RPC protocol operations.

```csharp
public enum WellKnownOperation
```

#### Extension Methods

[WellKnownProtocolTranslator.ToOperationNumber\(WellKnownOperation\)](DSInternals.Win32.RpcFilters.WellKnownProtocolTranslator.md\#DSInternals\_Win32\_RpcFilters\_WellKnownProtocolTranslator\_ToOperationNumber\_DSInternals\_Win32\_RpcFilters\_WellKnownOperation\_)

## Fields

`BaseRegCreateKey = 10` 

The BaseRegCreateKey (MS-RRP) method creates the specified registry key.



`BaseRegSetValue = 11` 

The BaseRegSetValue (MS-RRP) method sets the data for the specified value of a registry key.



`EfsRpcAddUsersToFile = 32` 

The EfsRpcAddUsersToFile (MS-EFSR) method is used to grant the possessors of the private keys corresponding to certain X.509 certificates the ability to decrypt the object.



`EfsRpcDecryptFileSrv = 28` 

The EfsRpcDecryptFileSrv (MS-EFSR) method is used to convert an existing encrypted object to the unencrypted state in the server's data store.



`EfsRpcEncryptFileSrv = 27` 

The EfsRpcEncryptFileSrv (MS-EFSR) method is used to convert a given object on the server to an encrypted state in the server's data store.



`EfsRpcOpenFileRaw = 26` 

The EfsRpcOpenFileRaw (MS-EFSR) method is used to open an encrypted object on the server for backup or restore.



`EfsRpcQueryRecoveryAgents = 30` 

The EfsRpcQueryRecoveryAgents (MS-EFSR) method is used to query the EFSRPC Metadata of an encrypted object for the X.509 certificates of the data recovery agents whose private keys can be used to decrypt the object.



`EfsRpcQueryUsersOnFile = 29` 

The EfsRpcQueryUsersOnFile (MS-EFSR) method is used by the client to query the metadata of an encrypted object for the X.509 certificates whose associated private keys can be used to decrypt the object.



`EfsRpcRemoveUsersFromFile = 31` 

The EfsRpcRemoveUsersFromFile (MS-EFSR) method is used to revoke a user's access to an encrypted object.



`ElfrClearELFA = 2` 

The ElfrClearELFA (MS-EVEN) method instructs the server to clear an event log.



`ElfrClearELFW = 1` 

The ElfrClearELFW (MS-EVEN) method instructs the server to clear an event log.



`EvtRpcClearLog = 0` 

The EvtRpcClearLog (MS-EVEN6) method instructs the server to clear all the events in a live channel.



`IDL_DRSGetNCChanges = 8` 

The IDL_DRSGetNCChanges (MS-DRSR) method replicates updates from an NC replica on the server.



`IDL_DRSReplicaAdd = 9` 

The IDL_DRSReplicaAdd (MS-DRSR) method adds a replication source reference for the specified NC.



`IsPathShadowCopied = 34` 

The IsPathShadowCopied (MS-FSRVP) method is invoked by the client to query if any shadow copy for a share already exists.



`IsPathSupported = 33` 

The IsPathSupported (MS-FSRVP) method is invoked by the client to query if a given share is supported by the server for shadow copy operations.



`LsarRetrievePrivateData = 24` 

The LsarRetrievePrivateData (MS-LSAD) method is invoked to retrieve a secret value.



`LsarRetrievePrivateData2 = 25` 

The LsarRetrievePrivateData2 (MS-LSAD) method is invoked to retrieve a secret value.



`NetrConnectionEnum = 17` 

The NetrConnectionEnum (MS-SRVS) method lists the treeconnects made to a shared resource on the server.



`NetrDfsAddRootTarget = 37` 

The NetrDfsAddRootTarget (MS-DFSNM) method is used to create a stand-alone DFS namespace, a domainv1-based DFS namespace, or a domainv2-based DFS namespace.



`NetrDfsAddStdRoot = 35` 

The NetrDfsAddStdRoot (MS-DFSNM) method creates a new stand-alone DFS namespace.



`NetrDfsRemoveRootTarget = 38` 

The NetrDfsRemoveRootTarget (MS-DFSNM) method is the unified DFS namespace deletion method.



`NetrDfsRemoveStdRoot = 36` 

The NetrDfsRemoveStdRoot (MS-DFSNM) method deletes the specified stand-alone DFS namespace.



`NetrFileEnum = 14` 

The NetrFileEnum (MS-SRVS) method returns information about open files on a server.



`NetrJobAdd = 13` 

The NetrJobAdd (MS-TSCH) method add a single AT task to the server's task store.



`NetrSessionEnum = 15` 

The NetrSessionEnum (MS-SRVS) method returns information about sessions that are established on a server.



`NetrShareEnum = 16` 

The NetrShareEnum (MS-SRVS) method retrieves information about each shared resource on a server.



`RCreateServiceA = 4` 

The RCreateServiceA (MS-SCMR) method creates the service record in the SCM database.



`RCreateServiceW = 3` 

The RCreateServiceW (MS-SCMR) method creates the service record in the SCM database.



`RCreateServiceWOW64A = 5` 

The RCreateServiceWOW64A (MS-SCMR) method creates the service record for a 32-bit service on a 64-bit system.



`RCreateServiceWOW64W = 6` 

The RCreateServiceWOW64W (MS-SCMR) method creates the service record for a 32-bit service on a 64-bit system.



`RCreateWowService = 7` 

The RCreateWowService (MS-SCMR) method creates a service whose binary is compiled for a specified computer architecture.



`RpcAddPrinterDriverEx = 19` 

The RpcAddPrinterDriverEx (MS-RPRN) method installs a printer driver on the print server.



`RpcAsyncAddPrinterDriver = 18` 

The RpcAsyncAddPrinterDriver (MS-PAR) method installs a specified local or a remote printer driver on a specified print server.



`RpcRemoteFindFirstPrinterChangeNotification = 20` 

The RpcRemoteFindFirstPrinterChangeNotification (MS-RPRN) method creates a remote change notification object that monitors changes to printer objects and sends change notifications to a print client.



`RpcRemoteFindFirstPrinterChangeNotificationEx = 21` 

The RpcRemoteFindFirstPrinterChangeNotification (MS-RPRN) method creates a remote change notification object that monitors changes to printer objects and sends change notifications to a print client.



`SamrEnumerateGroupsInDomain = 22` 

The SamrEnumerateGroupsInDomain (MS-SAMR) method enumerates all groups.



`SamrEnumerateUsersInDomain = 23` 

The SamrEnumerateUsersInDomain (MS-SAMR) method enumerates all users.



`SchRpcRegisterTask = 12` 

The SchRpcRegisterTask (MS-TSCH) method registers a task in the Task Scheduler service.



