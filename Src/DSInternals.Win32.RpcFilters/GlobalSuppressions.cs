// This file is used by Code Analysis to maintain SuppressMessage
// attributes that are applied to this project.
// Project-level suppressions either have no target or are given
// a specific target and scoped to a namespace, type, member, etc.

using System.Diagnostics.CodeAnalysis;

[assembly: SuppressMessage("Style", "IDE0130:Namespace does not match folder structure", Justification = "Some types are intentionally put into subdirectories.", Scope = "namespace", Target = "~N:DSInternals.Win32.RpcFilters")]
[assembly: SuppressMessage("Interoperability", "SYSLIB1054:Use 'LibraryImportAttribute' instead of 'DllImportAttribute' to generate P/Invoke marshalling code at compile time", Justification = "The feature is incompatible with .NET Framework, which must be targeted as well.")]
[assembly: SuppressMessage("Naming", "CA1707:Identifiers should not contain underscores", Justification = "Many members correspond to RPC operation names that are defined with underscores.")]
[assembly: SuppressMessage("Naming", "CA1711:Identifiers should not have incorrect suffix", Justification = "Some Win32 API function names end with 'Ex'.")]
[assembly: SuppressMessage("Usage", "CA2201:Do not raise reserved exception types", Justification = "The OutOfMemoryException is thrown as a result of Win32 API calls.")]
