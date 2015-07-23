# Introduction #

This is a list of Volatility 2.1 features organized by plugins and categories. Before using these plugins, make sure to read the BasicUsage instructions. To see example use cases and example output from the plugins, see the CommandReference21 or click on the name of the plugin.

## Image Identification ##

|Command|Description|OS Support|
|:------|:----------|:---------|
|[imageinfo](http://code.google.com/p/volatility/wiki/CommandReference21#imageinfo)|Identity information for the image|All       |
|[kdbgscan](http://code.google.com/p/volatility/wiki/CommandReference21#kdbgscan)|Search for and dump potential KDBG values|All       |
|[kpcrscan](http://code.google.com/p/volatility/wiki/CommandReference21#kpcrscan)|Search for and dump potential KPCR values|All       |

## Processes and DLLs ##

|Command|Description|OS Support|
|:------|:----------|:---------|
|[pslist](http://code.google.com/p/volatility/wiki/CommandReference21#pslist)|Print all running processes by following the EPROCESS lists|All       |
|[pstree](http://code.google.com/p/volatility/wiki/CommandReference21#pstree)|Print process list as a tree|All       |
|[psscan](http://code.google.com/p/volatility/wiki/CommandReference21#psscan)|Scan Physical memory for EPROCESS pool allocations|All       |
|[psdispscan](http://code.google.com/p/volatility/wiki/CommandReference21#psdispscan)|Scan Physical memory for EPROCESS objects based on their Dispatch Headers|Only Windows XP x86|
|[dlllist](http://code.google.com/p/volatility/wiki/CommandReference21#dlllist)|Print list of loaded dlls for each process|All       |
|[dlldump](http://code.google.com/p/volatility/wiki/CommandReference21#dlldump)|Dump DLLs from a process address space|All       |
|[handles](http://code.google.com/p/volatility/wiki/CommandReference21#handles)|Print list of open handles for each process|All       |
|[getsids](http://code.google.com/p/volatility/wiki/CommandReference21#getsids)|Print the SIDs owning each process|All       |
|[cmdscan](http://code.google.com/p/volatility/wiki/CommandReference21#cmdscan)|Extract command history by scanning for COMMAND\_HISTORY|All except Windows 7 x64 (patch available, see [Issue #318](https://code.google.com/p/volatility/issues/detail?id=#318))|
|[consoles](http://code.google.com/p/volatility/wiki/CommandReference21#consoles)|Extract command history by scanning for CONSOLE\_INFORMATION|All except Windows 7 x64 (patch available, see [Issue #318](https://code.google.com/p/volatility/issues/detail?id=#318))|
|[envars](http://code.google.com/p/volatility/wiki/CommandReference21#envars)|Display process environment variables|All       |
|[verinfo](http://code.google.com/p/volatility/wiki/CommandReference21#verinfo)|Prints out the version information from PE images|All       |
|[enumfunc](http://code.google.com/p/volatility/wiki/CommandReference21#enumfunc)|Enumerate imported and exported functions|All       |

## Processes Memory ##

|Command|Description|OS Support|
|:------|:----------|:---------|
|[memmap](http://code.google.com/p/volatility/wiki/CommandReference21#memmap)|Print the virtual addresses, physical addresses, and size of each page accessible to a process|All       |
|[memdump](http://code.google.com/p/volatility/wiki/CommandReference21#memdump)|Dump the addressable memory for a process|All       |
|[procmemdump](http://code.google.com/p/volatility/wiki/CommandReference21#procmemdump)|Extract a process's executable, preserving slack space|All       |
|[procexedump](http://code.google.com/p/volatility/wiki/CommandReference21#procexedump)|Extract a process's executable, do not preserve slack space|All       |
|[vadwalk](http://code.google.com/p/volatility/wiki/CommandReference21#vadwalk)|Walk the VAD tree and print basic information|All       |
|[vadtree](http://code.google.com/p/volatility/wiki/CommandReference21#vadtree)|Walk the VAD tree and display in tree format|All       |
|[vadinfo](http://code.google.com/p/volatility/wiki/CommandReference21#vadinfo)|Walk the VAD tree and print extended information|All       |
|[vaddump](http://code.google.com/p/volatility/wiki/CommandReference21#vaddump)|Dumps out the VAD sections to a file|All       |

## Kernel Memory and Objects ##

|Command|Description|OS Support|
|:------|:----------|:---------|
|[modules](http://code.google.com/p/volatility/wiki/CommandReference21#modules)|Print list of loaded kernel modules|All       |
|[modscan](http://code.google.com/p/volatility/wiki/CommandReference21#modscan)|Scan physical memory for LDR\_DATA\_TABLE\_ENTRY objects|All       |
|[moddump](http://code.google.com/p/volatility/wiki/CommandReference21#moddump)|Dump a kernel driver to an executable file sample|All       |
|[ssdt](http://code.google.com/p/volatility/wiki/CommandReference21#ssdt)|Display SSDT entries|All       |
|[driverscan](http://code.google.com/p/volatility/wiki/CommandReference21#driverscan)|Scan physical memory for DRIVER\_OBJECT objects|All       |
|[filescan](http://code.google.com/p/volatility/wiki/CommandReference21#filescan)|Scan physical memory for FILE\_OBJECT objects|All       |
|[mutantscan](http://code.google.com/p/volatility/wiki/CommandReference21#mutantscan)|Scan physical memory for KMUTANT objects|All       |
|[symlinkscan](http://code.google.com/p/volatility/wiki/CommandReference21#symlinkscan) |Scans for symbolic link objects|All       |
|[thrdscan](http://code.google.com/p/volatility/wiki/CommandReference21#thrdscan)|Scan physical memory for ETHREAD objects|All       |

## Networking ##

|Command|Description|OS Support|
|:------|:----------|:---------|
|[connections](http://code.google.com/p/volatility/wiki/CommandReference21#connections)|Print a list of open TCP connections|Only Windows XP and 2003|
|[connscan](http://code.google.com/p/volatility/wiki/CommandReference21#connscan)|Scan physical memory for connection objects|Only Windows XP and 2003|
|[sockets](http://code.google.com/p/volatility/wiki/CommandReference21#sockets)|Print a list of open sockets|Only Windows XP and 2003|
|[sockscan](http://code.google.com/p/volatility/wiki/CommandReference21#sockscan)|Scan physical memory for socket objects|Only Windows XP and 2003|
|[netscan](http://code.google.com/p/volatility/wiki/CommandReference21#netscan)|Scan a Vista, 2008 or Windows 7 image for connections and sockets|Only Windows Vista, 2008 and 7|

## Registry ##

|Command|Description|OS Support|
|:------|:----------|:---------|
|[hivescan](http://code.google.com/p/volatility/wiki/CommandReference21#hivescan)|Scan Physical memory for _CMHIVE objects (registry hives)_|All       |
|[hivelist](http://code.google.com/p/volatility/wiki/CommandReference21#hivelist)|Walk the linked list of registry hives and print their virtual addresses and corresponding paths on disk|All       |
|[printkey](http://code.google.com/p/volatility/wiki/CommandReference21#printkey)|Print the contents of a registry key, its values, timestamps, and data|All       |
|[hivedump](http://code.google.com/p/volatility/wiki/CommandReference21#hivedump)|Recursively prints all keys and timestamps in a given hive|All       |
|[hashdump](http://code.google.com/p/volatility/wiki/CommandReference21#hashdump)|Dumps passwords hashes (LM/NTLM) from memory|All x86   |
|[lsadump](http://code.google.com/p/volatility/wiki/CommandReference21#lsadump)|Dump (decrypted) LSA secrets from the registry|XP and 2003 x86|
|[userassist](http://code.google.com/p/volatility/wiki/CommandReference21#userassist)|Parses and output UserAssist keys from the registry|All       |
|[shimcache](http://code.google.com/p/volatility/wiki/CommandReference21#shimcache)|Parses the Application Compatibility Shim Cache registry key|All       |

## Crash Dumps, Hibernation, and Conversion ##

|Command|Description|OS Support|
|:------|:----------|:---------|
|[crashinfo](http://code.google.com/p/volatility/wiki/CommandReference21#crashinfo)|Dump crash-dump information|All       |
|[hibinfo](http://code.google.com/p/volatility/wiki/CommandReference21#hibinfo)|Dump hibernation file information|All       |
|[imagecopy](http://code.google.com/p/volatility/wiki/CommandReference21#imagecopy)|Copies a physical address space out as a raw DD image|All       |
|[raw2dmp](http://code.google.com/p/volatility/wiki/CommandReference21#raw2dmp)|Converts a raw memory dump into a crash dump|All       |

## Malware/Rootkits ##

|Command|Description|OS Support|
|:------|:----------|:---------|
|[malfind](http://code.google.com/p/volatility/wiki/CommandReference21#malfind)|Find hidden and injected code|All       |
|[yarascan](http://code.google.com/p/volatility/wiki/CommandReference21#yarascan)|Scan process or kernel memory with Yara signatures|All       |
|[svcscan](http://code.google.com/p/volatility/wiki/CommandReference21#svcscan)|Scan for Windows service records|All       |
|[ldrmodules](http://code.google.com/p/volatility/wiki/CommandReference21#ldrmodules)|Detect unlinked DLLs|All       |
|[impscan](http://code.google.com/p/volatility/wiki/CommandReference21#impscan)|Scan for calls to imported functions|All       |
|[apihooks](http://code.google.com/p/volatility/wiki/CommandReference21#apihooks)|Detect API hooks in process and kernel memory|All x86   |
|[idt](http://code.google.com/p/volatility/wiki/CommandReference21#idt)|Display Interrupt Descriptor Table|All x86   |
|[gdt](http://code.google.com/p/volatility/wiki/CommandReference21#gdt)|Dumps the Global Descriptor Table|All x86   |
|[threads](http://code.google.com/p/volatility/wiki/CommandReference21#threads)|Investigate ETHREADs and KTHREADs|All       |
|[callbacks](http://code.google.com/p/volatility/wiki/CommandReference21#callbacks)|Print system-wide notification routines and callbacks|All x86   |
|[driverirp](http://code.google.com/p/volatility/wiki/CommandReference21#driverirp)|Driver IRP hook detection|All       |
|[devicetree](http://code.google.com/p/volatility/wiki/CommandReference21#devicetree)|Walk a driver's device tree|All       |
|[psxview](http://code.google.com/p/volatility/wiki/CommandReference21#psxview)|Find hidden processes with various process listings|All       |
|[timers](http://code.google.com/p/volatility/wiki/CommandReference21#timers)|Explore kernel timers (KTIMER) and DPCs (Deferred Procedure Calls)|All x86   |

## Miscellaneous ##

|Command|Description|OS Support|
|:------|:----------|:---------|
|[strings](http://code.google.com/p/volatility/wiki/CommandReference21#strings)|Match physical offsets to virtual addresses for string correlations|All       |
|[volshell](http://code.google.com/p/volatility/wiki/CommandReference21#volshell)|Shell to interactively explore a memory image|All       |
|[bioskbd](http://code.google.com/p/volatility/wiki/CommandReference21#bioskbd)|Reads the keyboard buffer from Real Mode memory|          |
|[patcher](http://code.google.com/p/volatility/wiki/CommandReference21#patcher)|Patches memory based on page scans|All       |
|[pagecheck](http://code.google.com/p/volatility/wiki/CommandReference21#pagecheck)|Reads the available pages and reports if any are inaccessible|Non-PAE x86|