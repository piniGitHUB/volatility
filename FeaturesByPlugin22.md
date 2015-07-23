# Introduction #

---


**This page is a draft until 2.2 is released - October 2012**

This is a list of Volatility 2.2 features organized by plugins and categories. Before using these plugins, make sure to read the BasicUsage22 instructions. To see example use cases and example output from the plugins, see the CommandReference22 or click on the name of the plugin.

# Windows #

---


##  ##

|Command|Category|Description|OS Support|
|:------|:-------|:----------|:---------|
|[imageinfo](http://code.google.com/p/volatility/wiki/CommandReference21#imageinfo)|Image Identification|Identity information for the image|All       |
|[kdbgscan](http://code.google.com/p/volatility/wiki/CommandReference21#kdbgscan)|Image Identification|Search for and dump potential KDBG values|All       |
|[kpcrscan](http://code.google.com/p/volatility/wiki/CommandReference21#kpcrscan)|Image Identification|Search for and dump potential KPCR values|All       |
|[pslist](http://code.google.com/p/volatility/wiki/CommandReference21#pslist)|Processes and DLLs|Print all running processes by following the EPROCESS lists|All       |
|[pstree](http://code.google.com/p/volatility/wiki/CommandReference21#pstree)|Processes and DLLs|Print process list as a tree|All       |
|[psscan](http://code.google.com/p/volatility/wiki/CommandReference21#psscan)|Processes and DLLs|Scan Physical memory for EPROCESS pool allocations|All       |
|[psdispscan](http://code.google.com/p/volatility/wiki/CommandReference21#psdispscan)|Processes and DLLs|Scan Physical memory for EPROCESS objects based on their Dispatch Headers|Only Windows XP x86|
|[dlllist](http://code.google.com/p/volatility/wiki/CommandReference21#dlllist)|Processes and DLLs|Print list of loaded dlls for each process|All       |
|[dlldump](http://code.google.com/p/volatility/wiki/CommandReference21#dlldump)|Processes and DLLs|Dump DLLs from a process address space|All       |
|[handles](http://code.google.com/p/volatility/wiki/CommandReference21#handles)|Processes and DLLs|Print list of open handles for each process|All       |
|[getsids](http://code.google.com/p/volatility/wiki/CommandReference21#getsids)|Processes and DLLs|Print the SIDs owning each process|All       |
|[cmdscan](http://code.google.com/p/volatility/wiki/CommandReference21#cmdscan)|Processes and DLLs|Extract command history by scanning for COMMAND\_HISTORY|All (see [Issue #318](https://code.google.com/p/volatility/issues/detail?id=#318))|
|[consoles](http://code.google.com/p/volatility/wiki/CommandReference21#consoles)|Processes and DLLs|Extract command history by scanning for CONSOLE\_INFORMATION|All (see [Issue #318](https://code.google.com/p/volatility/issues/detail?id=#318))|
|[envars](http://code.google.com/p/volatility/wiki/CommandReference21#envars)|Processes and DLLs|Display process environment variables|All       |
|[verinfo](http://code.google.com/p/volatility/wiki/CommandReference21#verinfo)|Processes and DLLs|Prints out the version information from PE images|All       |
|[enumfunc](http://code.google.com/p/volatility/wiki/CommandReference21#enumfunc)|Processes and DLLs|Enumerate imported and exported functions|All       |
|[memmap](http://code.google.com/p/volatility/wiki/CommandReference21#memmap)|Processes Memory|Print the virtual and physical addresses and sizes of each page accessible to a process|All       |
|[memdump](http://code.google.com/p/volatility/wiki/CommandReference21#memdump)|Processes Memory|Dump the addressable memory for a process|All       |
|[procmemdump](http://code.google.com/p/volatility/wiki/CommandReference21#procmemdump)|Processes Memory|Extract a process's executable, preserving slack space|All       |
|[procexedump](http://code.google.com/p/volatility/wiki/CommandReference21#procexedump)|Processes Memory|Extract a process's executable, do not preserve slack space|All       |
|[vadwalk](http://code.google.com/p/volatility/wiki/CommandReference21#vadwalk)|Processes Memory|Walk the VAD tree and print basic information|All       |
|[vadtree](http://code.google.com/p/volatility/wiki/CommandReference21#vadtree)|Processes Memory|Walk the VAD tree and display in tree format|All       |
|[vadinfo](http://code.google.com/p/volatility/wiki/CommandReference21#vadinfo)|Processes Memory|Walk the VAD tree and print extended information|All       |
|[vaddump](http://code.google.com/p/volatility/wiki/CommandReference21#vaddump)|Processes Memory|Dumps out the VAD sections to a file|All       |
|[modules](http://code.google.com/p/volatility/wiki/CommandReference21#modules)|Kernel Memory and Objects|Print list of loaded kernel modules|All       |
|[modscan](http://code.google.com/p/volatility/wiki/CommandReference21#modscan)|Kernel Memory and Objects|Scan physical memory for LDR\_DATA\_TABLE\_ENTRY objects|All       |
|[moddump](http://code.google.com/p/volatility/wiki/CommandReference21#moddump)|Kernel Memory and Objects|Dump a kernel driver to an executable file sample|All       |
|[ssdt](http://code.google.com/p/volatility/wiki/CommandReference21#ssdt)|Kernel Memory and Objects|Display SSDT entries|All       |
|[driverscan](http://code.google.com/p/volatility/wiki/CommandReference21#driverscan)|Kernel Memory and Objects|Scan physical memory for DRIVER\_OBJECT objects|All       |
|[filescan](http://code.google.com/p/volatility/wiki/CommandReference21#filescan)|Kernel Memory and Objects|Scan physical memory for FILE\_OBJECT objects|All       |
|[mutantscan](http://code.google.com/p/volatility/wiki/CommandReference21#mutantscan)|Kernel Memory and Objects|Scan physical memory for KMUTANT objects|All       |
|[symlinkscan](http://code.google.com/p/volatility/wiki/CommandReference21#symlinkscan)|Kernel Memory and Objects|Scans for symbolic link objects|All       |
|[thrdscan](http://code.google.com/p/volatility/wiki/CommandReference21#thrdscan)|Kernel Memory and Objects|Scan physical memory for ETHREAD objects|All       |
|[connections](http://code.google.com/p/volatility/wiki/CommandReference21#connections)|Networking|Print a list of open TCP connections|Only Windows XP and 2003|
|[connscan](http://code.google.com/p/volatility/wiki/CommandReference21#connscan)|Networking|Scan physical memory for connection objects|Only Windows XP and 2003|
|[sockets](http://code.google.com/p/volatility/wiki/CommandReference21#sockets)|Networking|Print a list of open sockets|Only Windows XP and 2003|
|[sockscan](http://code.google.com/p/volatility/wiki/CommandReference21#sockscan)|Networking|Scan physical memory for socket objects|Only Windows XP and 2003|
|[netscan](http://code.google.com/p/volatility/wiki/CommandReference21#netscan)|Networking|Scan a Vista, 2008 or Windows 7 image for connections and sockets|Only Windows Vista, 2008 and 7|
|[hivescan](http://code.google.com/p/volatility/wiki/CommandReference21#hivescan)|Registry|Scan Physical memory for _CMHIVE objects (registry hives)_|All       |
|[hivelist](http://code.google.com/p/volatility/wiki/CommandReference21#hivelist)|Registry|Walk the linked list of registry hives and print their virtual addresses and paths on disk|All       |
|[printkey](http://code.google.com/p/volatility/wiki/CommandReference21#printkey)|Registry|Print the contents of a registry key, its values, timestamps, and data|All       |
|[hivedump](http://code.google.com/p/volatility/wiki/CommandReference21#hivedump)|Registry|Recursively prints all keys and timestamps in a given hive|All       |
|[hashdump](http://code.google.com/p/volatility/wiki/CommandReference21#hashdump)|Registry|Dumps passwords hashes (LM/NTLM) from memory|All x86   |
|[lsadump](http://code.google.com/p/volatility/wiki/CommandReference21#lsadump)|Registry|Dump (decrypted) LSA secrets from the registry|XP and 2003 x86|
|[userassist](http://code.google.com/p/volatility/wiki/CommandReference21#userassist)|Registry|Parses and output UserAssist keys from the registry|All       |
|[shimcache](http://code.google.com/p/volatility/wiki/CommandReference21#shimcache)|Registry|Parses the Application Compatibility Shim Cache registry key|All       |
|[crashinfo](http://code.google.com/p/volatility/wiki/CommandReference21#crashinfo)|Crash Dumps|Dump crash-dump information|All       |
|[raw2dmp](http://code.google.com/p/volatility/wiki/CommandReference21#raw2dmp)|Crash Dumps|Converts a raw memory dump into a crash dump|All       |
|[hibinfo](http://code.google.com/p/volatility/wiki/CommandReference21#hibinfo)|Hibernation|Dump hibernation file information|All       |
|[imagecopy](http://code.google.com/p/volatility/wiki/CommandReference21#imagecopy)|Image Conversion|Copies a physical address space out as a raw DD image|All       |
|[malfind](http://code.google.com/p/volatility/wiki/CommandReference21#malfind)|Malware/Rootkits|Find hidden and injected code|All       |
|[yarascan](http://code.google.com/p/volatility/wiki/CommandReference21#yarascan)|Malware/Rootkits|Scan process or kernel memory with Yara signatures|All       |
|[svcscan](http://code.google.com/p/volatility/wiki/CommandReference21#svcscan)|Malware/Rootkits|Scan for Windows service records|All       |
|[ldrmodules](http://code.google.com/p/volatility/wiki/CommandReference21#ldrmodules)|Malware/Rootkits|Detect unlinked DLLs|All       |
|[impscan](http://code.google.com/p/volatility/wiki/CommandReference21#impscan)|Malware/Rootkits|Scan for calls to imported functions|All       |
|[apihooks](http://code.google.com/p/volatility/wiki/CommandReference21#apihooks)|Malware/Rootkits|Detect API hooks in process and kernel memory|All x86   |
|[idt](http://code.google.com/p/volatility/wiki/CommandReference21#idt)|Malware/Rootkits|Display Interrupt Descriptor Table|All x86   |
|[gdt](http://code.google.com/p/volatility/wiki/CommandReference21#gdt)|Malware/Rootkits|Dumps the Global Descriptor Table|All x86   |
|[threads](http://code.google.com/p/volatility/wiki/CommandReference21#threads)|Malware/Rootkits|Investigate ETHREADs and KTHREADs|All       |
|[callbacks](http://code.google.com/p/volatility/wiki/CommandReference21#callbacks)|Malware/Rootkits|Print system-wide notification routines and callbacks|All x86   |
|[driverirp](http://code.google.com/p/volatility/wiki/CommandReference21#driverirp)|Malware/Rootkits|Driver IRP hook detection|All       |
|[devicetree](http://code.google.com/p/volatility/wiki/CommandReference21#devicetree)|Malware/Rootkits|Walk a driver's device tree|All       |
|[psxview](http://code.google.com/p/volatility/wiki/CommandReference21#psxview)|Malware/Rootkits|Find hidden processes with various process listings|All       |
|[timers](http://code.google.com/p/volatility/wiki/CommandReference21#timers)|Malware/Rootkits|Explore kernel timers (KTIMER) and DPCs (Deferred Procedure Calls)|All x86   |
|[strings](http://code.google.com/p/volatility/wiki/CommandReference21#strings)|Miscellaneous|Match physical offsets to virtual addresses for string correlations|All       |
|[volshell](http://code.google.com/p/volatility/wiki/CommandReference21#volshell)|Miscellaneous|Shell to interactively explore a memory image|All       |
|[bioskbd](http://code.google.com/p/volatility/wiki/CommandReference21#bioskbd)|Miscellaneous|Reads the keyboard buffer from Real Mode memory|          |
|[patcher](http://code.google.com/p/volatility/wiki/CommandReference21#patcher)|Miscellaneous|Patches memory based on page scans|All       |
|[pagecheck](http://code.google.com/p/volatility/wiki/CommandReference21#pagecheck)|Miscellaneous|Reads the available pages and reports if any are inaccessible|Non-PAE x86|

# Linux #

---


|Command|Category|Description|OS Support|
|:------|:-------|:----------|:---------|
|linux\_psaux|Processes|Gathers processes along with full command line and start time|          |
|linux\_pslist|Processes|Gather active tasks by walking the task\_struct->task list|          |
|linux\_pslist\_cache|Processes|Gather tasks from the kmem\_cache|          |
|linux\_pstree|Processes|Shows the parent/child relationship between processes|          |
|linux\_psxview|Processes|Find hidden processes with various process listings|          |
|linux\_dump\_map|Process Memory|Writes selected process memory mappings to disk|          |
|linux\_memmap|Process Memory|Dumps the memory map for linux tasks|          |
|linux\_pidhashtable|Process Memory|Enumerates processes through the PID hash table|          |
|linux\_proc\_maps|Process Memory|Gathers process maps for linux|          |
|linux\_lsmod|Kernel Memory and Objects|Gather loaded kernel modules|          |
|linux\_lsof|Kernel Memory and Objects|Lists open files|          |
|linux\_tmpfs|Kernel Memory and Objects|Recovers tmpfs filesystems from memory|          |
|linux\_arp|Networking|Print the ARP table|          |
|linux\_ifconfig|Networking|Gathers active interfaces|          |
|linux\_netstat|Networking|Lists open sockets|          |
|linux\_route|Networking|Lists routing table|          |
|linux\_route\_cache|Networking|Recovers the routing cache from memory|          |
|linux\_cpuinfo|System Information|Prints info about each active processor|          |
|linux\_dmesg|System Information|Gather dmesg buffer|          |
|linux\_iomem|System Information|Provides output similar to /proc/iomem|          |
|linux\_mount|System Information|Gather mounted fs/devices|          |
|linux\_mount\_cache|System Information|Gather mounted fs/devices from kmem\_cache|          |
|linux\_slabinfo|System Information|Mimics /proc/slabinfo on a running machine|