# Introduction #

This is a list of Volatility features organized by plugins and categories. It applies to the current version of Volatility. Plugins for older versions of Volatility can be found on [The Forensics Wiki](http://www.forensicswiki.org/wiki/List_of_Volatility_Plugins) or in the [deprecated Plugins page](http://code.google.com/p/volatility/wiki/Plugins).

If the OS Support column contains the word "All", that doesn't mean it works on all operating systems - it just means it works on all operating systems that Volatility supports. For a list, see the [FAQ page](http://code.google.com/p/volatility/wiki/FAQ).

Before using these plugins, make sure to read the BasicUsage instructions. To see example use cases and example output from the plugins, see the CommandReference or click on the name of the plugin.

## Image Identification ##

|Command|Description|OS Support|
|:------|:----------|:---------|
|[imageinfo](http://code.google.com/p/volatility/wiki/CommandReference#imageinfo)|Prints the suggested profile (OS version and patch level).<br>Tells you if the system is PAE vs no PAE.<br>Locates the DTB, KDBG, KPCR, and KUSER_SHARED_DATA.<br>Prints the date/time info.<table><thead><th>All       </th></thead><tbody>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#kdbgscan'>kdbgscan</a></td><td>Search for and dump potential KDBG values</td><td>All       </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#kpcrscan'>kpcrscan</a></td><td>Search for and dump potential KDBG values</td><td>All       </td></tr></tbody></table>

<h2>Processes and DLLs</h2>

<table><thead><th>Command</th><th>Description</th><th>OS Support</th></thead><tbody>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#pslist'>pslist</a></td><td>Print active processes by walking the PsActiveProcessHead linked list.<br>For inactive/terminated or hidden/unlinked processes, see psscan.</td><td>All       </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#pstree'>pstree</a></td><td>Print process list as a tree so you can visualize the parent/child relationships</td><td>All       </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#psscan'>psscan</a></td><td>Find <i>EPROCESS objects using pool tag scanning</i></td><td>All       </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#dlllist'>dlllist</a></td><td>Print loaded DLLs by walking the InLoadOrderModuleList in the PEB.<br>Print DLLs in unlinked/hidden processes by specifying an <i>EPROCESS offset.</i><br>To cross reference this list with 3 other sources of information, see LdrModules.</td><td>All       </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#dlldump'>dlldump</a></td><td>Extract DLLs to executable files.<br>Dump a PE from process memory (even if it's not in the DLL list) by specifying a base address.</td><td>All       </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#handles'>handles</a></td><td>Print list of open handles for each process</td><td>All       </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#getsids'>getsids</a></td><td>Print the SIDs owning each process</td><td>All       </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#verinfo'>verinfo</a></td><td>Print the version information compiled into a process or DLL's PE file</td><td>All       </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#enumfunc'>enumfunc</a></td><td>Enumerate imported and exported functions from PE files (applies to processes, DLLs, and kernel drivers)</td><td>All       </td></tr></tbody></table>

<h2>Processes Memory</h2>

<table><thead><th>Command</th><th>Description</th><th>OS Support</th></thead><tbody>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#memmap'>memmap</a></td><td>Print the virtual addresses, physical addresses, and size of each page accessible to a process</td><td>All       </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#memdump'>memdump</a></td><td>Dump the addressable memory for a process (outputs 1 file per process)</td><td>All       </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#procmemdump'>procmemdump</a></td><td>Extract a process's executable, preserving slack space</td><td>All       </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#procexedump'>procexedump</a></td><td>Extract a process's executable, do not preserve slack space</td><td>All       </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#vadwalk'>vadwalk</a></td><td>Walk the VAD tree and print basic information</td><td>All       </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#vadtree'>vadtree</a></td><td>Walk the VAD tree and display in tree format</td><td>All       </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#vadinfo'>vadinfo</a></td><td>Walk the VAD tree and print extended information</td><td>All       </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#vaddump'>vaddump</a></td><td>Dumps out the VAD sections (outputs multiple files per process)</td><td>All       </td></tr></tbody></table>

<h2>Kernel Memory and Objects</h2>

<table><thead><th>Command</th><th>Description</th><th>OS Support</th></thead><tbody>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#modules'>modules</a></td><td>Print loaded kernel drivers by walking the PsLoadedModuleList linked list</td><td>All       </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#modscan'>modscan</a></td><td>Scan physical memory for LDR_DATA_TABLE_ENTRY objects.<br>Can locate unloaded and unlinked kernel drivers.</td><td>All       </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#moddump'>moddump</a></td><td>Extract a kernel driver to disk (by base address or regular expression)</td><td>All       </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#ssdt'>ssdt</a></td><td>Print the Native and GDI System Service Descriptor Tables</td><td>All       </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#driverscan'>driverscan</a></td><td>Scan physical memory for DRIVER_OBJECT objects</td><td>All       </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#filescan'>filescan</a></td><td>Scan physical memory for FILE_OBJECT objects</td><td>All       </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#mutantscan'>mutantscan</a></td><td>Scan physical memory for KMUTANT objects</td><td>All       </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#symlinkscan'>symlinkscan</a> </td><td>Scans for symbolic link objects</td><td>All       </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#thrdscan'>thrdscan</a></td><td>Scan physical memory for ETHREAD objects</td><td>All       </td></tr></tbody></table>

<h2>Networking</h2>

<table><thead><th>Command</th><th>Description</th><th>OS Support</th></thead><tbody>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#connections'>connections</a></td><td>Display open network connections by walking the linked list in tcpip.sys</td><td>Windows XP, 2003</td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#connscan2'>connscan</a></td><td>Scan physical memory for connection objects</td><td>Windows XP, 2003</td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#sockets'>sockets</a></td><td>Display open client and server (listening) sockets by walking the linked list in tcpip.sys</td><td>Windows XP, 2003</td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#sockscan'>sockscan</a></td><td>Scan physical memory for socket objects</td><td>Windows XP, 2003</td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#netscan'>netscan</a></td><td>Scan physical memory for connection and socket objects.<br>Distinguishes between IPv4 and IPv6.<br>Shows owning process, creation time, and state (for TCP connections).</td><td>Windows Vista, 2008 and 7</td></tr></tbody></table>

<h2>Registry</h2>

<table><thead><th>Command</th><th>Description</th><th>OS Support</th></thead><tbody>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#hivescan'>hivescan</a></td><td>Scan Physical memory for <i>CMHIVE objects (registry hives)</i></td><td>All       </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#hivelist'>hivelist</a></td><td>Walk the linked list of registry hives and print their virtual addresses and corresponding paths on disk</td><td>All       </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#printkey'>printkey</a></td><td>Print the contents of a registry key, its values, timestamps, and data</td><td>All       </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#hivedump'>hivedump</a></td><td>Recursively prints all keys and timestamps in a given hive</td><td>All       </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#hashdump'>hashdump</a></td><td>Dumps passwords hashes (LM/NTLM) from memory</td><td>All       </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#lsadump'>lsadump</a></td><td>Dump (decrypted) LSA secrets from the registry</td><td>Windows XP</td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#userassist'>userassist</a></td><td>Parses and output UserAssist keys from the registry</td><td>All       </td></tr></tbody></table>

<h2>Crash Dumps, Hibernation, and Conversion</h2>

<table><thead><th>Command</th><th>Description</th><th>OS Support</th></thead><tbody>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#crashinfo'>crashinfo</a></td><td>Dump crash-dump information</td><td>All       </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#hibdump'>hibdump</a></td><td>Dumps the hibernation file to a raw file</td><td>          </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#hibinfo'>hibinfo</a></td><td>Dump hibernation file information</td><td>          </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#imagecopy'>imagecopy</a></td><td>Copies a physical address space out as a raw DD image</td><td>          </td></tr></tbody></table>

<h2>Malware/Rootkits</h2>

<table><thead><th>Command</th><th>Description</th><th>OS Support</th></thead><tbody>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#malfind'>malfind</a></td><td>Extract injected DLLs, injected code, unpacker stubs, API hook trampolines.<br>Scan for any ANSI string, Unicode string, regular expression, or byte sequence in process or kernel driver memory.</td><td>All       </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#svcscan'>svcscan</a></td><td>Scan the Service Control Manager for information on Windows services.<br>Shows binary path, process ID or driver object, current state, etc).</td><td>All       </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#ldrmodules'>ldrmodules</a></td><td>Detect unlinked DLLs by cross-referencing memory mapped files with the 3 PEB DLL lists</td><td>All       </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#impscan'>impscan</a></td><td>Scan for calls to imported functions.<br>Does not rely on the Import Address Table (for example it works when the PE header has been erased).<br>Automatically generates a labeled IDA Pro Database.<br>Works on EXEs, DLLs, arbitrary executable ranges of process memory, and kernel drivers.</td><td>All       </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#apihooks'>apihooks</a></td><td>Detect IAT, EAT, and Inline hooks in process or kernel memory.<br>For inline hooks, it checks direct calls, direct jumps, indirect calls, indirect jumps, and push/ret instructions.<br>Detects calls to unknown code pages in kernel drivers.<br>Detects redirected system calls in ntdll.dll.<br>Allows whitelisting by process name, hooked module, hooking module, or function name.</td><td>All       </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#idt'>idt</a></td><td>Dumps the Interrupt Descriptor Table.<br>Checks for inline API hooks of all IDT entries.</td><td>All       </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#gdt'>gdt</a></td><td>Dumps the Global Descriptor Table.<br>Prints a disassembly for malicious 32-bit call gates.</td><td>All       </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#threads'>threads</a></td><td>Investigate threads using various heuristics - find hardware breakpoints, threads with hooked SSDTs, orphan threads, etc.</td><td>All       </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#callbacks'>callbacks</a></td><td>Prints kernel callbacks of the following types:<br>PsSetCreateProcessNotifyRoutine (process creation).<br>PsSetCreateThreadNotifyRoutine (thread creation).<br>PsSetImageLoadNotifyRoutine (DLL/image load).<br>IoRegisterFsRegistrationChange (file system registration).<br>KeRegisterBugCheck and KeRegisterBugCheckReasonCallback.<br>CmRegisterCallback (registry callbacks on XP).<br>CmRegisterCallbackEx (registry callbacks on Vista and 7).<br>IoRegisterShutdownNotification (shutdown callbacks).<br>DbgSetDebugPrintCallback (debug print callbacks on Vista and 7).<br>DbgkLkmdRegisterCallback (debug callbacks on 7).</td><td>All       </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#driverirp'>driverirp</a></td><td>Print the 28 IRP handlers for each driver object.<br>Checks for inline API hooks of each function.<br>Detects hooks of DriverStartIO.</td><td>All       </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#devicetree'>devicetree</a></td><td>Walk a driver's device tree</td><td>All       </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#psxview'>psxview</a></td><td>Detect hidden processes by cross-referencing with various sources of process listings:<br>PsActiveProcessHead linked list<br>EPROCESS pool scanning<br>ETHREAD pool scanning<br>PspCidTable<br>Csrss.exe handle table<br>Csrss.exe internal linked list</td><td>All, but no internal list on Vista and 7</td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#ssdt_ex'>ssdt_ex</a></td><td>Automated SSDT hook explorer for use with IDA Pro.<br>Detects which SSDT functions are hooked.<br>Extracts the hooking driver and creates an IDA Database.<br>Labels the rootkit function in the IDA Database.</td><td>All       </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#timers'>timers</a></td><td>Explore kernel timers (KTIMER) and DPCs (Deferred Procedure Calls)</td><td>All       </td></tr></tbody></table>

<h2>Miscellaneous</h2>

<table><thead><th>Command</th><th>Description</th><th>OS Support</th></thead><tbody>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#strings'>strings</a></td><td>Match physical offsets to virtual addresses</td><td>All       </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#volshell'>volshell</a></td><td>Shell to interactively explore a memory image</td><td>All       </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#bioskbd'>bioskbd</a></td><td>Reads the keyboard buffer from Real Mode memory</td><td>          </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#inspectcache'>inspectcache</a></td><td>Inspect the contents of a cache</td><td>          </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#patcher'>patcher</a></td><td>Patches memory based on page scans</td><td>          </td></tr>
<tr><td><a href='http://code.google.com/p/volatility/wiki/CommandReference#testsuite'>testsuite</a></td><td>Run unit test suit using the Cache</td><td>          </td></tr>