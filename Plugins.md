# Introduction #

A list of known Volatility plugins.

# Existing 2.0 plugins #

Note: MHL's malware plugins for Volatility 2.0 can be found at [The Malware Cookbook Code Repository (malware.py)](http://code.google.com/p/malwarecookbook/source/browse/trunk/)

|Plugin|Description|Primary Maintainer|Core Vote|
|:-----|:----------|:-----------------|:--------|
|  apihooks | Find API hooks  | MHL              | .       |
|bioskbd|Reads the keyboard buffer from Real Mode memory|MA                |Yes      |
|connections|Print list of open connections|.                 |Yes      |
|connscan2|Scan Physical memory for _TCPT\_OBJECT objects (tcp connections)_|.                 |Yes      |
|crashinfo|Dump crash-dump information|.                 |Yes      |
| csrpslist |Find hidden processes with csrss handles and CsrRootProcess  | MHL              | .       |
|datetime|Get date/time information for image|MA                |Yes      |
|dlllist|Print list of loaded dlls for each process|.                 |Yes      |
|dlldump|Dump a DLL from a process address space|MHL               |Yes (in contrib folder)|
|driverirp|Driver IRP hook detection|MHL               |.        |
|driverscan|Scan for driver objects _DRIVER\_OBJECT_|.                 |.        |
|files |Print list of open files for each process|.                 |Yes      |
|filescan|Scan Physical memory for _FILE\_OBJECT pool allocations_|.                 |.        |
|getsids|Print the SIDs owning each process|moyix             |Yes      |
|hashdump|Dumps passwords hashes (LM/NTLM) from memory|moyix             |Yes      |
|hibdump|Dumps the hibernation file to a raw file|.                 |Yes      |
|hibinfo|Dump hibernation file information|.                 |Yes      |
|hivedump|Prints out a hive|moyix             |Yes      |
|hivelist|Print list of registry hives.|moyix             |Yes      |
|hivescan|Scan Physical memory for _CMHIVE objects (registry hives)_|moyix             |Yes      |
| idt  | Display Interrupt Descriptor Table | MHL              | .       |
|imageinfo|Identify information for the image|MA                |Yes      |
|impscan | Scan a module for imports (API calls) | MHL              | .       |
| ldrmodules | Detect unlinked DLLs | MHL              | .       |
|kpcrscan|Search for and dump potential KPCR values|scudette          |Yes      |
|lsadump|Dump (decrypted) LSA secrets from the registry|moyix             |Yes      |
| malfind | Find hidden and injected code | MHL              | .       |
|memdump|Dump the addressable memory for a process|.                 |Yes      |
|memmap|Print the memory map|.                 |Yes      |
|moddump|Dump out a kernel module (aka driver)|.                 |Yes (in contrib folder)|
|modscan2|Scan Physical memory for _LDR\_DATA\_TABLE\_ENTRY objects_|.                 |Yes      |
|modules|Print list of loaded modules|MA                |.        |
|mutantscan|Scan for mutant objects _KMUTANT_|.                 |.        |
| mutantscandb | mutantscan extension for highlighting suspicious mutexes | MHL              | .       |
| notifyroutines | Print system-wide notification routines | MHL              | .       |
|  orphanthread | Locate hidden threads | MHL              | .       |
|patcher|Patches memory based on page scans|MA                |Yes      |
|printkey|Print a registry key, and its subkeys and values|moyix             |Yes      |
|procexedump|Dump a process to an executable file sample|.                 |Yes      |
|procmemdump|Dump a process to an executable memory sample|.                 |Yes      |
|pslist|print all running processes by following the EPROCESS lists|.                 |Yes      |
|psscan|Scan Physical memory for _EPROCESS objects_|.                 |Yes      |
|pstree|Print process list as a tree|scudette          |Yes      |
|regobjkeys|Print list of open regkeys for each process|MA                |.        |
|sockets|Print list of open sockets|.                 |Yes      |
|sockscan|Scan Physical memory for _ADDRESS\_OBJECT objects (tcp sockets)_|.                 |Yes      |
|ssdt  |Display SSDT entries|moyix             |Yes      |
| ssdt\_by\_threads | SSDT hooks by thread | MHL              | .       |
| ssdt\_ex | SSDT Hook Explorer for IDA Pro (and SSDT by thread) | MHL              | .       |
|strings|Match physical offsets to virtual addresses (may take a while, VERY verbose)|.                 |.        |
|  svcscan| Scan for Windows services | MHL              | .       |
|thrdscan|Scan Physical memory for _ETHREAD objects_|.                 |Yes      |
|thrdscan2|Scan physical memory for _ETHREAD objects_|.                 |Yes      |
|vaddump|Dumps out the vad sections to a file|.                 |.        |
|vadinfo|Dump the VAD info|.                 |.        |
|vadtree|Walk the VAD tree and display in tree format|.                 |.        |
|vadwalk|Walk the VAD tree|.                 |.        |



# Plugins Left to Port to 2.0 #



|Plugin|Description|Primary Maintainer|Core Vote|
|:-----|:----------|:-----------------|:--------|
|objtypescan|Enumerates Windows kernel object types. (Note: If running the SVN version of Volatility, just install the plugin file from this archive)|.                 |Yes      |
|psscan3|Scans the physical address space looking for memory resident data structures associated with processes|.                 | Yes     |
|raw2dmp|Convert a raw dump to a crash dump|.                 |.        |
|symlinkobjscan|Extracts symbolic link objects from the Windows kernel.(Note: If running the SVN version of Volatility, just install the plugin file from this archive.)|.                 |Yes      |



# Plugins (1.3) #



|Plugin|Author|URL|Description|Status|Supported OSes|Core Vote|
|:-----|:-----|:--|:----------|:-----|:-------------|:--------|
|bioskbd|AB & MA|[url](http://code.google.com/p/volatility/source/browse/trunk/plugins/bioskbd.py)|Reads the keyboard buffer from Real Mode memory|.     |.             |Yes      |
|cryptoscan|JesseK|[url](http://jessekornblum.com/tools/volatility/cryptoscan.py)|Finds Truecrypt passphrases|.     |.             |No       |
|DriverIRP|MHL   |[url](http://mhl-malware-scripts.googlecode.com/files/driverirp.py)|[Prints driver IRP function addresses](http://mnin.blogspot.com/2009/07/new-and-updated-volatility-plug-ins.html)|.     |.             |Yes      |
|driverscan|Andreas Schuster|[url](http://computer.forensikblog.de/files/volatility_plugins/volatility_driverscan-current.zip)|[Scan for kernel \_DRIVER\_OBJECTs. (Note: If running the SVN version of Volatility, just install the plugin file from this archive.)](http://computer.forensikblog.de/en/2009/04/scanning_for_drivers.html#more)|.     |.             |Yes      |
|dmp2raw|.     |.  |Convert a crash dump to a raw dump|.     |.             |.        |
|fileobjscan AKA filescan (1.4 branch)|Andreas Schuster|[url](http://computer.forensikblog.de/files/volatility_plugins/volatility_fileobjscan-current.zip)|[File object -> process linkage, including hidden files. (Note: If running the SVN version of Volatility, just install the plugin file from this archive.)](http://computer.forensikblog.de/en/2009/04/linking_file_objects_to_processes.html#more)|.     |.             |Yes      |
|getsids|Moyix |[url](http://moyix.blogspot.com/2008/08/linking-processes-to-users.html)|[Get information about what user (SID) started a process.](http://moyix.blogspot.com/2008/08/linking-processes-to-users.html)|.     |.             |Yes      |
|IDT   |MHL   |[url](http://mhl-malware-scripts.googlecode.com/files/idt.py)|[Prints the Interrupt Descriptor Table (IDT) addresses for one processor](http://mnin.blogspot.com/2009/07/new-and-updated-volatility-plug-ins.html)|.     |.             |Yes      |
|kernel\_hooks|MHL   |[url](http://mhl-malware-scripts.googlecode.com/files/kernel_hooks.py)|[Detects IAT, EAT, and in-line hooks in kernel drivers instead of usermode modules](http://mnin.blogspot.com/2009/07/new-and-updated-volatility-plug-ins.html)|.     |.             |Yes      |
|keyboardbuffer|Andreas Schuster|[url](http://computer.forensikblog.de/files/volatility_plugins/keyboardbuffer.py)|[Extracts keyboard buffer used by the BIOS, which may contain BIOS or disk encryption passwords.](http://computer.forensikblog.de/en/2009/04/read_password_from_keyboard_buffer.html#more)|.     |.             |(Above)  |
|kpcrscan|Bradley Schatz|[url](http://code.google.com/p/volatility/source/browse/trunk/plugins/internal/kpcrscan.py)|Finds potential KPCR addresses|.     |.             |.        |
|malfind2|MHL   |[url](http://mhl-malware-scripts.googlecode.com/files/malfind2.py)|[Automates the process of finding and extracting (usually malicious) code injected into another process](http://mnin.blogspot.com/2009/07/new-and-updated-volatility-plug-ins.html)|.     |.             |Yes      |
|moddump|Moyix |[url](http://moyix.blogspot.com/2008/10/plugin-post-moddump.html)|Dump out a kernel module (aka driver)|.     |.             |Yes      |
|mutantscan|Andreas Schuster|[url](http://computer.forensikblog.de/files/volatility_plugins/volatility_mutantscan-current.zip)|[Extracts mutexes from the Windows kernel.(Note: If running the SVN version of Volatility, just install the plugin file from this archive.)](http://computer.forensikblog.de/en/2009/04/searching_for_mutants.html#more)|.     |.             |No       |
|objtypescan|Andreas Schuster|[url](http://computer.forensikblog.de/files/volatility_plugins/volatility_objtypescan-current.zip)|[Enumerates Windows kernel object types. (Note: If running the SVN version of Volatility, just install the plugin file from this archive)](http://computer.forensikblog.de/en/2009/04/scanning_for_file_objects.html)|.     |.             |Yes      |
|orphan\_threads|MHL   |[url](http://mhl-malware-scripts.googlecode.com/files/orphan_threads.py)|[Detects hidden system/kernel threads](http://mnin.blogspot.com/2009/07/new-and-updated-volatility-plug-ins.html)|.     |.             |No       |
|patcher|MA    |[url](http://code.google.com/p/volatility/source/browse/trunk/plugins/internal/patcher.py)|Patches memory based on page scans|.     |.             |Yes      |
|psscan3|Moyix |[url](http://www.cc.gatech.edu/~brendan/volatility/dl/psscan3.py)|[Scans the physical address space looking for memory resident data structures associated with processes.](http://moyix.blogspot.com/2010/07/plugin-post-robust-process-scanner.html)|.     |.             | Yes     |
|pstree|Scudette|[url](http://scudette.blogspot.com/2008/10/pstree-volatility-plugin.html)|[Produces a tree-style listing of processes](http://scudette.blogspot.com/2008/10/pstree-volatility-plugin.html)|.     |.             |Yes      |
|raw2dmp|.     |.  |Convert a raw dump to a crash dump|.     |.             |.        |
|Registry Tools|Moyix |[url](http://www.cc.gatech.edu/%7Ebrendan/volatility/dl/volreg-0.6.tar.gz)|[A suite of plugins for accessing data from the registry, including password hashes, LSA secrets, and arbitrary registry keys](http://moyix.blogspot.com/2009/01/memory-registry-tools.html)|.     |.             |Yes      |
|Modified Regripper & Glue Code|Moyix |[url](http://www.cc.gatech.edu/%7Ebrendan/volatility/dl/volrip-0.1.tar.gz)|[Code to run a modified RegRipper against the registry hives embedded in a memory dump. Note that due to a dependency on Inline::Python, this only works on Linux.](http://moyix.blogspot.com/2009/03/regripper-and-volatility-prototype.html)|.     |.             |No       |
|sqlite3|Gleeda|[url](http://jls-scripts.googlecode.com/files/vol_sql-0.2.tgz)|[Allows one to place Volatility output into a SQLite3 Database](http://gleeda.blogspot.com/2010/01/volatilitys-output-rendering-functions.html)|.     |.             |As example|
|ssdt  |Moyix |[url](http://moyix.blogspot.com/2008/08/auditing-system-call-table.html)| [List entries in the system call table. Can be used to detect certain rootkits that hook system calls by replacing entries in this table](http://moyix.blogspot.com/2008/08/auditing-system-call-table.html)|.     |.             |Yes      |
|suspicious|JesseK|[url](http://jessekornblum.com/tools/volatility/suspicious.py)|Identify suspicious processes. This version counts any command line running Truecrypt or any command line that starts with a lower case drive letter as suspicious|.     |.             |No       |
|symlinkobjscan|Andreas Schuster|[url](http://computer.forensikblog.de/files/volatility_plugins/volatility_symlinkobjscan-current.zip)|[Extracts symbolic link objects from the Windows kernel.(Note: If running the SVN version of Volatility, just install the plugin file from this archive.)](http://computer.forensikblog.de/en/2009/04/symbolic_link_objects.html#more)|.     |.             |Yes      |
|threadqueues|Moyix |[url](http://kurtz.cs.wesleyan.edu/%7Ebdolangavitt/memory/threadqueues.py)|[Enumerates window messages pending for each thread on the system. Window messages are the mechanism used to send things like button presses, mouse clicks, and other events to GUI programs.](http://moyix.blogspot.com/2008/09/window-messages-as-forensic-resource.html)|.     |.             |No       |
|usermode\_hooks|MHL   |[url](http://mhl-malware-scripts.googlecode.com/files/usermode_hooks2.py)|[Detect IAT/EAT/Inline rootkit hooks](http://mnin.blogspot.com/2009/07/new-and-updated-volatility-plug-ins.html)|.     |.             |Yes      |
|verinfo|MA    |[url](http://code.google.com/p/volatility/source/browse/trunk/plugins/internal/verinfo.py)|Prints out the version information from PE images|.     |.             |NO       |
|Volatility Analyst Pack 0.1|MHL   |[url](http://mhl-malware-scripts.googlecode.com/files/vap-0.1.zip)|[A pack which contains updates to many of the listed modules](http://mnin.blogspot.com/2009/12/new-and-updated-volatility-plug-ins.html)|.     |.             |(included above)|
|volshell|Moyix |[url](http://moyix.blogspot.com/2008/08/indroducing-volshell.html)|[Creates a python shell can be used with the framework](http://moyix.blogspot.com/2008/08/indroducing-volshell.html)|.     |.             |No       |