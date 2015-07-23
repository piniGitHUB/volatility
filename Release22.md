# Introduction #

Volatility 2.2 was released in October 2012.

  * [Volatility 2.2 Standalone Windows Program](http://volatility.googlecode.com/files/volatility-2.2.standalone.exe)
  * [Volatility 2.2 Windows Module Installer](http://volatility.googlecode.com/files/volatility-2.2.win32.exe)
  * [Volatility 2.2 Source code (tgz)](http://volatility.googlecode.com/files/volatility-2.2.tar.gz)
  * [Volatility 2.2 Source code (zip)](http://volatility.googlecode.com/files/volatility-2.2.zip)

# Release Highlights #

  * Introduction of Linux support (Intel x86, x64)
    * Kernels: 2.6.11 to 3.5
    * Debian, Ubuntu, OpenSuSE, Fedora, CentOS, Mandriva, and more...
  * Approximately 35 new Linux plugins
  * New LiME Address Space
  * Addition of the win32k suite (14 new plugins and APIs for analyzing windows GUI memory)
  * New windows plugins:
    * getservicesids: calculate SIDs of windows services
    * evtlogs: parse XP and 2003 event logs from memory

# Operating Systems #

  * 32-bit Windows XP Service Pack 2 and 3
  * 32-bit Windows 2003 Server Service Pack 0, 1, 2
  * 32-bit Windows Vista Service Pack 0, 1, 2
  * 32-bit Windows 2008 Server Service Pack 1, 2
  * 32-bit Windows 7 Service Pack 0, 1
  * 64-bit Windows XP Service Pack 1 and 2
  * 64-bit Windows 2003 Server Service Pack 1 and 2
  * 64-bit Windows Vista Service Pack 0, 1, 2
  * 64-bit Windows 2008 Server Service Pack 1 and 2
  * 64-bit Windows 2008 `R2` Server Service Pack 0 and 1
  * 64-bit Windows 7 Service Pack 0 and 1
  * <font color='red'>(new)</font> 32-bit Linux kernels 2.6.11 to 3.5
  * <font color='red'>(new)</font> 64-bit Linux kernels 2.6.11 to 3.5

# Address Spaces #

  * FileAddressSpace - This is a direct file AS
  * Legacy Intel x86 address spaces
    * IA32PagedMemoryPae
    * IA32PagedMemory
  * Standard Intel x86 address spaces
    * JKIA32PagedMemoryPae
    * JKIA32PagedMemory
  * AMD64PagedMemory - This AS supports AMD 64-bit address spaces
  * [WindowsCrashDumpSpace32](CrashAddressSpace.md) - This AS supports windows Crash Dump format (x86)
  * [WindowsCrashDumpSpace64](CrashAddressSpace.md) - This AS supports windows Crash Dump format (x64)
  * [WindowsHiberFileSpace32](HiberAddressSpace.md) - This AS supports windows hibernation files (x86 and x64)
  * [EWFAddressSpace](EWFAddressSpace.md) - This AS supports expert witness (EWF) files
  * [FirewireAddressSpace](FirewireAddressSpace.md) - This AS supports direct memory access over firewire
  * <font color='red'>(new)</font> [LimeAddressSpace](LimeAddressSpace.md) - This AS supports LiME (Linux Memory Extractor)

# Plugins #

  * **Windows**
    * **Image Identification**
      * [imageinfo](CommandReference22#imageinfo.md) - Identify information for the image
      * [kdbgscan](CommandReference22#kdbgscan.md) - Search for and dump potential KDBG values
      * [kpcrscan](CommandReference22#kpcrscan.md) - Search for and dump potential `_KPCR` values
    * **Process and DLLs**
      * [pslist](CommandReference22#pslist.md) - Print active processes by following the `_EPROCESS` list
      * [pstree](CommandReference22#pstree.md) - Print process list as a tree
      * [psscan](CommandReference22#psscan.md) - Scan Physical memory for `_EPROCESS` pool allocations
      * [psdispscan](CommandReference22#psdispscan.md) - Scan Physical memory for `_EPROCESS` objects based on Dispatch Headers (Windows XP x86 only)
      * [dlllist](CommandReference22#dlllist.md) - Print list of loaded DLLs for each process
      * [dlldump](CommandReference22#dlldump.md) - Dump DLLs from a process address space
      * [handles](CommandReference22#handles.md) - Print list of open handles for each process
      * [getsids](CommandReference22#getsids.md) - Print the SIDs owning each process
      * [verinfo](CommandReference22#verinfo.md) - Print a PE file's version information
      * [enumfunc](CommandReference22#enumfunc.md) - Enumerate a PE file's imports and exports
      * [envars](CommandReference22#envars.md) - Display process environment variables
      * [cmdscan](CommandReference22#cmdscan.md) - Extract command history by scanning for `_COMMAND_HISTORY`
      * [consoles](CommandReference21#consoles.md) - Extract command history by scanning for `_CONSOLE_INFORMATION`
    * **Process Memory**
      * [memmap](CommandReference22#memmap.md) - Print the memory map
      * [memdump](CommandReference22#memdump.md) - Dump the addressable memory for a process
      * [procexedump](CommandReference22#procexedump.md) - Dump a process to an executable file
      * [procmemdump](CommandReference22#procmemdump.md) - Dump a process to an executable memory sample
      * [vadwalk](CommandReference22#vadwalk.md) - Walk the VAD tree
      * [vadtree](CommandReference22#vadtree.md) - Walk the VAD tree and display in tree format
      * [vadinfo](CommandReference22#vadinfo.md) - Dump the VAD info
      * [vaddump](CommandReference22#vaddump.md) - Dumps out the vad sections to a file
      * <font color='red'>(new)</font> [evtlogs](CommandReference22#evtlogs.md) - Parse XP and 2003 event logs from memory
    * **Kernel Memory and Objects**
      * [modules](CommandReference22#modules.md) - Print list of loaded modules
      * [modscan](CommandReference22#modscan.md) - Scan Physical memory for `_LDR_DATA_TABLE_ENTRY` objects
      * [moddump](CommandReference22#moddump.md) - Extract a kernel driver to disk
      * [ssdt](CommandReference22#ssdt.md) - Print the Native and GDI System Service Descriptor Tables
      * [driverscan](CommandReference22#driverscan.md) - Scan physical memory for `_DRIVER_OBJECT` objects
      * [filescan](CommandReference22#filescan.md) - Scan physical memory for `_FILE_OBJECT` objects
      * [mutantscan](CommandReference22#mutantscan.md) - Scan physical memory for `_KMUTANT` objects
      * [symlinkscan](CommandReference22#symlinkscan.md) - Scans for symbolic link objects
      * [thrdscan](CommandReference22#thrdscan.md) - Scan physical memory for `_ETHREAD` objects
    * **Win32k / GUI Memory**
      * <font color='red'>(new)</font> [sessions](CommandReferenceGui22#sessions.md) - List details on `_MM_SESSION_SPACE` (user logon sessions)
      * <font color='red'>(new)</font> [wndscan](CommandReferenceGui22#wndscan.md) - Pool scanner for tagWINDOWSTATION (window stations)
      * <font color='red'>(new)</font> [deskscan](CommandReferenceGui22#deskscan.md) - Poolscaner for tagDESKTOP (desktops)
      * <font color='red'>(new)</font> [atomscan](CommandReferenceGui22#atomscan.md) - Pool scanner for `_RTL_ATOM_TABLE`
      * <font color='red'>(new)</font> [atoms](CommandReferenceGui22#atoms.md) - Print session and window station atom tables
      * <font color='red'>(new)</font> [clipboard](CommandReferenceGui22#clipboard.md) - Extract the contents of the windows clipboard
      * <font color='red'>(new)</font> [eventhooks](CommandReferenceGui22#eventhooks.md) - Print details on windows event hooks
      * <font color='red'>(new)</font> [gathi](CommandReferenceGui22#gahti.md) - Dump the USER handle type information
      * <font color='red'>(new)</font> [messagehooks](CommandReferenceGui22#messagehooks.md) - List desktop and thread window message hooks
      * <font color='red'>(new)</font> [screenshot](CommandReferenceGui22#screenshot.md) - Save a pseudo-screenshot based on GDI windows
      * <font color='red'>(new)</font> [userhandles](CommandReferenceGui22#userhandles.md) - Dump the USER handle tables
      * <font color='red'>(new)</font> [windows](CommandReferenceGui22#windows.md) - Print Desktop Windows (verbose details)
      * <font color='red'>(new)</font> [wintree](CommandReferenceGui22#wintree.md) - Print Z-Order Desktop Windows Tree
      * <font color='red'>(new)</font> [gditimers](CommandReferenceGui22#gditimers.md) - Analyze GDI timer objects and their callbacks
    * **Networking**
      * [connections](CommandReference22#connections.md) - Print open connections (XP and 2003 only)
      * [connscan](CommandReference22#connscan.md) - Scan Physical memory for `_TCPT_OBJECT` objects (XP and 2003 only)
      * [sockets](CommandReference22#sockets.md) - Print open sockets (XP and 2003 only)
      * [sockscan](CommandReference22#sockscan.md) - Scan Physical memory for `_ADDRESS_OBJECT` (XP and 2003 only)
      * [netscan](CommandReference22#netscan.md) - Scan physical memory for network objects (Vista, 2008, and 7)
    * **Registry**
      * [hivescan](CommandReference22#hivescan.md) - Scan Physical memory for `_CMHIVE` objects
      * [hivelist](CommandReference22#hivelist.md) - Print list of registry hives
      * [printkey](CommandReference22#printkey.md) - Print a registry key, and its subkeys and values
      * [hivedump](CommandReference22#hivedump.md) - Recursively prints all keys and timestamps in a given hive
      * [hashdump](CommandReference22#hashdump.md) - Dumps passwords hashes (LM/NTLM) from memory (x86 only)
      * [lsadump](CommandReference22#lsadump.md) - Dump (decrypted) LSA secrets from the registry (XP and 2003 x86 only)
      * [userassist](CommandReference22#userassist.md) - Parses and output User Assist keys from the registry
      * [shimcache](CommandReference21#shimcache.md) - Parses the Application Compatibility Shim Cache registry key
      * <font color='red'>(new)</font> [getservicesids](CommandReference22#getservicesids.md) - Calculate SIDs for windows services in the registry
    * **File Formats**
      * [crashinfo](CommandReference22#crashinfo.md) - Dump crash-dump information
      * [hibinfo](CommandReference22#hibinfo.md) - Dump hibernation file information
      * [imagecopy](CommandReference22#imagecopy.md) - Copies a physical address space out as a raw DD image
      * [raw2dmp](CommandReference22#raw2dmp.md) - Converts a physical memory sample to a windbg crash dump
    * **Malware**
      * [malfind](CommandReferenceMal22#malfind.md) - Find hidden and injected code
      * [svcscan](CommandReferenceMal22#svcscan.md) - Scan for Windows services
      * [ldrmodules](CommandReferenceMal22#ldrmodules.md) - Detect unlinked DLLs
      * [impscan](CommandReferenceMal22#impscan.md) - Scan for calls to imported functions
      * [apihooks](CommandReferenceMal22#apihooks.md) - Detect API hooks in process and kernel memory (x86 only)
      * [idt](CommandReferenceMal22#idt.md) - Dumps the Interrupt Descriptor Table (x86 only)
      * [gdt](CommandReferenceMal22#gdt.md) - Dumps the Global Descriptor Table (x86 only)
      * [threads](CommandReferenceMal22#threads.md) - Investigate `_ETHREAD` and `_KTHREAD`s
      * [callbacks](CommandReferenceMal22#callbacks.md) - Print system-wide notification routines (x86 only)
      * [driverirp](CommandReferenceMal22#driverirp.md) - Driver IRP hook detection
      * [devicetree](CommandReferenceMal22#devicetree.md) - Show device tree
      * [psxview](CommandReferenceMal22#psxview.md) - Find hidden processes with various process listings
      * [timers](CommandReferenceMal22#timers.md) - Print kernel timers and associated module DPCs (x86 only)
    * **Miscellaneous**
      * [strings](CommandReference22#strings.md) - Match physical offsets to virtual addresses
      * [volshell](CommandReference22#volshell.md) - Shell to interactively explore a memory image
      * [bioskbd](CommandReference22#bioskbd.md) - Reads the keyboard buffer from Real Mode memory
      * [patcher](CommandReference22#patcher.md) - Patches memory based on page scans
  * **Linux**
    * **Processes**
      * <font color='red'>(new)</font> [linux\_pslist](LinuxCommandReference22#linux_pslist.md) - Gather active tasks by walking the task\_struct->task list
      * <font color='red'>(new)</font> [linux\_psaux](LinuxCommandReference22#linux_psaux.md) - Gathers processes along with full command line and start time
      * <font color='red'>(new)</font> [linux\_pslist\_cache](LinuxCommandReference22#linux_pslist_cache.md) - Gather tasks from the kmem\_cache
      * <font color='red'>(new)</font> [linux\_pstree](LinuxCommandReference22#linux_pstree.md) - Shows the parent/child relationship between processes
      * <font color='red'>(new)</font> [linux\_psxview](LinuxCommandReference22#linux_psxview.md) - Find hidden processes with various process listings
    * **Process Memory**
      * <font color='red'>(new)</font> [linux\_dump\_map](LinuxCommandReference22#linux_dump_map.md) - Writes selected process memory mappings to disk
      * <font color='red'>(new)</font> [linux\_memmap](LinuxCommandReference22#linux_memmap.md) - Dumps the memory map for linux tasks
      * <font color='red'>(new)</font> [linux\_pidhashtable](LinuxCommandReference22#linux_pidhashtable.md) - Enumerates processes through the PID hash table
      * <font color='red'>(new)</font> [linux\_proc\_maps](LinuxCommandReference22#linux_proc_maps.md) - Gathers process maps for linux
      * <font color='red'>(new)</font> [linux\_bash](LinuxCommandReference22#linux_bash.md) - Recover bash history from bash process memory
    * **Kernel Memory and Objects**
      * <font color='red'>(new)</font> [linux\_lsmod](LinuxCommandReference22#linux_lsmod.md) - Gather loaded kernel modules
      * <font color='red'>(new)</font> [linux\_lsof](LinuxCommandReference22#linux_lsof.md) - Lists open files
      * <font color='red'>(new)</font> [linux\_tmpfs](LinuxCommandReference22#linux_tmpfs.md) - Recovers tmpfs filesystems from memory
    * **Networking**
      * <font color='red'>(new)</font> [linux\_arp](LinuxCommandReference22#linux_arp.md) - Print the ARP table
      * <font color='red'>(new)</font> [linux\_ifconfig](LinuxCommandReference22#linux_ifconfig.md) - Gathers active interfaces
      * <font color='red'>(new)</font> [linux\_netstat](LinuxCommandReference22#linux_netstat.md) - Lists open sockets
      * <font color='red'>(new)</font> [linux\_route\_cache](LinuxCommandReference22#linux_route_cache.md) - Recovers the routing cache from memory
      * <font color='red'>(new)</font> [linux\_pkt\_queues](LinuxCommandReference22#linux_pkt_queues.md) - Writes per-process packet queues out to disk
      * <font color='red'>(new)</font> [linux\_sk\_buff\_cache](LinuxCommandReference22#linux_sk_buff_cache.md) - Recovers packets from the sk\_buff kmem\_cache
    * **Malware/Rootkits**
      * <font color='red'>(new)</font> [linux\_check\_afinfo](LinuxCommandReference22#linux_check_afinfo.md) - Verifies the operation function pointers of network protocols
      * <font color='red'>(new)</font> [linux\_check\_creds](LinuxCommandReference22#linux_check_creds.md) - Checks if any processes are sharing credential structures
      * <font color='red'>(new)</font> [linux\_check\_fop](LinuxCommandReference22#linux_check_fop.md) - Check file operation structures for rootkit modifications
      * <font color='red'>(new)</font> [linux\_check\_idt](LinuxCommandReference22#linux_check_idt.md) - Checks if the IDT has been altered
      * <font color='red'>(new)</font> [linux\_check\_modules](LinuxCommandReference22#linux_check_modules.md) - Compares module list to sysfs info, if available
      * <font color='red'>(new)</font> [linux\_check\_syscall](LinuxCommandReference22#linux_check_syscall.md) - Checks if the system call table has been altered
    * **System Information**
      * <font color='red'>(new)</font> [linux\_cpuinfo](LinuxCommandReference22#linux_cpuinfo.md) - Prints info about each active processor
      * <font color='red'>(new)</font> [linux\_dmesg](LinuxCommandReference22#linux_dmesg.md) - Gather dmesg buffer
      * <font color='red'>(new)</font> [linux\_iomem](LinuxCommandReference22#linux_iomem.md) - Provides output similar to /proc/iomem
      * <font color='red'>(new)</font> [linux\_mount](LinuxCommandReference22#linux_mount.md) - Gather mounted fs/devices
      * <font color='red'>(new)</font> [linux\_mount\_cache](LinuxCommandReference22#linux_mount_cache.md) - Gather mounted fs/devices from kmem\_cache
      * <font color='red'>(new)</font> [linux\_slabinfo](LinuxCommandReference22#linux_slabinfo.md) - Mimics /proc/slabinfo on a running machine
      * <font color='red'>(new)</font> [linux\_dentry\_cache](LinuxCommandReference22#linux_dentry_cache.md) - Gather files from the dentry cache
      * <font color='red'>(new)</font> [linux\_find\_file](LinuxCommandReference22#linux_find_file.md) - Extract cached file contents from memory via inodes
      * <font color='red'>(new)</font> [linux\_vma\_cache](LinuxCommandReference22#linux_vma_cache.md) - Gather VMAs from the vm\_area\_struct cache

# Release Notes #

  * AMD64 specs say that bits 63-48 of 64-bit addresses/pointers should be a sign extension of bit 47. In other words, only 48 of the 64 bits are used for address translation...the other bits are not necessary to map a virtual address to physical offset. Thus Volatility currently doesn't differentiate, so vtop(0xfffff80002837070) == vtop(0x1234f80002837070) == vtop(0xf80002837070). Although all three virtual addresses translate to the same physical offset, their values are not exactly equal (i.e. 0xfffff80002837070 != 0x1234f80002837070 != 0xf80002837070). In Volatility 2.2 we apply a bitmask to all pointers (see [Issue #184](https://code.google.com/p/volatility/issues/detail?id=#184) and #[Issue 190](https://code.google.com/p/volatility/issues/detail?id=190)) which allows us to perform the correct translations globally while still allowing pointer comparisons to work as expected. As a side effect, you may see object offsets printed by plugins as either 0xfffff80002837070 (all upper bits set) or 0xf80002837070 (all upper bits cleared).

# API Changes #

## Module Dumping/PE Extraction ##

  * The ProcExeDump.dump\_pe, get\_code, and get\_image functions previously took an outfd parameter which was used to report errors back to the user with outfd.write. This has been deprecated. The functions no longer accept an outfd parameter, as errors are reported through the standard debug facility. For more information see [r2162](https://code.google.com/p/volatility/source/detail?r=2162).