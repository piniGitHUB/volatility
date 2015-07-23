# Introduction #

This page contains the release notes for Volatility 2.3.

# Release Highlights #

  * Windows
    * new plugins to parse IE history/index.dat URLs, recover shellbags data, dump cached files (exe/pdf/doc/etc), extract the MBR and MFT records, explore recently unloaded kernel modules, dump SSL private and public keys/certs, and display details on process privileges
    * added plugins to detect poison ivy infections, find and decrypt configurations in memory for poison ivy, zeus v1, zeus v2 and citadelscan 1.3.4.5
    * apihooks detects duqu style instruction modifications (MOV reg32, imm32; JMP reg32)
    * crashinfo displays uptime, systemtime, and dump type (i.e. kernel, complete, etc)
    * psxview plugin adds two new sources of process listings from the GUI APIs
    * screenshots plugin shows text for window titles
    * svcscan automatically queries the cached registry for service dlls
    * dlllist shows load count to distinguish between static and dynamic loaded dlls
  * New address spaces
    * added support for VirtualBox ELF64 core dumps, VMware saved state (vmss) and snapshot (vmsn) files, and FDPro's non-standard HPAK format
    * associated plugins: vboxinfo, vmwareinfo, hpakinfo, hpakextract
  * Mac
    * new MachO address space for 32- and 64-bit Mac memory samples
    * over 30+ plugins for Mac memory forensics
  * Linux/Android
    * new ARM address space to support memory dumps from Linux and Android devices on ARM
    * added plugins to scan linux process and kernel memory with yara signatures, dump LKMs to disk, and check TTY devices for rootkit hooks
    * added plugins to check the ARM system call and exception vector tables for hooks

# Operating Systems #

Volatility supports the following operating systems and versions. All Windows profiles are included in the standard Volatility package. You can download sample Linux profiles from the LinuxProfiles wiki page or read LinuxMemoryForensics on how to build your own. You can download a [single archive of 38 different Mac OSX profiles](https://code.google.com/p/volatility/downloads/detail?name=MacProfilesAll.zip) or read MacMemoryForensics to build your own.

  * Windows
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
  * Linux
    * 32-bit Linux kernels 2.6.11 to 3.5
    * 64-bit Linux kernels 2.6.11 to 3.5
    * OpenSuSE, Ubuntu, Debian, CentOS, Fedora, Mandriva, etc
  * Mac OSX
    * <font color='red'>(new)</font> 32-bit 10.5.x Leopard (the only 64-bit 10.5 is Server, which isn't supported)
    * <font color='red'>(new)</font> 32-bit 10.6.x Snow Leopard
    * <font color='red'>(new)</font> 64-bit 10.6.x Snow Leopard
    * <font color='red'>(new)</font> 32-bit 10.7.x Lion
    * <font color='red'>(new)</font> 64-bit 10.7.x Lion
    * <font color='red'>(new)</font> 64-bit 10.8.x Mountain Lion (there is no 32-bit version)

# Address Spaces #

  * FileAddressSpace - This is a direct file AS
  * Standard Intel x86 address spaces
    * IA32PagedMemoryPae
    * IA32PagedMemory
  * AMD64PagedMemory - This AS supports AMD 64-bit address spaces
  * [WindowsCrashDumpSpace32](CrashAddressSpace.md) - This AS supports windows Crash Dump format (x86)
  * [WindowsCrashDumpSpace64](CrashAddressSpace.md) - This AS supports windows Crash Dump format (x64)
  * [WindowsHiberFileSpace32](HiberAddressSpace.md) - This AS supports windows hibernation files (x86 and x64)
  * [EWFAddressSpace](EWFAddressSpace.md) - This AS supports expert witness (EWF) files
  * [FirewireAddressSpace](FirewireAddressSpace.md) - This AS supports direct memory access over firewire
  * [LimeAddressSpace](LimeAddressSpace.md) - This AS supports LiME (Linux Memory Extractor)
  * <font color='red'>(new)</font> [MachOAddressSpace](MachOAddressSpace.md) - This AS supports 32- and 64-bit Mac OSX memory dumps
  * <font color='red'>(new)</font> [ArmAddressSpace](ArmAddressSpace.md) - This AS supports memory dumps from 32-bit ARM (there is no 64-bit ARM yet)
  * <font color='red'>(new)</font> [VirtualBoxCoreDumpElf64](VirtualBoxCoreDump.md) - This AS supports memory dumps from VirtualBox virtual machines
  * <font color='red'>(new)</font> [VMware Snapshot](VMwareSnapshotFile.md) - This AS supports VMware saved state (.vmss) and VMware snapshot (.vmsn) files. **Note**: these are _not_ raw memory dumps like the typical .vmem files.
  * <font color='red'>(new)</font> [HPAKAddressSpace](HPAKAddressSpace.md) - This AS supports ".hpak" files produced by H.B. Gary's FDPro tool.

# Plugins #

  * **Windows**
    * **Image Identification**
      * [imageinfo](CommandReference23#imageinfo.md) - Identify information for the image
      * [kdbgscan](CommandReference23#kdbgscan.md) - Search for and dump potential KDBG values
      * [kpcrscan](CommandReference23#kpcrscan.md) - Search for and dump potential `_KPCR` values
    * **Process and DLLs**
      * [pslist](CommandReference23#pslist.md) - Print active processes by following the `_EPROCESS` list
      * [pstree](CommandReference23#pstree.md) - Print process list as a tree
      * [psscan](CommandReference23#psscan.md) - Scan Physical memory for `_EPROCESS` pool allocations
      * [psdispscan](CommandReference23#psdispscan.md) - Scan Physical memory for `_EPROCESS` objects based on Dispatch Headers (Windows XP x86 only)
      * [dlllist](CommandReference23#dlllist.md) - Print list of loaded DLLs for each process
      * [dlldump](CommandReference23#dlldump.md) - Dump DLLs from a process address space
      * [handles](CommandReference23#handles.md) - Print list of open handles for each process
      * [getsids](CommandReference23#getsids.md) - Print the SIDs owning each process
      * [verinfo](CommandReference23#verinfo.md) - Print a PE file's version information
      * [enumfunc](CommandReference23#enumfunc.md) - Enumerate a PE file's imports and exports
      * [envars](CommandReference23#envars.md) - Display process environment variables
      * [cmdscan](CommandReference23#cmdscan.md) - Extract command history by scanning for `_COMMAND_HISTORY`
      * [consoles](CommandReference21#consoles.md) - Extract command history by scanning for `_CONSOLE_INFORMATION`
      * <font color='red'>(new)</font> [privs](CommandReference23#privs.md) - Identify the present and/or enabled windows privileges for each process
    * **Process Memory**
      * [memmap](CommandReference23#memmap.md) - Print the memory map
      * [memdump](CommandReference23#memdump.md) - Dump the addressable memory for a process
      * [procexedump](CommandReference23#procexedump.md) - Dump a process to an executable file
      * [procmemdump](CommandReference23#procmemdump.md) - Dump a process to an executable memory sample
      * [vadwalk](CommandReference23#vadwalk.md) - Walk the VAD tree
      * [vadtree](CommandReference23#vadtree.md) - Walk the VAD tree and display in tree format
      * [vadinfo](CommandReference23#vadinfo.md) - Dump the VAD info
      * [vaddump](CommandReference23#vaddump.md) - Dumps out the vad sections to a file
      * [evtlogs](CommandReference23#evtlogs.md) - Parse XP and 2003 event logs from memory
      * <font color='red'>(new)</font> [iehistory](CommandReference23#iehistory.md) - Extract and parse Internet Explorer history and URL cache
    * **Kernel Memory and Objects**
      * [modules](CommandReference23#modules.md) - Print list of loaded modules
      * [modscan](CommandReference23#modscan.md) - Scan Physical memory for `_LDR_DATA_TABLE_ENTRY` objects
      * [moddump](CommandReference23#moddump.md) - Extract a kernel driver to disk
      * [ssdt](CommandReference23#ssdt.md) - Print the Native and GDI System Service Descriptor Tables
      * [driverscan](CommandReference23#driverscan.md) - Scan physical memory for `_DRIVER_OBJECT` objects
      * [filescan](CommandReference23#filescan.md) - Scan physical memory for `_FILE_OBJECT` objects
      * [mutantscan](CommandReference23#mutantscan.md) - Scan physical memory for `_KMUTANT` objects
      * [symlinkscan](CommandReference23#symlinkscan.md) - Scans for symbolic link objects
      * [thrdscan](CommandReference23#thrdscan.md) - Scan physical memory for `_ETHREAD` objects
      * <font color='red'>(new)</font> [dumpfiles](CommandReference23#dumpfiles.md) - Reconstruct files from the windows cache manager and shared section objects
      * <font color='red'>(new)</font> [unloadedmodules](CommandReference23#unloadedmodules.md) - Show recently unloaded kernel modules (which indirectly tells you which ones recently loaded)
    * **Win32k / GUI Memory**
      * [sessions](CommandReferenceGui23#sessions.md) - List details on `_MM_SESSION_SPACE` (user logon sessions)
      * [wndscan](CommandReferenceGui23#wndscan.md) - Pool scanner for tagWINDOWSTATION (window stations)
      * [deskscan](CommandReferenceGui23#deskscan.md) - Poolscaner for tagDESKTOP (desktops)
      * [atomscan](CommandReferenceGui23#atomscan.md) - Pool scanner for `_RTL_ATOM_TABLE`
      * [atoms](CommandReferenceGui23#atoms.md) - Print session and window station atom tables
      * [clipboard](CommandReferenceGui23#clipboard.md) - Extract the contents of the windows clipboard
      * [eventhooks](CommandReferenceGui23#eventhooks.md) - Print details on windows event hooks
      * [gathi](CommandReferenceGui23#gahti.md) - Dump the USER handle type information
      * [messagehooks](CommandReferenceGui23#messagehooks.md) - List desktop and thread window message hooks
      * [screenshot](CommandReferenceGui23#screenshot.md) - Save a pseudo-screenshot based on GDI windows
      * [userhandles](CommandReferenceGui23#userhandles.md) - Dump the USER handle tables
      * [windows](CommandReferenceGui23#windows.md) - Print Desktop Windows (verbose details)
      * [wintree](CommandReferenceGui23#wintree.md) - Print Z-Order Desktop Windows Tree
      * [gditimers](CommandReferenceGui23#gditimers.md) - Analyze GDI timer objects and their callbacks
    * **Networking**
      * [connections](CommandReference23#connections.md) - Print open connections (XP and 2003 only)
      * [connscan](CommandReference23#connscan.md) - Scan Physical memory for `_TCPT_OBJECT` objects (XP and 2003 only)
      * [sockets](CommandReference23#sockets.md) - Print open sockets (XP and 2003 only)
      * [sockscan](CommandReference23#sockscan.md) - Scan Physical memory for `_ADDRESS_OBJECT` (XP and 2003 only)
      * [netscan](CommandReference23#netscan.md) - Scan physical memory for network objects (Vista, 2008, and 7)
    * **Registry**
      * [hivescan](CommandReference23#hivescan.md) - Scan Physical memory for `_CMHIVE` objects
      * [hivelist](CommandReference23#hivelist.md) - Print list of registry hives
      * [printkey](CommandReference23#printkey.md) - Print a registry key, and its subkeys and values
      * [hivedump](CommandReference23#hivedump.md) - Recursively prints all keys and timestamps in a given hive
      * [hashdump](CommandReference23#hashdump.md) - Dumps passwords hashes (LM/NTLM) from memory (x86 only)
      * [lsadump](CommandReference23#lsadump.md) - Dump (decrypted) LSA secrets from the registry (XP and 2003 x86 only)
      * [userassist](CommandReference23#userassist.md) - Parses and output User Assist keys from the registry
      * [shimcache](CommandReference21#shimcache.md) - Parses the Application Compatibility Shim Cache registry key
      * [getservicesids](CommandReference23#getservicesids.md) - Calculate SIDs for windows services in the registry
      * <font color='red'>(new)</font> [shellbags](CommandReference23#shellbags.md) - This plugin parses and prints Shellbag information obtained from the registry
    * **File Formats**
      * [crashinfo](CommandReference23#crashinfo.md) - Dump crash-dump information
      * [hibinfo](CommandReference23#hibinfo.md) - Dump hibernation file information
      * [imagecopy](CommandReference23#imagecopy.md) - Copies a physical address space out as a raw DD image
      * [raw2dmp](CommandReference23#raw2dmp.md) - Converts a physical memory sample to a windbg crash dump
      * <font color='red'>(new)</font> [vboxinfo](CommandReference23#vboxinfo.md) - Display header and memory runs information from VirtualBox core dumps
      * <font color='red'>(new)</font> [vmwareinfo](CommandReference23#vmwareinfo.md) - Display header and memory runs information from VMware vmss or vmsn files
      * <font color='red'>(new)</font> [hpakinfo](CommandReference23#hpakinfo.md) - Display header and memory runs information from .hpak files
      * <font color='red'>(new)</font> [hpakextract](CommandReference23#hpakextract.md) - Extract (and decompress if necessary) the raw physical memory dump from an .hpak file
    * **Malware**
      * [malfind](CommandReferenceMal23#malfind.md) - Find hidden and injected code
      * [svcscan](CommandReferenceMal23#svcscan.md) - Scan for Windows services
      * [ldrmodules](CommandReferenceMal23#ldrmodules.md) - Detect unlinked DLLs
      * [impscan](CommandReferenceMal23#impscan.md) - Scan for calls to imported functions
      * [apihooks](CommandReferenceMal23#apihooks.md) - Detect API hooks in process and kernel memory (x86 only)
      * [idt](CommandReferenceMal23#idt.md) - Dumps the Interrupt Descriptor Table (x86 only)
      * [gdt](CommandReferenceMal23#gdt.md) - Dumps the Global Descriptor Table (x86 only)
      * [threads](CommandReferenceMal23#threads.md) - Investigate `_ETHREAD` and `_KTHREAD`s
      * [callbacks](CommandReferenceMal23#callbacks.md) - Print system-wide notification routines (x86 only)
      * [driverirp](CommandReferenceMal23#driverirp.md) - Driver IRP hook detection
      * [devicetree](CommandReferenceMal23#devicetree.md) - Show device tree
      * [psxview](CommandReferenceMal23#psxview.md) - Find hidden processes with various process listings
      * [timers](CommandReferenceMal23#timers.md) - Print kernel timers and associated module DPCs (x86 only)
    * **File System**
      * <font color='red'>(new)</font> [mbrparser](CommandReference23#mbrparser.md) - Scans for and parses potential Master Boot Records (MBRs)
      * <font color='red'>(new)</font> [mftparser](CommandReference23#mftparser.md) - Scans for and parses potential MFT entries
    * **Miscellaneous**
      * [strings](CommandReference23#strings.md) - Match physical offsets to virtual addresses
      * [volshell](CommandReference23#volshell.md) - Shell to interactively explore a memory image
      * [bioskbd](CommandReference23#bioskbd.md) - Reads the keyboard buffer from Real Mode memory
      * [patcher](CommandReference23#patcher.md) - Patches memory based on page scans
      * <font color='red'>(new)</font> [timeliner](CommandReference23#timeliner.md) - Produce timelines in body file format, excel 2007 spreadsheets, or text
      * <font color='red'>(new)</font> [dumpcerts](CommandReference23#dumpcerts.md) - Extract SSL private and public keys/certs
  * **Linux/Android**
    * **Processes**
      * [linux\_pslist](LinuxCommandReference23#linux_pslist.md) - Gather active tasks by walking the task\_struct->task list
      * [linux\_psaux](LinuxCommandReference23#linux_psaux.md) - Gathers processes along with full command line and start time
      * [linux\_pstree](LinuxCommandReference23#linux_pstree.md) - Shows the parent/child relationship between processes
      * [linux\_pslist\_cache](LinuxCommandReference23#linux_pslist_cache.md) - Gather tasks from the kmem\_cache
      * [linux\_pidhashtable](LinuxCommandReference23#linux_pidhashtable.md) - Enumerates processes through the PID hash table
      * [linux\_psxview](LinuxCommandReference23#linux_psxview.md) - Find hidden processes with various process listings
      * [linux\_lsof](LinuxCommandReference23#linux_lsof.md) - Lists open files
    * **Process Memory**
      * [linux\_memmap](LinuxCommandReference23#linux_memmap.md) - Dumps the memory map for linux tasks
      * [linux\_proc\_maps](LinuxCommandReference23#linux_proc_maps.md) - Gathers process maps for linux
      * [linux\_dump\_map](LinuxCommandReference23#linux_dump_map.md) - Writes selected process memory mappings to disk
      * [linux\_bash](LinuxCommandReference23#linux_bash.md) - Recover bash history from bash process memory
    * **Kernel Memory and Objects**
      * [linux\_lsmod](LinuxCommandReference23#linux_lsmod.md) - Gather loaded kernel modules
      * [linux\_tmpfs](LinuxCommandReference23#linux_tmpfs.md) - Recovers tmpfs filesystems from memory
      * <font color='red'>(new)</font> [linux\_moddump](LinuxCommandReference23#linux_moddump.md) - Extract an LKM from memory to disk (.text segment only)
    * **Networking**
      * [linux\_arp](LinuxCommandReference23#linux_arp.md) - Print the ARP table
      * [linux\_ifconfig](LinuxCommandReference23#linux_ifconfig.md) - Gathers active interfaces
      * [linux\_netstat](LinuxCommandReference23#linux_netstat.md) - Lists open sockets
      * [linux\_route\_cache](LinuxCommandReference23#linux_route_cache.md) - Recovers the routing cache from memory
      * [linux\_pkt\_queues](LinuxCommandReference23#linux_pkt_queues.md) - Writes per-process packet queues out to disk
      * [linux\_sk\_buff\_cache](LinuxCommandReference23#linux_sk_buff_cache.md) - Recovers packets from the sk\_buff kmem\_cache
    * **Malware/Rootkits**
      * [linux\_check\_afinfo](LinuxCommandReference23#linux_check_afinfo.md) - Verifies the operation function pointers of network protocols
      * [linux\_check\_creds](LinuxCommandReference23#linux_check_creds.md) - Checks if any processes are sharing credential structures
      * [linux\_check\_fop](LinuxCommandReference23#linux_check_fop.md) - Check file operation structures for rootkit modifications
      * [linux\_check\_idt](LinuxCommandReference23#linux_check_idt.md) - Checks if the IDT has been altered
      * [linux\_check\_modules](LinuxCommandReference23#linux_check_modules.md) - Compares module list to sysfs info, if available
      * [linux\_check\_syscall](LinuxCommandReference23#linux_check_syscall.md) - Checks if the system call table has been altered
      * <font color='red'>(new)</font> [linux\_check\_syscall\_arm](LinuxCommandReference23#linux_check_syscall_arm.md) - Checks if the system call table has been altered (ARM)
      * <font color='red'>(new)</font> [linux\_check\_tty](LinuxCommandReference23#linux_check_tty.md) - Check TTY devices for rootkit hooks
      * <font color='red'>(new)</font> [linux\_check\_evt\_arm](LinuxCommandReference23#linux_check_evt_arm.md) - Check ARM exception vector table for hooks
    * **System Information**
      * [linux\_cpuinfo](LinuxCommandReference23#linux_cpuinfo.md) - Prints info about each active processor
      * [linux\_dmesg](LinuxCommandReference23#linux_dmesg.md) - Gather dmesg buffer
      * [linux\_iomem](LinuxCommandReference23#linux_iomem.md) - Provides output similar to /proc/iomem
      * [linux\_mount](LinuxCommandReference23#linux_mount.md) - Gather mounted fs/devices
      * [linux\_mount\_cache](LinuxCommandReference23#linux_mount_cache.md) - Gather mounted fs/devices from kmem\_cache
      * [linux\_slabinfo](LinuxCommandReference23#linux_slabinfo.md) - Mimics /proc/slabinfo on a running machine
      * [linux\_dentry\_cache](LinuxCommandReference23#linux_dentry_cache.md) - Gather files from the dentry cache
      * [linux\_find\_file](LinuxCommandReference23#linux_find_file.md) - Extract cached file contents from memory via inodes
      * [linux\_vma\_cache](LinuxCommandReference23#linux_vma_cache.md) - Gather VMAs from the vm\_area\_struct cache
      * <font color='red'>(new)</font> [linux\_keyboard\_notifier](LinuxCommandReference23#linux_keyboard_notifier.md) - Parses the keyboard notifier call chain
    * **Miscellaneous**
      * <font color='red'>(new)</font> [linux\_volshell](CommandReference23#linux_volshell.md) - Shell to interactively explore Linux/Android memory captures
      * <font color='red'>(new)</font> [linux\_yarascan](CommandReference23#linux_yarascan.md) - Scan process and kernel memory with yara signatures
  * **Mac OSX**
    * **Processes**
      * <font color='red'>(new)</font> [mac\_pslist](MacCommandReference23#mac_pslist.md) - List running processes
      * <font color='red'>(new)</font> [mac\_tasks](MacCommandReference23#mac_tasks.md) - List active tasks
      * <font color='red'>(new)</font> [mac\_pstree](MacCommandReference23#mac_pstree.md) - Show parent/child relationship of processes
      * <font color='red'>(new)</font> [mac\_lsof](MacCommandReference23#mac_lsof.md) - Lists per-process open files
      * <font color='red'>(new)</font> [mac\_pgrp\_hash\_table](MacCommandReference23#mac_pgrp_hash_table.md) - Walks the process group hash table
      * <font color='red'>(new)</font> [mac\_pid\_hash\_table](MacCommandReference23#mac_pid_hash_table.md) - Walks the pid hash table
      * <font color='red'>(new)</font> [mac\_dead\_procs](MacCommandReference23#mac_dead_procs.md) - List dead/terminated processes
      * <font color='red'>(new)</font> [mac\_psaux](MacCommandReference23#mac_psaux.md) - Prints processes with their command-line arguments (argv)
    * **Process Memory**
      * <font color='red'>(new)</font> [mac\_proc\_maps](MacCommandReference23#mac_proc_maps.md) - Print information on allocated process memory ranges
      * <font color='red'>(new)</font> [mac\_dump\_maps](MacCommandReference23#mac_dump_maps.md) - Dumps memory ranges of processes
    * **Kernel Memory and Objects**
      * <font color='red'>(new)</font> [mac\_list\_sessions](MacCommandReference23#mac_list_sessions.md) - Enumerates sessions
      * <font color='red'>(new)</font> [mac\_list\_zones](MacCommandReference23#mac_list_zones.md) - Enumerates zones (allocated/freed object counts)
      * <font color='red'>(new)</font> [mac\_lsmod](MacCommandReference23#mac_lsmod.md) - Lists loaded kernel modules
      * <font color='red'>(new)</font> [mac\_mount](MacCommandReference23#mac_mount.md) - Prints mounted device information
    * **Networking**
      * <font color='red'>(new)</font> [mac\_arp](MacCommandReference23#mac_arp.md) - Prints the arp table
      * <font color='red'>(new)</font> [mac\_ifconfig](MacCommandReference23#mac_ifconfig.md) - Lists network interface information for all devices
      * <font color='red'>(new)</font> [mac\_netstat](MacCommandReference23#mac_netstat.md) - Lists active per-process network connections
      * <font color='red'>(new)</font> [mac\_route](MacCommandReference23#mac_route.md) - Prints the routing table
    * **Malware/Rootkits**
      * <font color='red'>(new)</font> [mac\_check\_sysctl](MacCommandReference23#mac_check_sysctl.md) - Check for unknown sysctl handlers
      * <font color='red'>(new)</font> [mac\_check\_syscalls](MacCommandReference23#mac_check_syscalls.md) - Check for hooked syscall table entries
      * <font color='red'>(new)</font> [mac\_check\_trap\_table](MacCommandReference23#mac_check_trap_table.md) - Checks to see if mach trap table entries are hooked
      * <font color='red'>(new)</font> [mac\_ip\_filters](MacCommandReference23#mac_ip_filters.md) - Reports any hooked IP filters
      * <font color='red'>(new)</font> [mac\_notifiers](MacCommandReference23#mac_notifiers.md) - Detects rootkits that add hooks into I/O Kit (e.g. LogKext)
      * <font color='red'>(new)</font> [mac\_trustedbsd](MacCommandReference23#mac_trustedbsd.md) - List malicious trustedbsd policies
    * **System Information**
      * <font color='red'>(new)</font> [mac\_dmesg](MacCommandReference23#mac_dmesg.md) - Prints the kernel debug buffers
      * <font color='red'>(new)</font> [mac\_find\_aslr\_shift](MacCommandReference23#mac_find_aslr_shift.md) - Find the ASLR shift value for 10.8+ images
      * <font color='red'>(new)</font> [mac\_machine\_info](MacCommandReference23#mac_machine_info.md) - Prints machine information about the sample
      * <font color='red'>(new)</font> [mac\_version](MacCommandReference23#mac_version.md) - Prints the Mac version
      * <font color='red'>(new)</font> [mac\_print\_boot\_cmdline](MacCommandReference23#mac_print_boot_cmdline.md) - Prints the mac boot command line
    * **Miscellaneous**
      * <font color='red'>(new)</font> [mac\_volshell](MacCommandReference23#mac_volshell.md) - Shell to interactively explore mac memory captures
      * <font color='red'>(new)</font> [machoinfo](MacCommandReference23#machoinfo.md) - Display header and memory runs for Mach-O memory dumps
      * <font color='red'>(new)</font> [mac\_yarascan](MacCommandReference23#mac_yarascan.md) - Scan for Yara signatures in process or kernel memory

# Credits #

In alphabetical order:

  * Cem Gurkok for his work on the privileges plugin for Windows
  * Nir Izraeli for his work on the VMware snapshot address space (see also the [vmsnparser](http://code.google.com/p/vmsnparser/) project)
  * @osxmem of the [volafox project](https://code.google.com/p/volafox/) (Mac OS X & BSD Memory Analysis Toolkit)
  * @osxreverser of [reverse.put.as](http://reverse.put.as/) for his help with OSX memory analysis
  * Carl Pulley for numerous bug reports, example patches, and plugin testing
  * Andreas Schuster for his work on poison ivy plugins for Windows
  * Joe Sylve for his work on the ARM address space and significant contributions to linux and mac  capabilities
  * Philippe Teuwen for his work on the virtual box address space
  * Santiago Vicente for his work on the citadel plugins for Windows