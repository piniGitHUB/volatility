# Introduction #

Volatility 2.0 was released August 2011.

  * [Volatility 2.0 Standalone Windows Program](http://volatility.googlecode.com/files/volatility-2.0.standalone.exe)
  * [Volatility 2.0 Windows Module Installer](http://volatility.googlecode.com/files/volatility-2.0.win32.exe)
  * [Volatility 2.0 Source code (tgz)](http://volatility.googlecode.com/files/volatility-2.0.tar.gz)
  * [Volatility 2.0 Source code (zip)](http://volatility.googlecode.com/files/volatility-2.0.zip)

# Release Highlights #

  * Restructured and depolluted namespace
  * Usage and Development Documentation
  * New Configuration Subsystem
  * New Caching Subsystem
  * New Pluggable address spaces with automated election
  * New Address Spaces (i.e. EWF, Firewire)
  * Updated Object Model and Profile Subsystems (VolatilityMagic)
  * Support for Windows Server 2003, Windows Vista, Windows Server 2008, Windows 7
  * Updated Scanning Framework
  * Volshell integration
  * Over 40 new plugins!

# Operating Systems #

  * 32-bit Windows XP Service Pack 2 and 3
  * <font color='red'>(new)</font> 32-bit Windows 2003 Server Service Pack 0, 1, 2
  * <font color='red'>(new)</font> 32-bit Windows Vista Service Pack 0, 1, 2
  * <font color='red'>(new)</font> 32-bit Windows 2008 Server Service Pack 1, 2
  * <font color='red'>(new)</font> 32-bit Windows 7 Service Pack 0, 1

# Address Spaces #

  * FileAddressSpace - This is a direct file AS
  * Legacy Intel x86 address spaces
    * IA32PagedMemoryPae
    * IA32PagedMemory
  * Standard Intel x86 address spaces
    * JKIA32PagedMemoryPae
    * JKIA32PagedMemory
  * [WindowsCrashDumpSpace32](CrashAddressSpace.md) - This AS supports windows Crash Dump format (x86)
  * [WindowsHiberFileSpace32](HiberAddressSpace.md) - This AS supports windows hibernation files (x86)
  * <font color='red'>(new)</font> [EWFAddressSpace](EWFAddressSpace.md) - This AS supports expert witness (EWF) files
  * <font color='red'>(new)</font> [FirewireAddressSpace](FirewireAddressSpace.md) - This AS supports direct memory access over firewire

# Plugins #

  * **Image Identification**
    * [imageinfo](CommandReference20#imageinfo.md) - Identify information for the image
    * [kdbgscan](CommandReference20#kdbgscan.md) - Search for and dump potential KDBG values
    * [kpcrscan](CommandReference20#kpcrscan.md) - Search for and dump potential `_KPCR` values
  * **Process and DLLs**
    * [pslist](CommandReference20#pslist.md) - Print active processes by following the `_EPROCESS` list
    * [pstree](CommandReference20#pstree.md) - Print process list as a tree
    * [psscan](CommandReference20#psscan.md) - Scan Physical memory for `_EPROCESS` pool allocations
    * [dlllist](CommandReference20#dlllist.md) - Print list of loaded DLLs for each process
    * [dlldump](CommandReference20#dlldump.md) - Dump DLLs from a process address space
    * [handles](CommandReference20#handles.md) - Print list of open handles for each process
    * [getsids](CommandReference20#getsids.md) - Print the SIDs owning each process
    * [verinfo](CommandReference20#verinfo.md) - Print a PE file's version information
    * [enumfunc](CommandReference20#enumfunc.md) - Enumerate a PE file's imports and exports
  * **Process Memory**
    * [memmap](CommandReference20#memmap.md) - Print the memory map
    * [memdump](CommandReference20#memdump.md) - Dump the addressable memory for a process
    * [procexedump](CommandReference20#procexedump.md) - Dump a process to an executable file
    * [procmemdump](CommandReference20#procmemdump.md) - Dump a process to an executable memory sample
    * [vadwalk](CommandReference20#vadwalk.md) - Walk the VAD tree
    * [vadtree](CommandReference20#vadtree.md) - Walk the VAD tree and display in tree format
    * [vadinfo](CommandReference20#vadinfo.md) - Dump the VAD info
    * [vaddump](CommandReference20#vaddump.md) - Dumps out the vad sections to a file
  * **Kernel Memory and Objects**
    * [modules](CommandReference20#modules.md) - Print list of loaded modules
    * [modscan](CommandReference20#modscan.md) - Scan Physical memory for `_LDR_DATA_TABLE_ENTRY` objects
    * [moddump](CommandReference20#moddump.md) - Extract a kernel driver to disk
    * [ssdt](CommandReference20#ssdt.md) - Print the Native and GDI System Service Descriptor Tables
    * [driverscan](CommandReference20#driverscan.md) - Scan physical memory for `_DRIVER_OBJECT` objects
    * [filescan](CommandReference20#filescan.md) - Scan physical memory for `_FILE_OBJECT` objects
    * [mutantscan](CommandReference20#mutantscan.md) - Scan physical memory for `_KMUTANT` objects
    * [symlinkscan](CommandReference20#symlinkscan.md) - Scans for symbolic link objects
    * [thrdscan](CommandReference20#thrdscan.md) - Scan physical memory for `_ETHREAD` objects
  * **Networking**
    * [connections](CommandReference20#connections.md) - Print open connections (XP and 2003 only)
    * [connscan](CommandReference20#connscan.md) - Scan Physical memory for `_TCPT_OBJECT` objects (XP and 2003 only)
    * [sockets](CommandReference20#sockets.md) - Print open sockets (XP and 2003 only)
    * [sockscan](CommandReference20#sockscan.md) - Scan Physical memory for `_ADDRESS_OBJECT` (XP and 2003 only)
    * [netscan](CommandReference20#netscan.md) - Scan physical memory for network objects (Vista, 2008, and 7)
  * **Registry**
    * [hivescan](CommandReference20#hivescan.md) - Scan Physical memory for `_CMHIVE` objects
    * [hivelist](CommandReference20#hivelist.md) - Print list of registry hives
    * [printkey](CommandReference20#printkey.md) - Print a registry key, and its subkeys and values
    * [hivedump](CommandReference20#hivedump.md) - Recursively prints all keys and timestamps in a given hive
    * [hashdump](CommandReference20#hashdump.md) - Dumps passwords hashes (LM/NTLM) from memory
    * [lsadump](CommandReference20#lsadump.md) - Dump (decrypted) LSA secrets from the registry
    * [userassist](CommandReference20#userassist.md) - Parses and output User Assist keys from the registry
  * **File Formats**
    * [crashinfo](CommandReference20#crashinfo.md) - Dump crash-dump information
    * [hibinfo](CommandReference20#hibinfo.md) - Dump hibernation file information
    * [imagecopy](CommandReference20#imagecopy.md) - Copies a physical address space out as a raw DD image
  * **Malware**
    * [malfind](CommandReference20#malfind.md) - Find hidden and injected code
    * [svcscan](CommandReference20#svcscan.md) - Scan for Windows services
    * [ldrmodules](CommandReference20#ldrmodules.md) - Detect unlinked DLLs
    * [impscan](CommandReference20#impscan.md) - Scan for calls to imported functions
    * [apihooks](CommandReference20#apihooks.md) - Detect API hooks in process and kernel memory
    * [idt](CommandReference20#idt.md) - Dumps the Interrupt Descriptor Table
    * [gdt](CommandReference20#gdt.md) - Dumps the Global Descriptor Table
    * [threads](CommandReference20#threads.md) - Investigate `_ETHREAD` and `_KTHREAD`s
    * [callbacks](CommandReference20#callbacks.md) - Print system-wide notification routines
    * [driverirp](CommandReference20#driverirp.md) - Driver IRP hook detection
    * [devicetree](CommandReference20#devicetree.md) - Show device tree
    * [psxview](CommandReference20#psxview.md) - Find hidden processes with various process listings
    * [timers](CommandReference20#timers.md) - Print kernel timers and associated module DPCs
  * **Miscellaneous**
    * [strings](CommandReference20#strings.md) - Match physical offsets to virtual addresses
    * [volshell](CommandReference20#volshell.md) - Shell to interactively explore a memory image
    * [bioskbd](CommandReference20#bioskbd.md) - Reads the keyboard buffer from Real Mode memory
    * [patcher](CommandReference20#patcher.md) - Patches memory based on page scans
