# Introduction #

Volatility 2.1 was released August 2012.

  * [Volatility 2.1 Standalone Windows Program](http://volatility.googlecode.com/files/volatility-2.1.standalone.exe)
  * [Volatility 2.1 Windows Module Installer](http://volatility.googlecode.com/files/volatility-2.1.win32.exe)
  * [Volatility 2.1 Source code (tgz)](http://volatility.googlecode.com/files/volatility-2.1.tar.gz)
  * [Volatility 2.1 Source code (zip)](http://volatility.googlecode.com/files/volatility-2.1.zip)

# Release Highlights #

  * New Address Spaces (AMD64PagedMemory, WindowsCrashDumpSpace64)
  * Majority of Existing Plugins Updated with x64 Support
  * Merged Malware Plugins into Volatility Core with Preliminary x64 Support
  * WindowsHiberFileSpace32 Overhaul (also includes x64 Support)
  * Now supports all major x64 Windows Operating Systems
  * Plugin Additions
    * Printing Process Environment Variables (envvars)
    * Inspecting the Shim Cache (shimcache)
    * Profiling Command History and Console Usage (cmdscan, consoles)
    * Converting x86 and x64 Raw Dumps to MS Crash Dump (raw2dmp)
  * Plugin Enhancements
    * Verbose details for kdbgscan and kpcrscan
    * idt/gdt/timers plugins cycle automatically for each CPU
    * apihooks detects LSP/winsock procedure tables
  * New Output Formatting Support (Table Rendering)
  * New Mechanism for Profile Modifications
  * New [Registry API Support](CommandReferenceRegistryApi22.md)
  * New Volshell Commands
  * Updated Documentation and Command Reference

# Operating Systems #

  * 32-bit Windows XP Service Pack 2 and 3
  * 32-bit Windows 2003 Server Service Pack 0, 1, 2
  * 32-bit Windows Vista Service Pack 0, 1, 2
  * 32-bit Windows 2008 Server Service Pack 1, 2
  * 32-bit Windows 7 Service Pack 0, 1
  * <font color='red'>(new)</font> 64-bit Windows XP Service Pack 1 and 2
  * <font color='red'>(new)</font> 64-bit Windows 2003 Server Service Pack 1 and 2
  * <font color='red'>(new)</font> 64-bit Windows Vista Service Pack 0, 1, 2
  * <font color='red'>(new)</font> 64-bit Windows 2008 Server Service Pack 1 and 2
  * <font color='red'>(new)</font> 64-bit Windows 2008 `R2` Server Service Pack 0 and 1
  * <font color='red'>(new)</font> 64-bit Windows 7 Service Pack 0 and 1

# Address Spaces #

  * FileAddressSpace - This is a direct file AS
  * Legacy Intel x86 address spaces
    * IA32PagedMemoryPae
    * IA32PagedMemory
  * Standard Intel x86 address spaces
    * JKIA32PagedMemoryPae
    * JKIA32PagedMemory
  * <font color='red'>(new)</font> AMD64PagedMemory - This AS supports AMD 64-bit address spaces
  * [WindowsCrashDumpSpace32](CrashAddressSpace.md) - This AS supports windows Crash Dump format (x86)
  * <font color='red'>(new)</font> [WindowsCrashDumpSpace64](CrashAddressSpace.md) - This AS supports windows Crash Dump format (x64)
  * <font color='red'>(new)</font> [WindowsHiberFileSpace32](HiberAddressSpace.md) - This AS supports windows hibernation files (x86 and x64)
  * [EWFAddressSpace](EWFAddressSpace.md) - This AS supports expert witness (EWF) files
  * [FirewireAddressSpace](FirewireAddressSpace.md) - This AS supports direct memory access over firewire

# Plugins #

  * **Image Identification**
    * [imageinfo](CommandReference21#imageinfo.md) - Identify information for the image
    * [kdbgscan](CommandReference21#kdbgscan.md) - Search for and dump potential KDBG values
    * [kpcrscan](CommandReference21#kpcrscan.md) - Search for and dump potential `_KPCR` values
  * **Process and DLLs**
    * [pslist](CommandReference21#pslist.md) - Print active processes by following the `_EPROCESS` list
    * [pstree](CommandReference21#pstree.md) - Print process list as a tree
    * [psscan](CommandReference21#psscan.md) - Scan Physical memory for `_EPROCESS` pool allocations
    * [psdispscan](CommandReference21#psdispscan.md) - Scan Physical memory for `_EPROCESS` objects based on Dispatch Headers (Windows XP x86 only)
    * [dlllist](CommandReference21#dlllist.md) - Print list of loaded DLLs for each process
    * [dlldump](CommandReference21#dlldump.md) - Dump DLLs from a process address space
    * [handles](CommandReference21#handles.md) - Print list of open handles for each process
    * [getsids](CommandReference21#getsids.md) - Print the SIDs owning each process
    * [verinfo](CommandReference21#verinfo.md) - Print a PE file's version information
    * [enumfunc](CommandReference21#enumfunc.md) - Enumerate a PE file's imports and exports
    * <font color='red'>(new)</font> [envars](CommandReference21#envars.md) - Display process environment variables
    * <font color='red'>(new)</font> [cmdscan](CommandReference21#cmdscan.md) - Extract command history by scanning for `_COMMAND_HISTORY`
    * <font color='red'>(new)</font> [consoles](CommandReference21#consoles.md) - Extract command history by scanning for `_CONSOLE_INFORMATION`
  * **Process Memory**
    * [memmap](CommandReference21#memmap.md) - Print the memory map
    * [memdump](CommandReference21#memdump.md) - Dump the addressable memory for a process
    * [procexedump](CommandReference21#procexedump.md) - Dump a process to an executable file
    * [procmemdump](CommandReference21#procmemdump.md) - Dump a process to an executable memory sample
    * [vadwalk](CommandReference21#vadwalk.md) - Walk the VAD tree
    * [vadtree](CommandReference21#vadtree.md) - Walk the VAD tree and display in tree format
    * [vadinfo](CommandReference21#vadinfo.md) - Dump the VAD info
    * [vaddump](CommandReference21#vaddump.md) - Dumps out the vad sections to a file
  * **Kernel Memory and Objects**
    * [modules](CommandReference21#modules.md) - Print list of loaded modules
    * [modscan](CommandReference21#modscan.md) - Scan Physical memory for `_LDR_DATA_TABLE_ENTRY` objects
    * [moddump](CommandReference21#moddump.md) - Extract a kernel driver to disk
    * [ssdt](CommandReference21#ssdt.md) - Print the Native and GDI System Service Descriptor Tables
    * [driverscan](CommandReference21#driverscan.md) - Scan physical memory for `_DRIVER_OBJECT` objects
    * [filescan](CommandReference21#filescan.md) - Scan physical memory for `_FILE_OBJECT` objects
    * [mutantscan](CommandReference21#mutantscan.md) - Scan physical memory for `_KMUTANT` objects
    * [symlinkscan](CommandReference21#symlinkscan.md) - Scans for symbolic link objects
    * [thrdscan](CommandReference21#thrdscan.md) - Scan physical memory for `_ETHREAD` objects
  * **Networking**
    * [connections](CommandReference21#connections.md) - Print open connections (XP and 2003 only)
    * [connscan](CommandReference21#connscan.md) - Scan Physical memory for `_TCPT_OBJECT` objects (XP and 2003 only)
    * [sockets](CommandReference21#sockets.md) - Print open sockets (XP and 2003 only)
    * [sockscan](CommandReference21#sockscan.md) - Scan Physical memory for `_ADDRESS_OBJECT` (XP and 2003 only)
    * [netscan](CommandReference21#netscan.md) - Scan physical memory for network objects (Vista, 2008, and 7)
  * **Registry**
    * [hivescan](CommandReference21#hivescan.md) - Scan Physical memory for `_CMHIVE` objects
    * [hivelist](CommandReference21#hivelist.md) - Print list of registry hives
    * [printkey](CommandReference21#printkey.md) - Print a registry key, and its subkeys and values
    * [hivedump](CommandReference21#hivedump.md) - Recursively prints all keys and timestamps in a given hive
    * [hashdump](CommandReference21#hashdump.md) - Dumps passwords hashes (LM/NTLM) from memory (x86 only)
    * [lsadump](CommandReference21#lsadump.md) - Dump (decrypted) LSA secrets from the registry (XP and 2003 x86 only)
    * [userassist](CommandReference21#userassist.md) - Parses and output User Assist keys from the registry
    * <font color='red'>(new)</font> [shimcache](CommandReference21#shimcache.md) - Parses the Application Compatibility Shim Cache registry key
  * **File Formats**
    * [crashinfo](CommandReference21#crashinfo.md) - Dump crash-dump information
    * [hibinfo](CommandReference21#hibinfo.md) - Dump hibernation file information
    * [imagecopy](CommandReference21#imagecopy.md) - Copies a physical address space out as a raw DD image
    * <font color='red'>(new)</font> [raw2dmp](CommandReference21#raw2dmp.md) - Converts a physical memory sample to a windbg crash dump
  * **Malware**
    * [malfind](CommandReference21#malfind.md) - Find hidden and injected code
    * [svcscan](CommandReference21#svcscan.md) - Scan for Windows services
    * [ldrmodules](CommandReference21#ldrmodules.md) - Detect unlinked DLLs
    * [impscan](CommandReference21#impscan.md) - Scan for calls to imported functions
    * [apihooks](CommandReference21#apihooks.md) - Detect API hooks in process and kernel memory (x86 only)
    * [idt](CommandReference21#idt.md) - Dumps the Interrupt Descriptor Table (x86 only)
    * [gdt](CommandReference21#gdt.md) - Dumps the Global Descriptor Table (x86 only)
    * [threads](CommandReference21#threads.md) - Investigate `_ETHREAD` and `_KTHREAD`s
    * [callbacks](CommandReference21#callbacks.md) - Print system-wide notification routines (x86 only)
    * [driverirp](CommandReference21#driverirp.md) - Driver IRP hook detection
    * [devicetree](CommandReference21#devicetree.md) - Show device tree
    * [psxview](CommandReference21#psxview.md) - Find hidden processes with various process listings
    * [timers](CommandReference21#timers.md) - Print kernel timers and associated module DPCs (x86 only)
  * **Miscellaneous**
    * [strings](CommandReference21#strings.md) - Match physical offsets to virtual addresses
    * [volshell](CommandReference21#volshell.md) - Shell to interactively explore a memory image
    * [bioskbd](CommandReference21#bioskbd.md) - Reads the keyboard buffer from Real Mode memory
    * [patcher](CommandReference21#patcher.md) - Patches memory based on page scans