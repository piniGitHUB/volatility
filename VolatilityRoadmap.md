

# Introduction #

This page is the official Volatility Roadmap. The goal of the Roadmap is to help set expectations as to when new features will be officially supported. Please keep in mind that on occasion the exact dates or features may change a bit based on resource availability, change in priority, or unforeseen circumstances, so please check back frequently.  Any date referenced as RC1 will also denote an official code freeze for that release, after which no new features will be added to the release and development efforts will primarily focus on testing the release candidate and fixing bugs as necessary.  After the official Release date, new features for the next release will be merged into trunk and thus available to those who track "bleeding edge".

# ~~Volatility 2.1 (Official x64 Support)~~ #

**RC1:** July 8, 2012
**Release:** August 3, 2012

  * New Address Spaces (AMD64PagedMemory, WindowsCrashDumpSpace64)
  * Majority of Existing Plugins Updated with x64 Support
  * Merged Malware Plugins into Volatility Core with Preliminary x64 Support (see FeaturesByPlugin21)
  * WindowsHiberFileSpace32 Overhaul (also includes x64 Support)
  * Now supports the following profiles:
    * Windows XP SP1, SP2 and SP3 x86
    * Windows XP SP1 and SP2 x64 (there is no SP3 x64)
    * Windows Server 2003 SP0, SP1, and SP2 x86
    * Windows Server 2003 SP1 and SP2 x64 (there is no SP0 x64)
    * Windows Vista SP0, SP1, and SP2 x86
    * Windows Vista SP0, SP1, and SP2 x64
    * Windows Server 2008 SP1 and SP2 x86 (there is no SP0)
    * Windows Server 2008 SP1 and SP2 x64 (there is no SP0)
    * Windows Server 2008 `R2` SP0 and SP1 x64
    * Windows 7 SP0 and SP1 x86
    * Windows 7 SP0 and SP1 x64
  * Plugin Additions
    * Printing Process Environment Variables (envvars)
    * Inspecting the Shim Cache (shimcache)
    * Profiling Command History and Console Usage (cmdscan, consoles)
    * Converting x86 and x64 Raw Dumps to MS CrashDump (raw2dmp)
  * Plugin Enhancements
    * Verbose details for kdbgscan and kpcrscan
    * idt/gdt/timers plugins cycle automatically for each CPU
    * apihooks detects LSP/winsock procedure tables
  * New Output Formatting Support (Table Rendering)
  * New Mechanism for Profile Modifications
  * New Registry API Support
  * New Volshell Commands
  * Updated Documentation and Command Reference

# ~~Volatility 2.2 (Official Linux Support)~~ #

**RC1:** Sept 10, 2012
**Release:** Oct 2, 2012

  * Linux Support (Intel x86, x64) kernels 2.6.11 - 3.x
  * Over 25+ Linux plugins
  * Windows win32k suite (14+ plugins, classes, algorithms and APIs for analyzing GUI memory)
  * New or Updated Plugins
    * eventlogs
    * getservicesids

# ~~Volatility 2.3 (Official Mac/Android/ARM Support)~~ #

**RC1:** N/A
**Release:** Oct 2013

  * Mac Support (x86, x64)
  * Android/Arm Support
  * New Address Spaces (VMWareSnapshotFile, VirtualBoxCoreDumpElf64, HpakAddressSpace, MachOAddressSpace)
  * New or Updated Plugins
    * shellbags
    * mbr/vbr parser
    * mftparser
    * dumpfiles
    * iehistory

# Volatility 2.4 (Official Windows 8/Server 2012/Mavericks Support) #

**RC1:** N/A
**Release:** Jan 2014

  * Windows 8 and 8.1/Server 2012 and 2012 [R2](https://code.google.com/p/volatility/source/detail?r=2)
  * Mac 10.9 / Mavericks
  * Pool Scanner Updates
  * VAD plugin design improvements
  * Enhanced PE dumping APIs
  * Truecrypt investigation plugins

# Volatility 3.0 #

**RC1:** 2014
**Release:** 2014

  * A refactor and clean up of the vtype language/profiles/object system
  * Plugin management and the session object
  * Interactive IPython shell
  * Unified Plugin Output Format (+ JSON renderers)
  * Updated Registry Hive and PE File Address Spaces
  * Performance Profiling and Regression Testing Framework
  * Updates to Config System
  * Improved Framework Support (Use as a Library)
  * Application Profiles and WOW64
  * Addition of Windows 8/Server 2012 Support/Testing
  * New or Updated Plugins
    * privileges
    * pktscan
    * cachedump
    * dnscache
    * stack, heaps
  * x64 Updates to Malware Plugins (timers, callbacks, idt/gdt, apihooks)
  * Pool Scanner Updates
  * Unicode improvements
  * KDBG/DTB Improvements
  * Profile Selection Enhancements

# Volatility Future #

  * Update to Python 3.0
  * Updates to PDBParse
  * PyVmiAddressSpace
  * Pagefile.sys
  * support single process dumps
  * Multiprocessing module
  * Performance profiling (C modules for some functions?)