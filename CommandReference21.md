

# Image Identification #

## imageinfo ##

For a high level summary of the memory sample you're analyzing, use the imageinfo command. Most often this command is used to identify the operating system, service pack, and hardware architecture (32 or 64 bit), but it also contains other useful information such as the DTB address and time the sample was collected.

```
$ python vol.py -f ~/Desktop/win7_trial_64bit.raw imageinfo
Volatile Systems Volatility Framework 2.1_alpha
Determining profile based on KDBG search...

          Suggested Profile(s) : Win7SP0x64, Win7SP1x64, Win2008R2SP0x64, Win2008R2SP1x64
                     AS Layer1 : AMD64PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (/Users/Michael/Desktop/win7_trial_64bit.raw)
                      PAE type : PAE
                           DTB : 0x187000L
                          KDBG : 0xf80002803070
          Number of Processors : 1
     Image Type (Service Pack) : 0
                KPCR for CPU 0 : 0xfffff80002804d00L
             KUSER_SHARED_DATA : 0xfffff78000000000L
           Image date and time : 2012-02-22 11:29:02 UTC+0000
     Image local date and time : 2012-02-22 03:29:02 -0800
```

The imageinfo output tells you the suggested profile that you should pass as the parameter to --profile=PROFILE when using other plugins. There may be more than one profile suggestion if profiles are closely related. It also prints the address of the KDBG (short for `_KDDEBUGGER_DATA64`) structure that will be used by plugins like [CommandReference21#pslist](CommandReference21#pslist.md) and [CommandReference21#modlist](CommandReference21#modlist.md) to find the process and module list heads, respectively. In some cases, especially larger memory samples, there may be multiple KDBG structures. Similarly, if there are multiple processors, you'll see the KPCR address and CPU number for each one.

Plugins automatically scan for the KPCR and KDBG values when they need them. However, you can specify the values directly for any plugin by providing --kpcr=ADDRESS or --kdbg=ADDRESS. By supplying the profile and KDBG (or failing that KPCR) to other Volatility commands, you'll get the most accurate and fastest results possible.

## kdbgscan ##

As opposed to [CommandReference21#imageinfo](CommandReference21#imageinfo.md) which simply provides profile suggestions, kdbgscan is designed to positively identify the correct profile and the correct KDBG address (if there happen to be multiple). This plugin scans for the KDBGHeader signatures linked to Volatility profiles and applies sanity checks to reduce false positives. The verbosity of the output and number of sanity checks that can be performed depends on whether Volatility can find a DTB, so if you already know the correct profile (or if you have a profile suggestion from [CommandReference21#imageinfo](CommandReference21#imageinfo.md)), then make sure you use it.

Here's an example scenario of when this plugin can be useful. You have a memory sample that you believe to be Windows 2003 SP2 x64, but [CommandReference21#pslist](CommandReference21#pslist.md) doesn't show any processes. The pslist plugin relies on finding the process list head which is pointed to by KDBG. However, the plugin takes the _first_ KDBG found in the memory sample, which is not always the _best_ one. You may run into this problem if a KDBG with an invalid PsActiveProcessHead pointer is found earlier in a sample (i.e. at a lower physical offset) than the valid KDBG.

Notice below how kdbgscan picks up two KDBG structures: an invalid one (with 0 processes and 0 modules) is found first at 0xf80001172cb0 and a valid one (with 37 processes and 116 modules) is found next at 0xf80001175cf0. In order to "fix" [CommandReference21#pslist](CommandReference21#pslist.md) for this sample, you would simply need to supply the --kdbg=0xf80001175cf0 to the plist plugin.

```
$ python vol.py -f Win2K3SP2x64-6f1bedec.vmem --profile=Win2003SP2x64 kdbgscan
Volatile Systems Volatility Framework 2.1_alpha
**************************************************
Instantiating KDBG using: Kernel AS Win2003SP2x64 (5.2.3791 64bit)
Offset (V)                    : 0xf80001172cb0
Offset (P)                    : 0x1172cb0
KDBG owner tag check          : True
Profile suggestion (KDBGHeader): Win2003SP2x64
Version64                     : 0xf80001172c70 (Major: 15, Minor: 3790)
Service Pack (CmNtCSDVersion) : 0
Build string (NtBuildLab)     : T?
PsActiveProcessHead           : 0xfffff800011947f0 (0 processes)
PsLoadedModuleList            : 0xfffff80001197ac0 (0 modules)
KernelBase                    : 0xfffff80001000000 (Matches MZ: True)
Major (OptionalHeader)        : 5
Minor (OptionalHeader)        : 2

**************************************************
Instantiating KDBG using: Kernel AS Win2003SP2x64 (5.2.3791 64bit)
Offset (V)                    : 0xf80001175cf0
Offset (P)                    : 0x1175cf0
KDBG owner tag check          : True
Profile suggestion (KDBGHeader): Win2003SP2x64
Version64                     : 0xf80001175cb0 (Major: 15, Minor: 3790)
Service Pack (CmNtCSDVersion) : 2
Build string (NtBuildLab)     : 3790.srv03_sp2_rtm.070216-1710
PsActiveProcessHead           : 0xfffff800011977f0 (37 processes)
PsLoadedModuleList            : 0xfffff8000119aae0 (116 modules)
KernelBase                    : 0xfffff80001000000 (Matches MZ: True)
Major (OptionalHeader)        : 5
Minor (OptionalHeader)        : 2
KPCR                          : 0xfffff80001177000 (CPU 0)
```

For more information on how KDBG structures are identified read [Finding Kernel Global Variables in Windows](http://moyix.blogspot.com/2008/04/finding-kernel-global-variables-in.html) and [Identifying Memory Images](http://gleeda.blogspot.com/2010/12/identifying-memory-images.html)

## kprcscan ##

Use this command to scan for potential KPCR structures by checking for the self-referencing members as described by [Finding Object Roots in Vista](http://blog.schatzforensic.com.au/2010/07/finding-object-roots-in-vista-kpcr/). On a multi-core system, each processor has its own KPCR. Therefore, you'll see details for each processor, including IDT and GDT address; current, idle, and next threads; CPU number, vendor & speed; and CR3 value.

```
$ python vol.py -f dang_win7_x64.raw --profile=Win7SP1x64 kpcrscan
Volatile Systems Volatility Framework 2.1_alpha
**************************************************
Offset (V)                    : 0xf800029ead00
Offset (P)                    : 0x29ead00
KdVersionBlock                : 0x0
IDT                           : 0xfffff80000b95080
GDT                           : 0xfffff80000b95000
CurrentThread                 : 0xfffffa800cf694d0 TID 2148 (kd.exe:2964)
IdleThread                    : 0xfffff800029f8c40 TID 0 (Idle:0)
Details                       : CPU 0 (GenuineIntel @ 2128 MHz)
CR3/DTB                       : 0x1dcec000
**************************************************
Offset (V)                    : 0xf880009e7000
Offset (P)                    : 0x4d9e000
KdVersionBlock                : 0x0
IDT                           : 0xfffff880009f2540
GDT                           : 0xfffff880009f24c0
CurrentThread                 : 0xfffffa800cf694d0 TID 2148 (kd.exe:2964)
IdleThread                    : 0xfffff880009f1f40 TID 0 (Idle:0)
Details                       : CPU 1 (GenuineIntel @ 2220 MHz)
CR3/DTB                       : 0x1dcec000
```

If the KdVersionBlock is not null, then it may be possible to find the machine's KDBG address via the KPCR. In fact, the backup method of finding KDBG used by plugins such as [CommandReference21#pslist](CommandReference21#pslist.md) is to leverage kpcrscan and then call the KPCR.get\_kdbg() API function.

# Processes and DLLs #

## pslist ##

To list the processes of a system, use the pslist command. This walks the doubly-linked list pointed to by PsActiveProcessHead and shows the offset, process name, process ID, the parent process ID, number of threads, number of handles, and date/time when the process started and exited. As of 2.1 it also shows the Session ID and if the process is a Wow64 process (it uses a 32 bit address space on a 64 bit kernel).

This plugin does not detect hidden or unlinked processes (but [CommandReference21#psscan](CommandReference21#psscan.md) can do that).

If you see processes with 0 threads, 0 handles, and/or a non-empty exit time, the process may not actually still be active. For more information, see [The Missing Active in PsActiveProcessHead](http://mnin.blogspot.com/2011/03/mis-leading-active-in.html). Below, you'll notice regsvr32.exe has terminated even though its still in the "active" list.

Also note the two processes System and smss.exe will not have a Session ID, because System starts before sessions are established and smss.exe is the session manager itself.

```
$ python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 pslist
Volatile Systems Volatility Framework 2.1_alpha
Offset(V)          Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                Exit                
------------------ -------------------- ------ ------ ------ -------- ------ ------ -------------------- --------------------
0xfffffa80004b09e0 System                    4      0     78      489 ------      0 2012-02-22 19:58:20                      
0xfffffa8000ce97f0 smss.exe                208      4      2       29 ------      0 2012-02-22 19:58:20                      
0xfffffa8000c006c0 csrss.exe               296    288      9      385      0      0 2012-02-22 19:58:24                      
0xfffffa8000c92300 wininit.exe             332    288      3       74      0      0 2012-02-22 19:58:30                      
0xfffffa8000c06b30 csrss.exe               344    324      7      252      1      0 2012-02-22 19:58:30                      
0xfffffa8000c80b30 winlogon.exe            372    324      5      136      1      0 2012-02-22 19:58:31                      
0xfffffa8000c5eb30 services.exe            428    332      6      193      0      0 2012-02-22 19:58:32                      
0xfffffa80011c5700 lsass.exe               444    332      6      557      0      0 2012-02-22 19:58:32                      
0xfffffa8000ea31b0 lsm.exe                 452    332     10      133      0      0 2012-02-22 19:58:32                      
0xfffffa8001296b30 svchost.exe             568    428     10      352      0      0 2012-02-22 19:58:34                      
0xfffffa80012c3620 svchost.exe             628    428      6      247      0      0 2012-02-22 19:58:34                      
0xfffffa8001325950 sppsvc.exe              816    428      5      154      0      0 2012-02-22 19:58:41                      
0xfffffa80007b7960 svchost.exe             856    428     16      404      0      0 2012-02-22 19:58:43                      
0xfffffa80007bb750 svchost.exe             880    428     34     1118      0      0 2012-02-22 19:58:43                      
0xfffffa80007d09e0 svchost.exe             916    428     19      443      0      0 2012-02-22 19:58:43                      
0xfffffa8000c64840 svchost.exe             348    428     14      338      0      0 2012-02-22 20:02:07                      
0xfffffa8000c09630 svchost.exe             504    428     16      496      0      0 2012-02-22 20:02:07                      
0xfffffa8000e86690 spoolsv.exe            1076    428     12      271      0      0 2012-02-22 20:02:10                      
0xfffffa8000518b30 svchost.exe            1104    428     18      307      0      0 2012-02-22 20:02:10                      
0xfffffa800094d960 wlms.exe               1264    428      4       43      0      0 2012-02-22 20:02:11                      
0xfffffa8000995b30 svchost.exe            1736    428     12      200      0      0 2012-02-22 20:02:25                      
0xfffffa8000aa0b30 SearchIndexer.         1800    428     12      757      0      0 2012-02-22 20:02:26                      
0xfffffa8000aea630 taskhost.exe           1144    428      7      189      1      0 2012-02-22 20:02:41                      
0xfffffa8000eafb30 dwm.exe                1476    856      3       71      1      0 2012-02-22 20:02:41                      
0xfffffa80008f3420 explorer.exe           1652    840     21      760      1      0 2012-02-22 20:02:42                      
0xfffffa8000c9a630 regsvr32.exe           1180   1652      0 --------      1      0 2012-02-22 20:03:05  2012-02-22 20:03:08 
0xfffffa8000a03b30 rundll32.exe           2016    568      3       67      1      0 2012-02-22 20:03:16                      
0xfffffa8000a4f630 svchost.exe            1432    428     12      350      0      0 2012-02-22 20:04:14                      
0xfffffa8000999780 iexplore.exe           1892   1652     19      688      1      1 2012-02-22 11:26:12                      
0xfffffa80010c9060 iexplore.exe           2820   1892     23      733      1      1 2012-02-22 11:26:15                      
0xfffffa8001016060 DumpIt.exe             2860   1652      2       42      1      1 2012-02-22 11:28:59                      
0xfffffa8000acab30 conhost.exe            2236    344      2       51      1      0 2012-02-22 11:28:59 
```

By default, pslist shows virtual offsets for the EPROCESS but the physical offset can be obtained with the -P switch:

```
$ python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 pslist -P 
Volatile Systems Volatility Framework 2.1_alpha
Offset(P)          Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                Exit                
------------------ -------------------- ------ ------ ------ -------- ------ ------ -------------------- --------------------
0x0000000017fef9e0 System                    4      0     78      489 ------      0 2012-02-22 19:58:20                      
0x00000000176e97f0 smss.exe                208      4      2       29 ------      0 2012-02-22 19:58:20                      
0x00000000176006c0 csrss.exe               296    288      9      385      0      0 2012-02-22 19:58:24                      
0x0000000017692300 wininit.exe             332    288      3       74      0      0 2012-02-22 19:58:30                      
0x0000000017606b30 csrss.exe               344    324      7      252      1      0 2012-02-22 19:58:30
... 
```

## pstree ##

To view the process listing in tree form, use the pstree command. This enumerates processes using the same technique as pslist, so it will also not show hidden or unlinked processes. Child process are indicated using indention and periods.

```
$ python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 pstree
Volatile Systems Volatility Framework 2.1_alpha
Name                                                  Pid   PPid   Thds   Hnds Time                
-------------------------------------------------- ------ ------ ------ ------ --------------------
 0xfffffa80004b09e0:System                              4      0     78    489 2012-02-22 19:58:20 
. 0xfffffa8000ce97f0:smss.exe                         208      4      2     29 2012-02-22 19:58:20 
 0xfffffa8000c006c0:csrss.exe                         296    288      9    385 2012-02-22 19:58:24 
 0xfffffa8000c92300:wininit.exe                       332    288      3     74 2012-02-22 19:58:30 
. 0xfffffa8000c5eb30:services.exe                     428    332      6    193 2012-02-22 19:58:32 
.. 0xfffffa8000aa0b30:SearchIndexer.                 1800    428     12    757 2012-02-22 20:02:26 
.. 0xfffffa80007d09e0:svchost.exe                     916    428     19    443 2012-02-22 19:58:43 
.. 0xfffffa8000a4f630:svchost.exe                    1432    428     12    350 2012-02-22 20:04:14 
.. 0xfffffa800094d960:wlms.exe                       1264    428      4     43 2012-02-22 20:02:11 
.. 0xfffffa8001325950:sppsvc.exe                      816    428      5    154 2012-02-22 19:58:41 
.. 0xfffffa8000e86690:spoolsv.exe                    1076    428     12    271 2012-02-22 20:02:10 
.. 0xfffffa8001296b30:svchost.exe                     568    428     10    352 2012-02-22 19:58:34 
... 0xfffffa8000a03b30:rundll32.exe                  2016    568      3     67 2012-02-22 20:03:16
...
```

## psscan ##

To enumerate processes using pool tag scanning, use the psscan command. This can find processes that previously terminated (inactive) and processes that have been hidden or unlinked by a rootkit.

```
$ python vol.py --profile=Win7SP0x86 -f win7.dmp psscan
Volatile Systems Volatility Framework 2.0
 Offset     Name             PID    PPID   PDB        Time created             Time exited             
---------- ---------------- ------ ------ ---------- ------------------------ ------------------------ 
0x3e025ba8 svchost.exe        1116    508 0x3ecf1220 2010-06-16 15:25:25                              
0x3e04f070 svchost.exe        1152    508 0x3ecf1340 2010-06-16 15:27:40                              
0x3e144c08 dwm.exe            1540    832 0x3ecf12e0 2010-06-16 15:26:58                              
0x3e145c18 TPAutoConnSvc.     1900    508 0x3ecf1360 2010-06-16 15:25:41                              
0x3e3393f8 lsass.exe           516    392 0x3ecf10e0 2010-06-16 15:25:18                              
0x3e35b8f8 svchost.exe         628    508 0x3ecf1120 2010-06-16 15:25:19                              
0x3e383770 svchost.exe         832    508 0x3ecf11a0 2010-06-16 15:25:20                              
0x3e3949d0 svchost.exe         740    508 0x3ecf1160 2010-06-16 15:25:20                              
0x3e3a5100 svchost.exe         872    508 0x3ecf11c0 2010-06-16 15:25:20                              
0x3e3f64e8 svchost.exe         992    508 0x3ecf1200 2010-06-16 15:25:24                              
0x3e45a530 wininit.exe         392    316 0x3ecf10a0 2010-06-16 15:25:15                              
0x3e45d928 svchost.exe        1304    508 0x3ecf1260 2010-06-16 15:25:28                              
0x3e45f530 csrss.exe           400    384 0x3ecf1040 2010-06-16 15:25:15                              
0x3e4d89c8 vmtoolsd.exe       1436    508 0x3ecf1280 2010-06-16 15:25:30                              
0x3e4db030 spoolsv.exe        1268    508 0x3ecf1240 2010-06-16 15:25:28                              
0x3e50b318 services.exe        508    392 0x3ecf1080 2010-06-16 15:25:18                              
0x3e7f3d40 csrss.exe           352    316 0x3ecf1060 2010-06-16 15:25:12                              
0x3e7f5bc0 winlogon.exe        464    384 0x3ecf10c0 2010-06-16 15:25:18                              
0x3eac6030 SearchProtocol     2448   1168 0x3ecf15c0 2010-06-16 23:30:52      2010-06-16 23:33:14     
0x3eb10030 SearchFilterHo     1812   1168 0x3ecf1480 2010-06-16 23:31:02      2010-06-16 23:33:14 
[snip]
```

If a process has previously terminated, the Time exited field will show the exit time. If you want to investigate a hidden process (such as displaying its DLLs), then you'll need physical offset of the EPROCESS object, which is shown in the far left column.

## psdispscan ##

This plugin is similar to psscan, except it enumerates processes by scanning for DISPATCHER\_HEADER instead of pool tags. This gives you an alternate way to carve EPROCESS objects in the event an attacker tried to hide by altering pool tags. This plugin is not well maintained and only supports XP x86. To use it, you must type --plugins=contrib/plugins on command-line.

## dlllist ##

To display a process's loaded DLLs, use the dlllist command. It walks the doubly-linked list of LDR\_DATA\_TABLE\_ENTRY structures which is pointed to by the PEB's InLoadOrderModuleList. DLLs are automatically added to this list when a process calls LoadLibrary (or some derivative such as LdrLoadDll) and they aren't removed until FreeLibrary is called and the reference count reaches zero.

```
$ python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 dlllist 
************************************************************************
wininit.exe pid:    332
Command line : wininit.exe

Base                             Size Path
------------------ ------------------ ----
0x00000000ff530000            0x23000 C:\Windows\system32\wininit.exe
0x0000000076d40000           0x1ab000 C:\Windows\SYSTEM32\ntdll.dll
0x0000000076b20000           0x11f000 C:\Windows\system32\kernel32.dll
0x000007fefcd50000            0x6b000 C:\Windows\system32\KERNELBASE.dll
0x0000000076c40000            0xfa000 C:\Windows\system32\USER32.dll
0x000007fefd7c0000            0x67000 C:\Windows\system32\GDI32.dll
0x000007fefe190000             0xe000 C:\Windows\system32\LPK.dll
0x000007fefef80000            0xca000 C:\Windows\system32\USP10.dll
0x000007fefd860000            0x9f000 C:\Windows\system32\msvcrt.dll
[snip]
```

To display the DLLs for a specific process instead of all processes, use the -p or --pid filter as shown below. Also, in the following output, notice we're analyzing a Wow64 process. Wow64 processes have a limited list of DLLs in the PEB lists, but that doesn't mean they're the _only_ DLLs loaded in the process address space. Thus Volatility will remind you to use the [CommandReference21#ldrmodules](CommandReference21#ldrmodules.md) instead for these processes.

```
$ python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 dlllist -p 1892
Volatile Systems Volatility Framework 2.1_alpha
************************************************************************
iexplore.exe pid:   1892
Command line : "C:\Program Files (x86)\Internet Explorer\iexplore.exe" 
Note: use ldrmodules for listing DLLs in Wow64 processes

Base                             Size Path
------------------ ------------------ ----
0x0000000000080000            0xa6000 C:\Program Files (x86)\Internet Explorer\iexplore.exe
0x0000000076d40000           0x1ab000 C:\Windows\SYSTEM32\ntdll.dll
0x00000000748d0000            0x3f000 C:\Windows\SYSTEM32\wow64.dll
0x0000000074870000            0x5c000 C:\Windows\SYSTEM32\wow64win.dll
0x0000000074940000             0x8000 C:\Windows\SYSTEM32\wow64cpu.dll
```

To display the DLLs for a process that is hidden or unlinked by a rootkit, first use the psscan to get the physical offset of the EPROCESS object and supply it with --offset=OFFSET. The plugin will "bounce back" and determine the virtual address of the EPROCESS and then acquire an address space in order to access the PEB.

```
$ python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 dlllist --offset=0x04a291a8
```

## dlldump ##

To extract a DLL from a process's memory space and dump it to disk for analysis, use the dlldump command. The syntax is nearly the same as what we've shown for dlllist above. You can:

  * Dump all DLLs from all processes
  * Dump all DLLs from a specific process (with --pid=PID)
  * Dump all DLLs from a hidden/unlinked process (with --offset=OFFSET)
  * Dump a PE from anywhere in process memory (with --base=BASEADDR), this option is useful for extracting hidden DLLs
  * Dump one or more DLLs that match a regular expression (--regex=REGEX), case sensitive or not (--ignore-case)

To specify an output directory, use --dump-dir=DIR or -d DIR.

```
$ python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 dlldump -D dlls/
...
Dumping sechost.dll, Process: lsass.exe, Base: 7fefd830000 output: module.444.173c5700.7fefd830000.dll
Dumping cryptbase.dll, Process: lsass.exe, Base: 7fefcb80000 output: module.444.173c5700.7fefcb80000.dll
Cannot dump lsass.exe@pstorsvc.dll at 7fef71e0000
Dumping USP10.dll, Process: lsass.exe, Base: 7fefef80000 output: module.444.173c5700.7fefef80000.dll
Dumping LPK.dll, Process: lsass.exe, Base: 7fefe190000 output: module.444.173c5700.7fefe190000.dll
Cannot dump lsass.exe@WINSTA.dll at 7fefcc40000
Dumping GDI32.dll, Process: lsass.exe, Base: 7fefd7c0000 output: module.444.173c5700.7fefd7c0000.dll
Dumping DNSAPI.dll, Process: lsass.exe, Base: 7fefc270000 output: module.444.173c5700.7fefc270000.dll
Dumping Secur32.dll, Process: lsass.exe, Base: 7fefc5d0000 output: module.444.173c5700.7fefc5d0000.dll
Dumping SAMSRV.dll, Process: lsass.exe, Base: 7fefc7e0000 output: module.444.173c5700.7fefc7e0000.dll
Dumping KERNELBASE.dll, Process: lsass.exe, Base: 7fefcd50000 output: module.444.173c5700.7fefcd50000.dll
...
```

If the extraction fails, as it did for a few DLLs above, it probably means that some of the memory pages in that DLL were not memory resident (due to paging). In particular, this is a problem if the first page containing the PE header and thus the PE section mappings is not available. In these cases you can still extract the memory segment using the [CommandReference21#vaddump](CommandReference21#vaddump.md) command, but you'll need to manually rebuild the PE header and fixup the sections as described in [Recovering CoreFlood Binaries with Volatility](http://mnin.blogspot.com/2008/11/recovering-coreflood-binaries-with.html).

To dump a PE file that doesn't exist in the DLLs list (for example, due to code injection or malicious unlinking), just specify the base address of the PE in process memory:

```
$ python vol.py --profile=Win7SP0x86 -f win7.dmp dlldump --pid=492 -D out --base=0x00680000
```

You can also specify an EPROCESS offset if the DLL you want is in a hidden process:

```
$ python vol.py --profile=Win7SP0x86 -f win7.dmp dlldump -o 0x3e3f64e8 -D out --base=0x00680000
```

## handles ##

To display the open handles in a process, use the handles command. This applies to files, registry keys, mutexes, named pipes, events, window stations, desktops, threads, and all other types of securable executive objects. This command replaces the older "files" and "regobjkeys" commands from the Volatility 1.3 framework. As of 2.1, the output includes handle value and granted access for each object.

```
$ python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 handles
Volatile Systems Volatility Framework 2.1_alpha
Offset(V)             Pid             Handle             Access Type             Details
------------------ ------ ------------------ ------------------ ---------------- -------
0xfffffa80004b09e0      4                0x4           0x1fffff Process          System(4)
0xfffff8a0000821a0      4               0x10            0x2001f Key              MACHINE\SYSTEM\CONTROLSET001\CONTROL\PRODUCTOPTIONS
0xfffff8a00007e040      4               0x14            0xf003f Key              MACHINE\SYSTEM\CONTROLSET001\CONTROL\SESSION MANAGER\MEMORY MANAGEMENT\PREFETCHPARAMETERS
0xfffff8a000081fa0      4               0x18            0x2001f Key              MACHINE\SYSTEM\SETUP
0xfffffa8000546990      4               0x1c           0x1f0001 ALPC Port        PowerMonitorPort
0xfffffa800054d070      4               0x20           0x1f0001 ALPC Port        PowerPort
0xfffff8a0000676a0      4               0x24            0x20019 Key              MACHINE\HARDWARE\DESCRIPTION\SYSTEM\MULTIFUNCTIONADAPTER
0xfffffa8000625460      4               0x28           0x1fffff Thread           TID 160 PID 4
0xfffff8a00007f400      4               0x2c            0xf003f Key              MACHINE\SYSTEM\CONTROLSET001
0xfffff8a00007f200      4               0x30            0xf003f Key              MACHINE\SYSTEM\CONTROLSET001\ENUM
0xfffff8a000080d10      4               0x34            0xf003f Key              MACHINE\SYSTEM\CONTROLSET001\CONTROL\CLASS
0xfffff8a00007f500      4               0x38            0xf003f Key              MACHINE\SYSTEM\CONTROLSET001\SERVICES
0xfffff8a0001cd990      4               0x3c                0xe Token            
0xfffff8a00007bfa0      4               0x40            0x20019 Key              MACHINE\SYSTEM\CONTROLSET001\CONTROL\WMI\SECURITY
0xfffffa8000cd52b0      4               0x44           0x120116 File             \Device\Mup
0xfffffa8000ce97f0      4               0x48               0x2a Process          smss.exe(208)
0xfffffa8000df16f0      4               0x4c           0x120089 File             \Device\HarddiskVolume2\Windows\System32\en-US\win32k.sys.mui
0xfffffa8000de37f0      4               0x50           0x12019f File             \Device\clfsTxfLog
0xfffff8a000952fa0      4               0x54            0x2001f Key              MACHINE\SYSTEM\CONTROLSET001\CONTROL\VIDEO\{6A8FC9DC-A76B-47FC-A703-17800182E1CE}\0000\VOLATILESETTINGS
0xfffffa800078da20      4               0x58           0x12019f File             \Device\Tcp
0xfffff8a002e17610      4               0x5c                0x9 Key              MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\IMAGE FILE EXECUTION OPTIONS
0xfffff8a0008f7b00      4               0x60               0x10 Key              MACHINE\SYSTEM\CONTROLSET001\CONTROL\LSA
0xfffffa8000da2870      4               0x64           0x100001 File             \Device\KsecDD
0xfffffa8000da3040      4               0x68                0x0 Thread           TID 228 PID 4
...
```

You can display handles for a particular process by specifying --pid=PID or the physical offset of an EPROCESS structure (--physical-offset=OFFSET). You can also filter by object type using -t or --object-type=OBJECTTYPE. For example to only display handles to process objects for pid 600, do the following:

```
$ python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 handles -p 296 -t Process
Volatile Systems Volatility Framework 2.1_alpha
Offset(V)             Pid             Handle             Access Type             Details
------------------ ------ ------------------ ------------------ ---------------- -------
0xfffffa8000c92300    296               0x54           0x1fffff Process          wininit.exe(332)
0xfffffa8000c5eb30    296               0xc4           0x1fffff Process          services.exe(428)
0xfffffa80011c5700    296               0xd4           0x1fffff Process          lsass.exe(444)
0xfffffa8000ea31b0    296               0xe4           0x1fffff Process          lsm.exe(452)
0xfffffa8000c64840    296              0x140           0x1fffff Process          svchost.exe(348)
0xfffffa8001296b30    296              0x150           0x1fffff Process          svchost.exe(568)
0xfffffa80012c3620    296              0x18c           0x1fffff Process          svchost.exe(628)
0xfffffa8001325950    296              0x1dc           0x1fffff Process          sppsvc.exe(816)
...
```

In some cases, the Details column will be blank (for example, if the objects don't have names). By default, you'll see both named and un-named objects. However, if you want to hide the less meaningful results and only show named objects, use the --silent parameter to this plugin.

## getsids ##

To view the SIDs (Security Identifiers) associated with a process, use the getsids command. Among other things, this can help you identify processes which have maliciously escalated privileges.

For more information, see BDG's [Linking Processes To Users](http://moyix.blogspot.com/2008/08/linking-processes-to-users.html).

```
$ python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 getsids
Volatile Systems Volatility Framework 2.1_alpha
System (4): S-1-5-18 (Local System)
System (4): S-1-5-32-544 (Administrators)
System (4): S-1-1-0 (Everyone)
System (4): S-1-5-11 (Authenticated Users)
System (4): S-1-16-16384 (System Mandatory Level)
smss.exe (208): S-1-5-18 (Local System)
smss.exe (208): S-1-5-32-544 (Administrators)
smss.exe (208): S-1-1-0 (Everyone)
smss.exe (208): S-1-5-11 (Authenticated Users)
smss.exe (208): S-1-16-16384 (System Mandatory Level)
[snip]
```

## cmdscan ##

The cmdscan plugin searches the memory of csrss.exe on XP/2003/Vista/2008 and conhost.exe on Windows 7 for commands that attackers entered through a console shell (cmd.exe). This is one of the most powerful commands you can use to gain visibility into an attackers actions on a victim system, whether they opened cmd.exe through an RDP session or proxied input/output to a command shell from a networked backdoor.

This plugin finds structures known as COMMAND\_HISTORY by looking for a known constant value (MaxHistory) and then applying sanity checks. It is important to note that the MaxHistory value can be changed by right clicking in the top left of a cmd.exe window and going to Properties. The value can also be changed for all consoles opened by a given user by modifying the registry key HKCU\Console\HistoryBufferSize. The default is 50 on Windows systems, meaning the most recent 50 commands are saved. You can tweak it if needed by using the --max\_history=NUMBER parameter.

The structures used by this plugin are not public (i.e. Microsoft does not produce PDBs for them), thus they're not available in WinDBG or any other forensic framework. They were reverse engineered by Michael Ligh from the conhost.exe and winsrv.dll binaries.

In addition to the commands entered into a shell, this plugin shows:

  * The name of the console host process (csrss.exe or conhost.exe)
  * The name of the application using the console (whatever process is using cmd.exe)
  * The location of the command history buffers, including the current buffer count, last added command, and last displayed command
  * The application process handle

Due to the scanning technique this plugin uses, it has the capability to find commands from both active and closed consoles.

```
$ python vol.py -f VistaSP2x64.vmem --profile=VistaSP2x64 cmdscan
Volatile Systems Volatility Framework 2.1_alpha

**************************************************
CommandProcess: csrss.exe Pid: 528
CommandHistory: 0x135ec00 Application: cmd.exe Flags: Allocated, Reset
CommandCount: 18 LastAdded: 17 LastDisplayed: 17
FirstCommand: 0 CommandCountMax: 50
ProcessHandle: 0x330
Cmd #0 @ 0x135ef10: cd \
Cmd #1 @ 0x135ef50: cd de
Cmd #2 @ 0x135ef70: cd PerfLogs
Cmd #3 @ 0x135ef90: cd ..
Cmd #4 @ 0x5c78b90: cd "Program Files"
Cmd #5 @ 0x135fae0: cd "Debugging Tools for Windows (x64)"
Cmd #6 @ 0x135efb0: livekd -w
Cmd #7 @ 0x135f010: windbg 
Cmd #8 @ 0x135efd0: cd \
Cmd #9 @ 0x135fd20: rundll32 c:\apphelp.dll,ExportFunc
Cmd #10 @ 0x5c8bdb0: rundll32 c:\windows_apphelp.dll,ExportFunc
Cmd #11 @ 0x5c8be10: rundll32 c:\windows_apphelp.dll
Cmd #12 @ 0x135ee30: rundll32 c:\windows_apphelp.dll,Test
Cmd #13 @ 0x135fd70: cd "Program Files"
Cmd #14 @ 0x5c8b9e0: dir
Cmd #15 @ 0x5c8be60: cd "Debugging Tools for Windows (x64)"
Cmd #16 @ 0x5c8ba00: dir
Cmd #17 @ 0x135eff0: livekd -w

[snip]
```

For background information, see Richard Stevens and Eoghan Casey's [Extracting Windows Cmd Line Details from Physical Memory](http://ww.dfrws.org/2010/proceedings/stevens.pdf).

## consoles ##

Similar to [CommandReference21#cmdscan](CommandReference21#cmdscan.md) the consoles plugin finds commands that attackers typed into cmd.exe or executed via backdoors. However, instead of scanning for COMMAND\_HISTORY, this plugin scans for CONSOLE\_INFORMATION. The major advantage to this plugin is it not only prints the commands attackers typed, but it collects the entire screen buffer (input **and** output). For instance, instead of just seeing "dir", you'll see exactly what the attacker saw, including all files and directories listed by the "dir" command.

Additionally, this plugin prints the following:

  * The original console window title and current console window title
  * The name and pid of attached processes (walks a LIST\_ENTRY to enumerate all of them if more than one)
  * Any aliases associated with the commands executed. For example, attackers can register an alias such that typing "hello" actually executes "cd system"
  * The screen coordinates of the cmd.exe console

Here's an example of the consoles command. For more information and a single file with various example output from public images, see the [cmd\_history.txt attachment to issue #147](http://bit.ly/LYEQOc). Below, you'll notice something quite funny. The forensic investigator seems to have lost his mind and cannot find the dd.exe tool for dumping memory. Nearly 20 typos later, he finds the tool and uses it.

```
$ python vol.py -f xp-laptop-2005-07-04-1430.img consoles
Volatile Systems Volatility Framework 2.1_alpha

[csrss.exe @ 0x821c11a8 pid 456 console @ 0x4e23b0]
  OriginalTitle: '%SystemRoot%\\system32\\cmd.exe'
  Title: 'C:\\WINDOWS\\system32\\cmd.exe - dd if=\\\\.\\PhysicalMemory of=c:\\xp-2005-07-04-1430.img conv=noerror'
  HistoryBufferCount: 2
  HistoryBufferMax: 4
  CommandHistorySize: 50
[history @ 0x4e4008]
  CommandCount: 0
  CommandCountMax: 50
  Application: 'dd.exe'
[history @ 0x4e4d88]
  CommandCount: 20
  CommandCountMax: 50
  Application: 'cmd.exe'
  Cmd #0 @ 0x4e1f90: 'dd'
  Cmd #1 @ 0x4e2cb8: 'cd\\'
  Cmd #2 @ 0x4e2d18: 'dr'
  Cmd #3 @ 0x4e2d28: 'ee:'
  Cmd #4 @ 0x4e2d38: 'e;'
  Cmd #5 @ 0x4e2d48: 'e:'
  Cmd #6 @ 0x4e2d58: 'dr'
  Cmd #7 @ 0x4e2d68: 'd;'
  Cmd #8 @ 0x4e2d78: 'd:'
  Cmd #9 @ 0x4e2d88: 'dr'
  Cmd #10 @ 0x4e2d98: 'ls'
  Cmd #11 @ 0x4e2da8: 'cd Docu'
  Cmd #12 @ 0x4e2dc0: 'cd Documents and'
  Cmd #13 @ 0x4e2e58: 'dr'
  Cmd #14 @ 0x4e2e68: 'd:'
  Cmd #15 @ 0x4e2e78: 'cd dd\\'
  Cmd #16 @ 0x4e2e90: 'cd UnicodeRelease'
  Cmd #17 @ 0x4e2ec0: 'dr'
  Cmd #18 @ 0x4e2ed0: 'dd '
  Cmd #19 @ 0x4e4100: 'dd if=\\\\.\\PhysicalMemory of=c:\\xp-2005-07-04-1430.img conv=noerror'
[screen @ 0x4e2460 X:80 Y:300]
  Output: Microsoft Windows XP [Version 5.1.2600]                                         
  Output: (C) Copyright 1985-2001 Microsoft Corp.                                         
  Output:                                                                                 
  Output: C:\Documents and Settings\Sarah>dd                                              
  Output: 'dd' is not recognized as an internal or external command,                      
  Output: operable program or batch file.                                                 
  Output:                                                                                 
  Output: C:\Documents and Settings\Sarah>cd\                                             
  Output:                                                                                 
  Output: C:\>dr                                                                          
  Output: 'dr' is not recognized as an internal or external command,                      
  Output: operable program or batch file.                                                 
  Output:                                                                                 
  Output: C:\>ee:                                                                         
  Output: 'ee:' is not recognized as an internal or external command,                     
  Output: operable program or batch file.                                                 
  Output:                                                                                 
  Output: C:\>e;                                                                          
  Output: 'e' is not recognized as an internal or external command,                       
  Output: operable program or batch file.                                                 
  Output:                                                                                 
  Output: C:\>e:                                                                          
  Output: The system cannot find the drive specified.                                     
  Output:                                                                                 
  Output: C:\>dr                                                                          
  Output: 'dr' is not recognized as an internal or external command,                      
  Output: operable program or batch file.                                                 
  Output:                                                                                 
  Output: C:\>d;                                                                          
  Output: 'd' is not recognized as an internal or external command,                       
  Output: operable program or batch file.                                                 
  Output:                                                                                 
  Output: C:\>d:                                                                          
  Output:                                                                                 
  Output: D:\>dr                                                                          
  Output: 'dr' is not recognized as an internal or external command,                      
  Output: operable program or batch file.                                                 
  Output:                                                                                 
  Output: D:\>dr                                                                          
  Output: 'dr' is not recognized as an internal or external command,                      
  Output: operable program or batch file.                                                 
  Output:                                                                                 
  Output: D:\>ls                                                                          
  Output: 'ls' is not recognized as an internal or external command,                      
  Output: operable program or batch file.                                                 
  Output:                                                                                 
  Output: D:\>cd Docu                                                                     
  Output: The system cannot find the path specified.                                      
  Output:                                                                                 
  Output: D:\>cd Documents and                                                            
  Output: The system cannot find the path specified.                                      
  Output:                                                                                 
  Output: D:\>dr                                                                          
  Output: 'dr' is not recognized as an internal or external command,                      
  Output: operable program or batch file.                                                 
  Output:                                                                                 
  Output: D:\>d:                                                                          
  Output:                                                                                 
  Output: D:\>cd dd\                                                                      
  Output:                                                                                 
  Output: D:\dd>                                                                          
  Output: D:\dd>cd UnicodeRelease                                                         
  Output:                                                                                 
  Output: D:\dd\UnicodeRelease>dr                                                         
  Output: 'dr' is not recognized as an internal or external command,                      
  Output: operable program or batch file.                                                 
  Output:                                                                                 
  Output: D:\dd\UnicodeRelease>dd                                                         
  Output:                                                                                 
  Output: 0+0 records in                                                                  
  Output: 0+0 records out                                                                 
  Output: ^C                                                                              
  Output: D:\dd\UnicodeRelease>dd if=\\.\PhysicalMemory of=c:\xp-2005-07-04-1430.img conv=
  Output: noerror                                                                         
  Output: Forensic Acquisition Utilities, 1, 0, 0, 1035                                   
  Output: dd, 3, 16, 2, 1035                                                              
  Output: Copyright (C) 2002-2004 George M. Garner Jr.                                    
  Output:                                                                                 
  Output: Command Line: dd if=\\.\PhysicalMemory of=c:\xp-2005-07-04-1430.img conv=noerror
  Output:                                                                                 
  Output: Based on original version developed by Paul Rubin, David MacKenzie, and Stuart K
  Output: emp                                                                             
  Output: Microsoft Windows: Version 5.1 (Build 2600.Professional Service Pack 2)         
  Output:                                                                                 
  Output: 04/07/2005  18:30:32 (UTC)                                                      
  Output: 04/07/2005  14:30:32 (local time)                                               
  Output:                                                                                 
  Output: Current User: SPLATITUDE\Sarah                                                  
  Output:                                                                                 
  Output: Total physical memory reported: 523676 KB                                       
  Output: Copying physical memory...                                                      
  Output: Physical memory in the range 0x00004000-0x00004000 could not be read.                              
```

## envars ##

To display a process's environment variables, use the envars plugin. Typically this will show the number of CPUs installed and the hardware architecture (though the [CommandReference21#kdbgscan](CommandReference21#kdbgscan.md) output is a much more reliable source), the process's current directory, temporary directory, session name, computer name, user name, and various other interesting artifacts.

```
$ /usr/bin/python2.6 vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 envars
Volatile Systems Volatility Framework 2.1_alpha
Pid      Process              Block              Variable                       Value
-------- -------------------- ------------------ ------------------------------ -----
     296 csrss.exe            0x00000000003d1320 ComSpec                        C:\Windows\system32\cmd.exe
     296 csrss.exe            0x00000000003d1320 FP_NO_HOST_CHECK               NO
     296 csrss.exe            0x00000000003d1320 NUMBER_OF_PROCESSORS           1
     296 csrss.exe            0x00000000003d1320 OS                             Windows_NT
     296 csrss.exe            0x00000000003d1320 Path                           C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\
     296 csrss.exe            0x00000000003d1320 PATHEXT                        .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC
     296 csrss.exe            0x00000000003d1320 PROCESSOR_ARCHITECTURE         AMD64
     296 csrss.exe            0x00000000003d1320 PROCESSOR_IDENTIFIER           Intel64 Family 6 Model 2 Stepping 3, GenuineIntel
     296 csrss.exe            0x00000000003d1320 PROCESSOR_LEVEL                6
     296 csrss.exe            0x00000000003d1320 PROCESSOR_REVISION             0203
     296 csrss.exe            0x00000000003d1320 PSModulePath                   C:\Windows\system32\WindowsPowerShell\v1.0\Modules\
     296 csrss.exe            0x00000000003d1320 SystemDrive                    C:
     296 csrss.exe            0x00000000003d1320 SystemRoot                     C:\Windows
     296 csrss.exe            0x00000000003d1320 TEMP                           C:\Windows\TEMP
     296 csrss.exe            0x00000000003d1320 TMP                            C:\Windows\TEMP
     296 csrss.exe            0x00000000003d1320 USERNAME                       SYSTEM
     296 csrss.exe            0x00000000003d1320 windir                         C:\Windows
```

## verinfo ##

To display the version information embedded in PE files, use the verinfo command. Not all PE files have version information, and many malware authors forge it to include false data, but nonetheless this command can be very helpful with identifying binaries and for making correlations with other files.

Note that this plugin resides in the contrib directory, therefore you'll need to tell Volatility to look there using the --plugins option. It currently only supports printing version information from process executables and DLLs, but later will be expanded to include kernel modules. If you want to filter by module name, use the --regex=REGEX and/or --ignore-case options.

```
$ python vol.py --plugins=contrib/plugins/ -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 verinfo
Volatile Systems Volatility Framework 2.1_alpha
\SystemRoot\System32\smss.exe
C:\Windows\SYSTEM32\ntdll.dll

C:\Windows\system32\csrss.exe
  File version    : 6.1.7600.16385
  Product version : 6.1.7600.16385
  Flags           : 
  OS              : Windows NT
  File Type       : Application
  File Date       : 
  CompanyName : Microsoft Corporation
  FileDescription : Client Server Runtime Process
  FileVersion : 6.1.7600.16385 (win7_rtm.090713-1255)
  InternalName : CSRSS.Exe
  LegalCopyright : \xa9 Microsoft Corporation. All rights reserved.
  OriginalFilename : CSRSS.Exe
  ProductName : Microsoft\xae Windows\xae Operating System
  ProductVersion : 6.1.7600.16385

[snip]
```

## enumfunc ##

This plugin enumerates imported and exported functions from processes, dlls, and kernel drivers. Specifically, it handles functions imported by name or ordinal, functions exported by name or ordinal, and forwarded exports. The output will be very verbose in most cases (functions exported by ntdll, msvcrt, and kernel32 can reach 1000+ alone). So you can either reduce the verbosity by filtering criteria with the command-line options (shown below) or you can use look at the code in enumfunc.py and use it as an example of how to use the IAT and EAT parsing API functions in your own plugin. For example, the [CommandReference21#apihooks](CommandReference21#apihooks.md) plugin leverages the imports and exports APIs to find functions in memory when checking for hooks.

Also note this plugin is in the contrib directory, so you can pass that to --plugins like this:

```
$ python vol.py --plugins=contrib/plugins/ -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 enumfunc -h
....
  -s, --scan            Scan for objects
  -P, --process-only    Process only
  -K, --kernel-only     Kernel only
  -I, --import-only     Imports only
  -E, --export-only     Exports only
```

To use pool scanners for finding processes and kernel drivers instead of walking linked lists, use the -s option. This can be useful if you're trying to enumerate functions in hidden processes or drivers. An example of the remaining command-line options is shown below.

To show exported functions in process memory, use -P and -E like this:

```
$ python vol.py --plugins=contrib/plugins/ -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 enumfunc -P -E
Process              Type       Module               Ordinal    Address              Name
lsass.exe            Export     ADVAPI32.dll         1133       0x000007fefd11dd34 CreateWellKnownSid
lsass.exe            Export     ADVAPI32.dll         1134       0x000007fefd17a460 CredBackupCredentials
lsass.exe            Export     ADVAPI32.dll         1135       0x000007fefd170590 CredDeleteA
lsass.exe            Export     ADVAPI32.dll         1136       0x000007fefd1704d0 CredDeleteW
lsass.exe            Export     ADVAPI32.dll         1137       0x000007fefd17a310 CredEncryptAndMarshalBinaryBlob
lsass.exe            Export     ADVAPI32.dll         1138       0x000007fefd17d080 CredEnumerateA
lsass.exe            Export     ADVAPI32.dll         1139       0x000007fefd17cf50 CredEnumerateW
lsass.exe            Export     ADVAPI32.dll         1140       0x000007fefd17ca00 CredFindBestCredentialA
lsass.exe            Export     ADVAPI32.dll         1141       0x000007fefd17c8f0 CredFindBestCredentialW
lsass.exe            Export     ADVAPI32.dll         1142       0x000007fefd130c10 CredFree
lsass.exe            Export     ADVAPI32.dll         1143       0x000007fefd1630f0 CredGetSessionTypes
lsass.exe            Export     ADVAPI32.dll         1144       0x000007fefd1703d0 CredGetTargetInfoA
[snip]
```

To show imported functions in kernel memory, use -K and -I like this:

```
$ python vol.py --plugins=contrib/plugins/ -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 enumfunc -K -I
Volatile Systems Volatility Framework 2.1_alpha
Process              Type       Module               Ordinal    Address              Name
<KERNEL>             Import     VIDEOPRT.SYS         583        0xfffff80002acc320 ntoskrnl.exe!IoRegisterPlugPlayNotification
<KERNEL>             Import     VIDEOPRT.SYS         1325       0xfffff800029f9f30 ntoskrnl.exe!RtlAppendStringToString
<KERNEL>             Import     VIDEOPRT.SYS         509        0xfffff800026d06e0 ntoskrnl.exe!IoGetAttachedDevice
<KERNEL>             Import     VIDEOPRT.SYS         443        0xfffff800028f7ec0 ntoskrnl.exe!IoBuildSynchronousFsdRequest
<KERNEL>             Import     VIDEOPRT.SYS         1466       0xfffff80002699300 ntoskrnl.exe!RtlInitUnicodeString
<KERNEL>             Import     VIDEOPRT.SYS         759        0xfffff80002697be0 ntoskrnl.exe!KeInitializeEvent
<KERNEL>             Import     VIDEOPRT.SYS         1461       0xfffff8000265e8a0 ntoskrnl.exe!RtlInitAnsiString
<KERNEL>             Import     VIDEOPRT.SYS         1966       0xfffff80002685060 ntoskrnl.exe!ZwSetValueKey
<KERNEL>             Import     VIDEOPRT.SYS         840        0xfffff80002699440 ntoskrnl.exe!KeReleaseSpinLock
<KERNEL>             Import     VIDEOPRT.SYS         1190       0xfffff800027a98b0 ntoskrnl.exe!PoRequestPowerIrp
<KERNEL>             Import     VIDEOPRT.SYS         158        0xfffff800026840f0 ntoskrnl.exe!ExInterlockedInsertTailList
<KERNEL>             Import     VIDEOPRT.SYS         1810       0xfffff80002684640 ntoskrnl.exe!ZwClose
[snip]
```

# Process Memory #

## memmap ##

The memmap command shows you exactly which pages are memory resident, given a specific process DTB (or kernel DTB if you use this plugin on the Idle or System process). It shows you the virtual address of the page, the corresponding physical offset of the page, and the size of the page. The map information generated by this plugin comes from the underlying address space's get\_available\_addresses method.

As of 2.1, the new column DumpFileOffset helps you correlate the output of memmap with the dump file produced by the [CommandReference21#memdump](CommandReference21#memdump.md) plugin. For example, according to the output below, the page at virtual address 0x0000000000058000 in the System process's memory can be found at offset 0x00000000162ed000 of the win7\_trial\_64bit.raw file. After using [CommandReference21#memdump](CommandReference21#memdump.md) to extract the addressable memory of the System process to an individual file, you can find this page at offset 0x8000.

```
$ python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 memmap -p 4 
Volatile Systems Volatility Framework 2.1_alpha
System pid:      4
Virtual            Physical                         Size     DumpFileOffset
------------------ ------------------ ------------------ ------------------
0x0000000000050000 0x0000000000cbc000             0x1000                0x0
0x0000000000051000 0x0000000015ec6000             0x1000             0x1000
0x0000000000052000 0x000000000f5e7000             0x1000             0x2000
0x0000000000053000 0x0000000005e28000             0x1000             0x3000
0x0000000000054000 0x0000000008b29000             0x1000             0x4000
0x0000000000055000 0x00000000155b8000             0x1000             0x5000
0x0000000000056000 0x000000000926e000             0x1000             0x6000
0x0000000000057000 0x0000000002dac000             0x1000             0x7000
0x0000000000058000 0x00000000162ed000             0x1000             0x8000
[snip]
```

## memdump ##

To extract all memory resident pages in a process (see [CommandReference21#memmap](CommandReference21#memmap.md) for details) into an individual file, use the memdump command. Supply the output directory with -D or --dump-dir=DIR.

```
$ python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 memdump -p 4 -D dump/
Volatile Systems Volatility Framework 2.1_alpha
************************************************************************
Writing System [     4] to 4.dmp

$ ls -alh dump/4.dmp 
-rw-r--r--  1 Michael  staff   111M Jun 24 15:47 dump/4.dmp
```

To conclude the demonstration we began in the [CommandReference21#memmap](CommandReference21#memmap.md) discussion, we should now be able to make an assertion regarding the relationship of the mapped and extracted pages:

```
$ python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 volshell
Volatile Systems Volatility Framework 2.1_alpha
Current context: process System, pid=4, ppid=0 DTB=0x187000
Welcome to volshell! Current memory image is:
file:///Users/Michael/Desktop/win7_trial_64bit.raw
To get help, type 'hh()'

>>> PAGE_SIZE = 0x1000

>>> assert self.addrspace.read(0x0000000000058000, PAGE_SIZE) == \
...        self.addrspace.base.read(0x00000000162ed000, PAGE_SIZE) == \
...        open("dump/4.dmp", "rb").read()[0x8000:0x8000 + PAGE_SIZE]
>>> 
```

## procmemdump ##

To dump a process's executable (including the slack space), use the procmemdump command. Optionally, pass the --unsafe or -u flags to bypass certain sanity checks used when parsing the PE header. Some malware will intentionally forge size fields in the PE header so that memory dumping tools fail.

For more information, see Andreas Schuster's 4-part series on [Reconstructing a Binary](http://computer.forensikblog.de/en/2006/04/reconstructing_a_binary.html#more). Also see [impscan](http://code.google.com/p/volatility/wiki/CommandReference#impscan) for help rebuilding a binary's import address table.

```
$ python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 procmemdump -D dump/ -p 296
Volatile Systems Volatility Framework 2.1_alpha
************************************************************************
Dumping csrss.exe, pid:    296 output: executable.296.exe

$ file dump/executable.296.exe 
dump/executable.296.exe: PE32+ executable for MS Windows (native) Mono/.Net assembly
```

## procexedump ##

To dump a process's executable (**not** including the slack space), use the procexedump command. The syntax is identical to procmemdump.

## vadinfo ##

The vadinfo command displays extended information about a process's VAD nodes. In particular, it shows:

  * The address of the MMVAD structure in kernel memory
  * The starting and ending virtual addresses in process memory that the MMVAD structure pertains to
  * The VAD Tag
  * The VAD flags, control flags, etc
  * The name of the memory mapped file (if one exists)
  * The memory protection constant (permissions). Note there is a difference between the original protection and current protection. The original protection is derived from the flProtect parameter to VirtualAlloc. For example you can reserve memory (MEM\_RESERVE) with protection PAGE\_NOACCESS (original protection). Later, you can call VirtualAlloc again to commit (MEM\_COMMIT) and specify PAGE\_READWRITE (becomes current protection). The vadinfo command shows the original protection only. Thus, just because you see PAGE\_NOACCESS here, it doesn't mean code in the region cannot be read, written, or executed.

```
$ python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 vadinfo -p 296
Volatile Systems Volatility Framework 2.1_alpha
************************************************************************
Pid:    296
VAD node @ 0xfffffa8000c00620 Start 0x000000007f0e0000 End 0x000000007ffdffff Tag VadS
Flags: PrivateMemory: 1, Protection: 1
Protection: PAGE_READONLY
Vad Type: VadNone

[snip]

VAD node @ 0xfffffa8000c04ce0 Start 0x000007fefcd00000 End 0x000007fefcd10fff Tag Vad 
Flags: CommitCharge: 2, Protection: 7, VadType: 2
Protection: PAGE_EXECUTE_WRITECOPY
Vad Type: VadImageMap
ControlArea @fffffa8000c04d70 Segment fffff8a000c45c10
Dereference list: Flink 00000000, Blink 00000000
NumberOfSectionReferences:          0 NumberOfPfnReferences:          13
NumberOfMappedViews:                2 NumberOfUserReferences:          2
WaitingForDeletion Event:  00000000
Control Flags: Accessed: 1, File: 1, Image: 1
FileObject @fffffa8000c074d0, Name: \Windows\System32\basesrv.dll
First prototype PTE: fffff8a000c45c58 Last contiguous PTE: fffffffffffffffc
Flags2: Inherit: 1

[snip]
```

For more information on the VAD, see BDG's [The VAD Tree: A Process-Eye View of Physical Memory](http://www.dfrws.org/2007/proceedings/p62-dolan-gavitt.pdf).

## vadwalk ##

To inspect a process's VAD nodes in table form, use the vadwalk command.

```
$ python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 vadwalk -p 296
Volatile Systems Volatility Framework 2.1_alpha
************************************************************************
Pid:    296
Address            Parent             Left               Right              Start              End                Tag 
------------------ ------------------ ------------------ ------------------ ------------------ ------------------ ----
0xfffffa8000c00620 0x0000000000000000 0xfffffa8000deaa40 0xfffffa8000c043d0 0x000000007f0e0000 0x000000007ffdffff VadS
0xfffffa8000deaa40 0xfffffa8000c00620 0xfffffa8000bc4660 0xfffffa80011b8d80 0x0000000000ae0000 0x0000000000b1ffff VadS
0xfffffa8000bc4660 0xfffffa8000deaa40 0xfffffa8000c04260 0xfffffa8000c91010 0x00000000004d0000 0x0000000000650fff Vadm
0xfffffa8000c04260 0xfffffa8000bc4660 0xfffffa8000c82010 0xfffffa80012acce0 0x00000000002a0000 0x000000000039ffff VadS
0xfffffa8000c82010 0xfffffa8000c04260 0xfffffa8000cbce80 0xfffffa8000c00330 0x00000000001f0000 0x00000000001f0fff Vadm
0xfffffa8000cbce80 0xfffffa8000c82010 0xfffffa8000bc4790 0xfffffa8000d9bb80 0x0000000000180000 0x0000000000181fff Vad 
0xfffffa8000bc4790 0xfffffa8000cbce80 0xfffffa8000c00380 0xfffffa8000e673a0 0x0000000000100000 0x0000000000166fff Vad 
0xfffffa8000c00380 0xfffffa8000bc4790 0x0000000000000000 0x0000000000000000 0x0000000000000000 0x00000000000fffff VadS
[snip]
```

## vadtree ##

To display the VAD nodes in a visual tree form, use the vadtree command.

```
$ python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 vadtree -p 296
Volatile Systems Volatility Framework 2.1_alpha
************************************************************************
Pid:    296
 0x000000007f0e0000 - 0x000000007ffdffff
  0x0000000000ae0000 - 0x0000000000b1ffff
   0x00000000004d0000 - 0x0000000000650fff
    0x00000000002a0000 - 0x000000000039ffff
     0x00000000001f0000 - 0x00000000001f0fff
      0x0000000000180000 - 0x0000000000181fff
       0x0000000000100000 - 0x0000000000166fff
        0x0000000000000000 - 0x00000000000fffff
        0x0000000000170000 - 0x0000000000170fff
       0x00000000001a0000 - 0x00000000001a1fff
        0x0000000000190000 - 0x0000000000190fff
        0x00000000001b0000 - 0x00000000001effff
      0x0000000000240000 - 0x000000000024ffff
       0x0000000000210000 - 0x0000000000216fff
        0x0000000000200000 - 0x000000000020ffff
[snip]
```

If you want to view the balanced binary tree in Graphviz format, just add --output=dot --output-file=graph.dot to your command. Then you can open graph.dot in any Graphviz-compatible viewer.

## vaddump ##

To extract the range of pages described by a VAD node, use the vaddump command. This is similar to [CommandReference21#memdump](CommandReference21#memdump.md), except the pages belonging to each VAD node are placed in separate files (named according to the starting and ending addresses) instead of one large conglomerate file. If any pages in the range are not memory resident, they're padded with 0's using the address space's zread() method.

```
$ python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 vaddump -D vads
Volatile Systems Volatility Framework 2.1_alpha
Pid:      4
************************************************************************
Pid:    208
************************************************************************
Pid:    296
************************************************************************
Pid:    332
************************************************************************
Pid:    344
************************************************************************
[snip]

$ ls -alh vads
total 229536
drwxr-xr-x  107 Michael  staff   3.6K Jun 24 16:15 .
drwxr-xr-x   25 Michael  staff   850B Jun 24 16:14 ..
-rw-r--r--    1 Michael  staff   140K Jun 24 16:15 System.17fef9e0.00010000-00032fff.dmp
-rw-r--r--    1 Michael  staff   4.0K Jun 24 16:15 System.17fef9e0.00040000-00040fff.dmp
-rw-r--r--    1 Michael  staff   1.7M Jun 24 16:15 System.17fef9e0.76d40000-76eeafff.dmp
-rw-r--r--    1 Michael  staff   1.5M Jun 24 16:15 System.17fef9e0.76f20000-7709ffff.dmp
-rw-r--r--    1 Michael  staff    64K Jun 24 16:15 System.17fef9e0.7ffe0000-7ffeffff.dmp
-rw-r--r--    1 Michael  staff   1.0M Jun 24 16:15 csrss.exe.176006c0.00000000-000fffff.dmp
-rw-r--r--    1 Michael  staff   412K Jun 24 16:15 csrss.exe.176006c0.00100000-00166fff.dmp
-rw-r--r--    1 Michael  staff   4.0K Jun 24 16:15 csrss.exe.176006c0.00170000-00170fff.dmp
-rw-r--r--    1 Michael  staff   8.0K Jun 24 16:15 csrss.exe.176006c0.00180000-00181fff.dmp
-rw-r--r--    1 Michael  staff   4.0K Jun 24 16:15 csrss.exe.176006c0.00190000-00190fff.dmp
[snip]
```

The files are named like this:

ProcessName.PhysicalOffset.StartingVPN.EndingVPN.dmp

The reason the PhysicalOffset field exists is so you can distinguish between two processes with the same name.

# Kernel Memory and Objects #

## modules ##

To view the list of kernel drivers loaded on the system, use the modules command. This walks the doubly-linked list of LDR\_DATA\_TABLE\_ENTRY structures pointed to by PsLoadedModuleList. Similar to the [CommandReference21#pslist](CommandReference21#pslist.md) command, this relies on finding the KDBG structure. In rare cases, you may need to use [CommandReference21#kdbgscan](CommandReference21#kdbgscan.md) to find the most appropriate KDBG structure address and then supply it to this plugin like --kdbg=ADDRESS.

It cannot find hidden/unlinked kernel drivers, however [CommandReference21#modscan](CommandReference21#modscan.md) serves that purpose. Also, since this plugin uses list walking techniques, you typically can assume that the order the modules are displayed in the output is the order they were loaded on the system. For example, below, ntoskrnl.exe was first to load, followed by hal.dll, etc.

```
$ python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 modules
Volatile Systems Volatility Framework 2.1_alpha
Offset(V)          Name                 Base                             Size File
------------------ -------------------- ------------------ ------------------ ----
0xfffffa80004a11a0 ntoskrnl.exe         0xfffff8000261a000           0x5dd000 \SystemRoot\system32\ntoskrnl.exe
0xfffffa80004a10b0 hal.dll              0xfffff80002bf7000            0x49000 \SystemRoot\system32\hal.dll
0xfffffa80004a7950 kdcom.dll            0xfffff80000bb4000             0xa000 \SystemRoot\system32\kdcom.dll
0xfffffa80004a7860 mcupdate.dll         0xfffff88000c3a000            0x44000 \SystemRoot\system32\mcupdate_GenuineIntel.dll
0xfffffa80004a7780 PSHED.dll            0xfffff88000c7e000            0x14000 \SystemRoot\system32\PSHED.dll
0xfffffa80004a7690 CLFS.SYS             0xfffff88000c92000            0x5e000 \SystemRoot\system32\CLFS.SYS
0xfffffa80004a8010 CI.dll               0xfffff88000cf0000            0xc0000 \SystemRoot\system32\CI.dll
[snip] 
```

The output shows the offset of the LDR\_DATA\_TABLE\_ENTRY structure, which is a virtual address by default but can be specified as a physical address with the -P switch as shown below. In either case, the Base column is the virtual address of the module's base in kernel memory (where you'd expect to find the PE header).

```
$ python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 modules -P
Volatile Systems Volatility Framework 2.1_alpha
Offset(P)          Name                 Base                             Size File
------------------ -------------------- ------------------ ------------------ ----
0x0000000017fe01a0 ntoskrnl.exe         0xfffff8000261a000           0x5dd000 \SystemRoot\system32\ntoskrnl.exe
0x0000000017fe00b0 hal.dll              0xfffff80002bf7000            0x49000 \SystemRoot\system32\hal.dll
0x0000000017fe6950 kdcom.dll            0xfffff80000bb4000             0xa000 \SystemRoot\system32\kdcom.dll
0x0000000017fe6860 mcupdate.dll         0xfffff88000c3a000            0x44000 \SystemRoot\system32\mcupdate_GenuineIntel.dll
0x0000000017fe6780 PSHED.dll            0xfffff88000c7e000            0x14000 \SystemRoot\system32\PSHED.dll
0x0000000017fe6690 CLFS.SYS             0xfffff88000c92000            0x5e000 \SystemRoot\system32\CLFS.SYS
0x0000000017fe7010 CI.dll               0xfffff88000cf0000            0xc0000 \SystemRoot\system32\CI.dll
[snip]
```

## modscan ##

The modscan command finds LDR\_DATA\_TABLE\_ENTRY structures by scanning physical memory for pool tags. This can pick up previously unloaded drivers and drivers that have been hidden/unlinked by rootkits. Unlike [CommandReference21#modlist](CommandReference21#modlist.md) the order of results has no relationship with the order in which the drivers loaded. As you can see below, DumpIt.sys was found at the lowest physical offset, but it was probably one of the last drivers to load (since it was used to acquire memory).

```
$ python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 modscan
Volatile Systems Volatility Framework 2.1_alpha
Offset(P)          Name                 Base                             Size File
------------------ -------------------- ------------------ ------------------ ----
0x00000000173b90b0 DumpIt.sys           0xfffff88003980000            0x11000 \??\C:\Windows\SysWOW64\Drivers\DumpIt.sys
0x000000001745b180 mouhid.sys           0xfffff880037e9000             0xd000 \SystemRoot\system32\DRIVERS\mouhid.sys
0x0000000017473010 lltdio.sys           0xfffff88002585000            0x15000 \SystemRoot\system32\DRIVERS\lltdio.sys
0x000000001747f010 rspndr.sys           0xfffff8800259a000            0x18000 \SystemRoot\system32\DRIVERS\rspndr.sys
0x00000000174cac40 dxg.sys              0xfffff96000440000            0x1e000 \SystemRoot\System32\drivers\dxg.sys
0x0000000017600190 monitor.sys          0xfffff8800360c000             0xe000 \SystemRoot\system32\DRIVERS\monitor.sys
0x0000000017601170 HIDPARSE.SYS         0xfffff880037de000             0x9000 \SystemRoot\system32\DRIVERS\HIDPARSE.SYS
0x0000000017604180 USBD.SYS             0xfffff880037e7000             0x2000 \SystemRoot\system32\DRIVERS\USBD.SYS
0x0000000017611d70 cdrom.sys            0xfffff88001944000            0x2a000 \SystemRoot\system32\DRIVERS\cdrom.sys
[snip]
```

## moddump ##

To extract a kernel driver to a file, use the moddump command. Supply the output directory with -D or --dump-dir=DIR. Without any additional parameters, all drivers identified by [CommandReference#21modlist](CommandReference#21modlist.md) will be dumped. If you want a specific driver, supply a regular expression of the driver's name with --regex=REGEX or the module's base address with --base=BASE.

For more information, see BDG's [Plugin Post: Moddump](http://moyix.blogspot.com/2008/10/plugin-post-moddump.html).

```
$ python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 moddump -D drivers/
Volatile Systems Volatility Framework 2.1_alpha
Dumping ntoskrnl.exe, Base: fffff8000261a000 output: driver.fffff8000261a000.sys
Dumping hal.dll, Base: fffff80002bf7000 output: driver.fffff80002bf7000.sys
Dumping intelide.sys, Base: fffff88000e5c000 output: driver.fffff88000e5c000.sys
Dumping mouclass.sys, Base: fffff8800349b000 output: driver.fffff8800349b000.sys
Dumping msisadrv.sys, Base: fffff88000f7c000 output: driver.fffff88000f7c000.sys
Dumping ndistapi.sys, Base: fffff880035c3000 output: driver.fffff880035c3000.sys
Dumping pacer.sys, Base: fffff88002c5d000 output: driver.fffff88002c5d000.sys
Dumping WDFLDR.SYS, Base: fffff88000f0d000 output: driver.fffff88000f0d000.sys
Dumping usbhub.sys, Base: fffff880036be000 output: driver.fffff880036be000.sys
Dumping hwpolicy.sys, Base: fffff8800149f000 output: driver.fffff8800149f000.sys
Dumping kbdclass.sys, Base: fffff8800348c000 output: driver.fffff8800348c000.sys
Dumping amdxata.sys, Base: fffff88000c00000 output: driver.fffff88000c00000.sys
Dumping crashdmp.sys, Base: fffff88003781000 output: driver.fffff88003781000.sys
Dumping swenum.sys, Base: fffff88003461000 output: driver.fffff88003461000.sys
Cannot dump TSDDD.dll at fffff96000670000
Cannot dump framebuf.dll at fffff960008a0000
[snip]
```

Similar to [CommandReference21#dlldump](CommandReference21#dlldump.md), if critical parts of the PE header are not memory resident, then rebuilding/extracting the driver may fail. Additionally, for drivers that are mapped in different sessions (like win32k.sys), there is currently no way to specify which session to use when acquiring the driver sample. This will be an enhancement added in the Volatility 2.2 release.

## ssdt ##

To list the functions in the Native and GUI SSDTs, use the ssdt command. This displays the index, function name, and owning driver for each entry in the SSDT. Please note the following:

  * Windows has 4 SSDTs by default (you can add more with KeAddSystemServiceTable), but only 2 of them are used - one for Native functions in the NT module, and one for GUI functions in the win32k.sys module.

  * There are multiple ways to locate the SSDTs in memory. Most tools do it by finding the exported KeServiceDescriptorTable symbol in the NT module, but this is not the way Volatility works.

  * For x86 systems, Volatility scans for ETHREAD objects (see the [CommandReference#thrdscan](CommandReference#thrdscan.md) command) and gathers all unique ETHREAD.Tcb.ServiceTable pointers. This method is more robust and complete, because it can detect when rootkits make copies of the existing SSDTs and assign them to particular threads. Also see the [CommandReference#thread](CommandReference#thread.md) command.

  * For x64 systems (which do not have an ETHREAD.Tcb.ServiceTable member) Volatility disassembles code in nt!KeAddSystemServiceTable and finds its references to the KeServiceDescriptorTable and KeServiceDescriptorTableShadow symbols.

  * The order and total number of functions in the SSDTs differ across operating system versions. Thus, Volatility stores the information in a per-profile (OS) dictionary which is auto-generated and cross-referenced using the ntoskrnl.exe, ntdll.dll, win32k.sys, user32.dll and gdi32.dll modules from the respective systems.

  * For more information, see BDG's [Auditing the System Call Table](http://moyix.blogspot.com/2008/08/auditing-system-call-table.html).

```
$ python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 ssdt
Volatile Systems Volatility Framework 2.1_alpha
[x64] Gathering all referenced SSDTs from KeAddSystemServiceTable...
Finding appropriate address space for tables...
SSDT[0] at fffff8000268cb00 with 401 entries
  Entry 0x0000: 0xfffff80002a9d190 (NtMapUserPhysicalPagesScatter) owned by ntoskrnl.exe
  Entry 0x0001: 0xfffff80002983a00 (NtWaitForSingleObject) owned by ntoskrnl.exe
  Entry 0x0002: 0xfffff80002683dd0 (NtCallbackReturn) owned by ntoskrnl.exe
  Entry 0x0003: 0xfffff800029a6b10 (NtReadFile) owned by ntoskrnl.exe
  Entry 0x0004: 0xfffff800029a4bb0 (NtDeviceIoControlFile) owned by ntoskrnl.exe
  Entry 0x0005: 0xfffff8000299fee0 (NtWriteFile) owned by ntoskrnl.exe
  Entry 0x0006: 0xfffff80002945dc0 (NtRemoveIoCompletion) owned by ntoskrnl.exe
  Entry 0x0007: 0xfffff80002942f10 (NtReleaseSemaphore) owned by ntoskrnl.exe
  Entry 0x0008: 0xfffff8000299ada0 (NtReplyWaitReceivePort) owned by ntoskrnl.exe
  Entry 0x0009: 0xfffff80002a6ce20 (NtReplyPort) owned by ntoskrnl.exe

[snip]

SSDT[1] at fffff96000101c00 with 827 entries
  Entry 0x1000: 0xfffff960000f5580 (NtUserGetThreadState) owned by win32k.sys
  Entry 0x1001: 0xfffff960000f2630 (NtUserPeekMessage) owned by win32k.sys
  Entry 0x1002: 0xfffff96000103c6c (NtUserCallOneParam) owned by win32k.sys
  Entry 0x1003: 0xfffff96000111dd0 (NtUserGetKeyState) owned by win32k.sys
  Entry 0x1004: 0xfffff9600010b1ac (NtUserInvalidateRect) owned by win32k.sys
  Entry 0x1005: 0xfffff96000103e70 (NtUserCallNoParam) owned by win32k.sys
  Entry 0x1006: 0xfffff960000fb5a0 (NtUserGetMessage) owned by win32k.sys
  Entry 0x1007: 0xfffff960000dfbec (NtUserMessageCall) owned by win32k.sys
  Entry 0x1008: 0xfffff960001056c4 (NtGdiBitBlt) owned by win32k.sys
  Entry 0x1009: 0xfffff960001fd750 (NtGdiGetCharSet) owned by win32k.sys

[snip]
```

To filter all functions which point to ntoskrnl.exe and win32k.sys, you can use egrep on command-line. This will only show hooked SSDT functions.

```
$ python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 ssdt | egrep -v '(ntos|win32k)'
```

Note that the NT module on your system may be ntkrnlpa.exe or ntkrnlmp.exe - so check that before using egrep of you'll be filtering the wrong module name. Also be aware that this isn't a hardened technique for finding hooks, as malware can load a driver named win32ktesting.sys and bypass your filter.

## driverscan ##

To find DRIVER\_OBJECTs in physical memory using pool tag scanning, use the driverscan command. This is another way to locate kernel modules, although not all kernel modules have an associated DRIVER\_OBJECT. The DRIVER\_OBJECT is what contains the 28 IRP (Major Function) tables, thus the [CommandReference21#driverirp](CommandReference21#driverirp.md) command is based on the methodology used by driverscan.

For more information, see Andreas Schuster's [Scanning for Drivers](http://computer.forensikblog.de/en/2009/04/scanning_for_drivers.html).

```
$ python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 driverscan
Volatile Systems Volatility Framework 2.1_alpha
Offset(P)          #Ptr #Hnd Start                            Size Service Key          Name         Driver Name
------------------ ---- ---- ------------------ ------------------ -------------------- ------------ -----------
0x00000000174c6350    3    0 0xfffff880037e9000             0xd000 mouhid               mouhid       \Driver\mouhid
0x0000000017660cb0    3    0 0xfffff8800259a000            0x18000 rspndr               rspndr       \Driver\rspndr
0x0000000017663e70    3    0 0xfffff88002585000            0x15000 lltdio               lltdio       \Driver\lltdio
0x0000000017691d70    3    0 0xfffff88001944000            0x2a000 cdrom                cdrom        \Driver\cdrom
0x0000000017692a50    3    0 0xfffff8800196e000             0x9000 Null                 Null         \Driver\Null
0x0000000017695e70    3    0 0xfffff88001977000             0x7000 Beep                 Beep         \Driver\Beep
0x00000000176965c0    3    0 0xfffff8800197e000             0xe000 VgaSave              VgaSave      \Driver\VgaSave
0x000000001769fb00    4    0 0xfffff880019c1000             0x9000 RDPCDD               RDPCDD       \Driver\RDPCDD
0x00000000176a1720    3    0 0xfffff880019ca000             0x9000 RDPENCDD             RDPENCDD     \Driver\RDPENCDD
0x00000000176a2230    3    0 0xfffff880019d3000             0x9000 RDPREFMP             RDPREFMP     \Driver\RDPREFMP
[snip]
```

## filescan ##

To find FILE\_OBJECTs in physical memory using pool tag scanning, use the filescan command. This will find open files even if a rootkit is hiding the files on disk and if the rootkit hooks some API functions to hide the open handles on a live system. The output shows the physical offset of the FILE\_OBJECT, file name, number of pointers to the object, number of handles to the object, and the effective permissions granted to the object.

For more information, see Andreas Schuster's [Scanning for File Objects](http://computer.forensikblog.de/en/2009/04/scanning_for_file_objects.html) and [Linking File Objects To Processes](http://computer.forensikblog.de/en/2009/04/linking_file_objects_to_processes.html).

```
$ python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 filescan
Volatile Systems Volatility Framework 2.1_alpha
Offset(P)            #Ptr   #Hnd Access Name
------------------ ------ ------ ------ ----
0x000000000126f3a0     14      0 R--r-d \Windows\System32\mswsock.dll
0x000000000126fdc0     11      0 R--r-d \Windows\System32\ssdpsrv.dll
0x000000000468f7e0      6      0 R--r-d \Windows\System32\cryptsp.dll
0x000000000468fdc0     16      0 R--r-d \Windows\System32\Apphlpdm.dll
0x00000000048223a0      1      1 ------ \Endpoint
0x0000000004822a30     16      0 R--r-d \Windows\System32\kerberos.dll
0x0000000004906070     13      0 R--r-d \Windows\System32\wbem\repdrvfs.dll
0x0000000004906580      9      0 R--r-d \Windows\SysWOW64\netprofm.dll
0x0000000004906bf0      9      0 R--r-d \Windows\System32\wbem\wmiutils.dll
0x00000000049ce8e0      2      1 R--rwd \$Extend\$ObjId
0x00000000049cedd0      1      1 R--r-d \Windows\System32\en-US\vsstrace.dll.mui
0x0000000004a71070     17      1 R--r-d \Windows\System32\en-US\pnidui.dll.mui
0x0000000004a71440     11      0 R--r-d \Windows\System32\nci.dll
0x0000000004a719c0      1      1 ------ \srvsvc
[snip]
```

## mutantscan ##

To scan physical memory for KMUTANT objects with pool tag scanning, use the mutantscan command. By default, it displays all objects, but you can pass -s or --silent to only show named mutexes. The CID column contains the process ID and thread ID of the mutex owner if one exists.

For more information, see Andreas Schuster's [Searching for Mutants](http://computer.forensikblog.de/en/2009/04/searching_for_mutants.html).

```
$ python -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 mutantscan --silent
Volatile Systems Volatility Framework 2.1_alpha
Offset(P)          #Ptr #Hnd Signal Thread                   CID Name
------------------ ---- ---- ------ ------------------ --------- ----
0x000000000f702630    2    1      1 0x0000000000000000           {A3BD3259-3E4F-428a-84C8-F0463A9D3EB5}
0x00000000102fd930    2    1      1 0x0000000000000000           Feed Arbitration Shared Memory Mutex [ User : S-1-5-21-2628989162-3383567662-1028919141-1000 ]
0x00000000104e5e60    3    2      1 0x0000000000000000           ZoneAttributeCacheCounterMutex
0x0000000010c29e40    2    1      1 0x0000000000000000           _!MSFTHISTORY!_LOW!_
0x0000000013035080    2    1      1 0x0000000000000000           c:!users!testing!appdata!local!microsoft!feeds cache!
0x000000001722dfc0    2    1      1 0x0000000000000000           c:!users!testing!appdata!roaming!microsoft!windows!ietldcache!low!
0x00000000172497f0    2    1      1 0x0000000000000000           LRIEElevationPolicyMutex
0x000000001724bfc0    3    2      1 0x0000000000000000           !BrowserEmulation!SharedMemory!Mutex
0x000000001724f400    2    1      1 0x0000000000000000           c:!users!testing!appdata!local!microsoft!windows!history!low!history.ie5!mshist012012022220120223!
0x000000001724f4c0    4    3      1 0x0000000000000000           _!SHMSFTHISTORY!_
0x00000000172517c0    2    1      1 0x0000000000000000           __DDrawExclMode__
0x00000000172783a0    2    1      1 0x0000000000000000           Lowhttp://sourceforge.net/
0x00000000172db840    4    3      1 0x0000000000000000           ConnHashTable<1892>_HashTable_Mutex
0x00000000172de1d0    2    1      1 0x0000000000000000           Feeds Store Mutex S-1-5-21-2628989162-3383567662-1028919141-1000
0x00000000173b8080    2    1      1 0x0000000000000000           DDrawDriverObjectListMutex
0x00000000173bd340    2    1      0 0xfffffa8000a216d0 1652:2000 ALTTAB_RUNNING_MUTEX
0x0000000017449c40    2    1      1 0x0000000000000000           DDrawWindowListMutex
[snip]
```

## symlinkscan ##

This plugin scans for symbolic link objects and outputs their information.

```
$ python -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 symlinkscan
Volatile Systems Volatility Framework 2.1_alpha
Offset(P)            #Ptr   #Hnd Creation time            From                 To                                                          
------------------ ------ ------ ------------------------ -------------------- ------------------------------------------------------------
0x0000000000469780      1      0 2012-02-22 20:03:13      UMB#UMB#1...e1ba19f} \Device\00000048                                            
0x0000000000754560      1      0 2012-02-22 20:03:15      ASYNCMAC             \Device\ASYNCMAC                                            
0x0000000000ef6cf0      2      1 2012-02-22 19:58:24      0                    \BaseNamedObjects                                           
0x00000000014b2a10      1      0 2012-02-22 20:02:10      LanmanRedirector     \Device\Mup\;LanmanRedirector                               
0x00000000053e56f0      1      0 2012-02-22 20:03:15      SW#{eeab7...abac361} \Device\KSENUM#00000001                                     
0x0000000005cc0770      1      0 2012-02-22 19:58:20      WanArpV6             \Device\WANARPV6                                            
0x0000000005cc0820      1      0 2012-02-22 19:58:20      WanArp               \Device\WANARP                                              
0x0000000008ffa680      1      0 2012-02-22 19:58:24      Global               \BaseNamedObjects                                           
0x0000000009594810      1      0 2012-02-22 19:58:24      KnownDllPath         C:\Windows\syswow64                                         
0x000000000968f5f0      1      0 2012-02-22 19:58:23      KnownDllPath         C:\Windows\system32                                         
0x000000000ab24060      1      0 2012-02-22 19:58:20      Volume{3b...f6e6963} \Device\CdRom0                                              
0x000000000ab24220      1      0 2012-02-22 19:58:21      {EE0434CC...863ACC2} \Device\NDMP2                                               
0x000000000abd3460      1      0 2012-02-22 19:58:21      ACPI#PNP0...91405dd} \Device\00000041                                            
0x000000000abd36f0      1      0 2012-02-22 19:58:21      {802389A0...A90C31A} \Device\NDMP3 
[snip]
```

## thrdscan ##

To find ETHREAD objects in physical memory with pool tag scanning, use the thrdscan command. Since an ETHREAD contains fields that identify its parent process, you can use this technique to find hidden processes. One such use case is documented in the [CommandReference21#psxview](CommandReference21#psxview.md) command. Also, for verbose details, try the [CommandReference21#threads](CommandReference21#threads.md) plugin.

```
$ python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 thrdscan
Volatile Systems Volatility Framework 2.1_alpha
Offset(P)             PID    TID      Start Address Create Time               Exit Time                
------------------ ------ ------ ------------------ ------------------------- -------------------------
0x0000000008df68d0    280    392         0x77943260 2012-02-22 19:08:18                                
0x000000000eac3850   2040    144         0x76d73260 2012-02-22 11:28:59       2012-02-22 11:29:04      
0x000000000fd82590    880   1944         0x76d73260 2012-02-22 20:02:29       2012-02-22 20:02:29      
0x00000000103d15f0    880    884         0x76d73260 2012-02-22 19:58:43                                
0x00000000103e5480   1652   1788 0xfffff8a0010ed490 2012-02-22 20:03:44                                
0x00000000105a3940    916    324         0x76d73260 2012-02-22 20:02:07       2012-02-22 20:02:09      
0x00000000105b3560    816    824         0x76d73260 2012-02-22 19:58:42                                
0x00000000106d1710    916   1228         0x76d73260 2012-02-22 20:02:11                                
0x0000000010a349a0    816    820         0x76d73260 2012-02-22 19:58:41                                
0x0000000010bd1060   1892   2280         0x76d73260 2012-02-22 11:26:13                                
0x0000000010f24230    628    660         0x76d73260 2012-02-22 19:58:34                                
0x0000000010f27060    568    648 0xfffff8a0017c6650 2012-02-22 19:58:34
[snip]
```

# Networking #

## connections ##

To view TCP connections that were active at the time of the memory acquisition, use the connections command. This walks the singly-linked list of connection structures pointed to by a non-exported symbol in the tcpip.sys module.

This command is for x86 and x64 Windows XP and Windows 2003 Server only.

```
$ python vol.py -f Win2003SP2x64.vmem --profile=Win2003SP2x64 connections
Volatile Systems Volatility Framework 2.1_alpha
Offset(V)          Local Address             Remote Address               Pid
------------------ ------------------------- ------------------------- ------
0xfffffadfe6f2e2f0 172.16.237.150:1408       72.246.25.25:80             2136
0xfffffadfe72e8080 172.16.237.150:1369       64.4.11.30:80               2136
0xfffffadfe622d010 172.16.237.150:1403       74.125.229.188:80           2136
0xfffffadfe62e09e0 172.16.237.150:1352       64.4.11.20:80               2136
0xfffffadfe6f2e630 172.16.237.150:1389       209.191.122.70:80           2136
0xfffffadfe5e7a610 172.16.237.150:1419       74.125.229.187:80           2136
0xfffffadfe7321bc0 172.16.237.150:1418       74.125.229.188:80           2136
0xfffffadfe5ea3c90 172.16.237.150:1393       216.115.98.241:80           2136
0xfffffadfe72a3a80 172.16.237.150:1391       209.191.122.70:80           2136
0xfffffadfe5ed8560 172.16.237.150:1402       74.125.229.188:80           2136
```

Output includes the virtual offset of the `_TCPT_OBJECT` by default.  The physical offset can be obtained with the -P switch.

## connscan ##

To find `_TCPT_OBJECT` structures using pool tag scanning, use the connscan command. This can find artifacts from previous connections that have since been terminated, in addition to the active ones. In the output below, you'll notice some fields have been partially overwritten, but some of the information is still accurate. For example, the very last entry's Pid field is 0, but all other fields are still in tact. Thus, while it may find false positives sometimes, you also get the benefit of detecting as much information as possible.

This command is for x86 and x64 Windows XP and Windows 2003 Server only.

```
$ python vol.py -f Win2K3SP0x64.vmem --profile=Win2003SP2x64 connscan
Volatile Systems Volatility Framework 2.1_alpha
 Offset(P)  Local Address             Remote Address            Pid   
---------- ------------------------- ------------------------- ------ 
0x0ea7a610 172.16.237.150:1419       74.125.229.187:80           2136
0x0eaa3c90 172.16.237.150:1393       216.115.98.241:80           2136
0x0eaa4480 172.16.237.150:1398       216.115.98.241:80           2136
0x0ead8560 172.16.237.150:1402       74.125.229.188:80           2136
0x0ee2d010 172.16.237.150:1403       74.125.229.188:80           2136
0x0eee09e0 172.16.237.150:1352       64.4.11.20:80               2136
0x0f9f83c0 172.16.237.150:1425       98.139.240.23:80            2136
0x0f9fe010 172.16.237.150:1394       216.115.98.241:80           2136
0x0fb2e2f0 172.16.237.150:1408       72.246.25.25:80             2136
0x0fb2e630 172.16.237.150:1389       209.191.122.70:80           2136
0x0fb72730 172.16.237.150:1424       98.139.240.23:80            2136
0x0fea3a80 172.16.237.150:1391       209.191.122.70:80           2136
0x0fee8080 172.16.237.150:1369       64.4.11.30:80               2136
0x0ff21bc0 172.16.237.150:1418       74.125.229.188:80           2136
0x1019ec90 172.16.237.150:1397       216.115.98.241:80           2136
0x179099e0 172.16.237.150:1115       66.150.117.33:80            2856
0x2cdb1bf0 172.16.237.150:139        172.16.237.1:63369             4
0x339c2c00 172.16.237.150:1138       23.45.66.43:80              1332
0x39b10010 172.16.237.150:1148       172.16.237.138:139             0
```

## sockets ##

To detect listening sockets for any protocol (TCP, UDP, RAW, etc), use the sockets command. This walks a singly-linked list of socket structures which is pointed to by a non-exported symbol in the tcpip.sys module.

This command is for x86 and x64 Windows XP and Windows 2003 Server only.

```
$ python vol.py -f Win2K3SP0x64.vmem --profile=Win2003SP2x64 sockets
Volatile Systems Volatility Framework 2.1_alpha
Offset(V)             PID   Port  Proto Protocol        Address         Create Time
------------------ ------ ------ ------ --------------- --------------- -----------
0xfffffadfe71bbda0    432   1025      6 TCP             0.0.0.0         2012-01-23 18:20:01 
0xfffffadfe7350490    776   1028     17 UDP             0.0.0.0         2012-01-23 18:21:44 
0xfffffadfe6281120    804    123     17 UDP             127.0.0.1       2012-06-25 12:40:55 
0xfffffadfe7549010    432    500     17 UDP             0.0.0.0         2012-01-23 18:20:09 
0xfffffadfe5ee8400      4      0     47 GRE             0.0.0.0         2012-02-24 18:09:07 
0xfffffadfe606dc90      4    445      6 TCP             0.0.0.0         2012-01-23 18:19:38 
0xfffffadfe6eef770      4    445     17 UDP             0.0.0.0         2012-01-23 18:19:38 
0xfffffadfe7055210   2136   1321     17 UDP             127.0.0.1       2012-05-09 02:09:59 
0xfffffadfe750c010      4    139      6 TCP             172.16.237.150  2012-06-25 12:40:55 
0xfffffadfe745f610      4    138     17 UDP             172.16.237.150  2012-06-25 12:40:55 
0xfffffadfe6096560      4    137     17 UDP             172.16.237.150  2012-06-25 12:40:55 
0xfffffadfe7236da0    720    135      6 TCP             0.0.0.0         2012-01-23 18:19:51 
0xfffffadfe755c5b0   2136   1419      6 TCP             0.0.0.0         2012-06-25 12:42:37 
0xfffffadfe6f36510   2136   1418      6 TCP             0.0.0.0         2012-06-25 12:42:37       
[snip]
```

Output includes the virtual offset of the `_ADDRESS_OBJECT` by default.  The physical offset can be obtained with the -P switch.

## sockscan ##

To find `_ADDRESS_OBJECT` structures using pool tag scanning, use the sockscan command. As with connscan, this can pick up residual data and artifacts from previous sockets.

This command is for x86 and x64 Windows XP and Windows 2003 Server only.

```
$ python vol.py -f Win2K3SP0x64.vmem --profile=Win2003SP2x64 sockscan
Volatile Systems Volatility Framework 2.1_alpha
Offset(P)             PID   Port  Proto Protocol        Address         Create Time
------------------ ------ ------ ------ --------------- --------------- -----------
0x0000000000608010    804    123     17 UDP             172.16.237.150  2012-05-08 22:17:44 
0x000000000eae8400      4      0     47 GRE             0.0.0.0         2012-02-24 18:09:07 
0x000000000eaf1240   2136   1403      6 TCP             0.0.0.0         2012-06-25 12:42:37 
0x000000000ec6dc90      4    445      6 TCP             0.0.0.0         2012-01-23 18:19:38 
0x000000000ec96560      4    137     17 UDP             172.16.237.150  2012-06-25 12:40:55 
0x000000000ecf7d20   2136   1408      6 TCP             0.0.0.0         2012-06-25 12:42:37 
0x000000000ed5a010   2136   1352      6 TCP             0.0.0.0         2012-06-25 12:42:18 
0x000000000ed84ca0    804    123     17 UDP             172.16.237.150  2012-06-25 12:40:55 
0x000000000ee2d380   2136   1393      6 TCP             0.0.0.0         2012-06-25 12:42:37 
0x000000000ee81120    804    123     17 UDP             127.0.0.1       2012-06-25 12:40:55 
0x000000000eeda8c0    776   1363     17 UDP             0.0.0.0         2012-06-25 12:42:20 
0x000000000f0be1a0   2136   1402      6 TCP             0.0.0.0         2012-06-25 12:42:37 
0x000000000f0d0890      4   1133      6 TCP             0.0.0.0         2012-02-24 18:09:07
[snip]
```

## netscan ##

To scan for network artifacts in 32- and 64-bit Windows Vista, Windows 2008 Server and Windows 7 memory dumps, use the netscan command. This finds TCP endpoints, TCP listeners, UDP endpoints, and UDP listeners. It distinguishes between IPv4 and IPv6, prints the local and remote IP (if applicable), the local and remote port (if applicable), the time when the socket was bound or when the connection was established, and the current state (for TCP connections only). For more information, see [Volatility's New Netscan Module.](http://mnin.blogspot.com/2011/03/volatilitys-new-netscan-module.html)

Please note the following:

  * The netscan command uses pool tag scanning
  * There are at least 2 alternate ways to enumerate connections and sockets on Vista+ operating systems. One of them is using partitions and dynamic hash tables, which is how the netstat.exe utility on Windows systems works. The other involves bitmaps and port pools. Plugins for both of these methods exist for the Volatility 2.1 framework, but are currently not in the public trunk.

```
$ python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 netscan
Volatile Systems Volatility Framework 2.1_alpha
Offset(P)  Proto    Local Address                  Foreign Address      State            Pid      Owner          Created
0xf882a30  TCPv4    0.0.0.0:135                    0.0.0.0:0            LISTENING        628      svchost.exe    
0xfc13770  TCPv4    0.0.0.0:49154                  0.0.0.0:0            LISTENING        916      svchost.exe    
0xfdda1e0  TCPv4    0.0.0.0:49154                  0.0.0.0:0            LISTENING        916      svchost.exe    
0xfdda1e0  TCPv6    :::49154                       :::0                 LISTENING        916      svchost.exe    
0x1121b7b0 TCPv4    0.0.0.0:135                    0.0.0.0:0            LISTENING        628      svchost.exe    
0x1121b7b0 TCPv6    :::135                         :::0                 LISTENING        628      svchost.exe    
0x11431360 TCPv4    0.0.0.0:49152                  0.0.0.0:0            LISTENING        332      wininit.exe    
0x11431360 TCPv6    :::49152                       :::0                 LISTENING        332      wininit.exe    

[snip]

0x17de8980 TCPv6    :::49153                       :::0                 LISTENING        444      lsass.exe      
0x17f35240 TCPv4    0.0.0.0:49155                  0.0.0.0:0            LISTENING        880      svchost.exe    
0x17f362b0 TCPv4    0.0.0.0:49155                  0.0.0.0:0            LISTENING        880      svchost.exe    
0x17f362b0 TCPv6    :::49155                       :::0                 LISTENING        880      svchost.exe    
0xfd96570  TCPv4    -:0                            232.9.125.0:0        CLOSED           1        ?C?            
0x17236010 TCPv4    -:49227                        184.26.31.55:80      CLOSED           2820     iexplore.exe   
0x1725d010 TCPv4    -:49359                        93.184.220.20:80     CLOSED           2820     iexplore.exe   
0x17270530 TCPv4    10.0.2.15:49363                173.194.35.38:80     ESTABLISHED      2820     iexplore.exe   
0x17285010 TCPv4    -:49341                        82.165.218.111:80    CLOSED           2820     iexplore.exe   
0x17288a90 TCPv4    10.0.2.15:49254                74.125.31.157:80     CLOSE_WAIT       2820     iexplore.exe   
0x1728f6b0 TCPv4    10.0.2.15:49171                204.245.34.130:80    ESTABLISHED      2820     iexplore.exe   
0x17291ba0 TCPv4    10.0.2.15:49347                173.194.35.36:80     CLOSE_WAIT       2820     iexplore.exe   

[snip]

0x17854010 TCPv4    -:49168                        157.55.15.32:80      CLOSED           2820     iexplore.exe   
0x178a2a20 TCPv4    -:0                            88.183.123.0:0       CLOSED           504      svchost.exe    
0x178f5b00 TCPv4    10.0.2.15:49362                173.194.35.38:80     CLOSE_WAIT       2820     iexplore.exe   
0x17922910 TCPv4    -:49262                        184.26.31.55:80      CLOSED           2820     iexplore.exe   
0x17a9d860 TCPv4    10.0.2.15:49221                204.245.34.130:80    ESTABLISHED      2820     iexplore.exe   
0x17ac84d0 TCPv4    10.0.2.15:49241                74.125.31.157:80     CLOSE_WAIT       2820     iexplore.exe   
0x17b9acf0 TCPv4    10.0.2.15:49319                74.125.127.148:80    CLOSE_WAIT       2820     iexplore.exe   
0x10f38d70 UDPv4    10.0.2.15:1900                 *:*                                   1736     svchost.exe    2012-02-22 20:04:12 
0x173b3dc0 UDPv4    0.0.0.0:59362                  *:*                                   1736     svchost.exe    2012-02-22 20:02:27 
0x173b3dc0 UDPv6    :::59362                       *:*                                   1736     svchost.exe    2012-02-22 20:02:27 
0x173b4cf0 UDPv4    0.0.0.0:3702                   *:*                                   1736     svchost.exe    2012-02-22 20:02:27 
0x173b4cf0 UDPv6    :::3702                        *:*                                   1736     svchost.exe    2012-02-22 20:02:27
[snip]
```

# Registry #

Volatility is the only memory forensics framework with the ability to carve registry data. For more information, see BDG's [Memory Registry Tools](http://moyix.blogspot.com/2009/01/memory-registry-tools.html) and [Registry Code Updates](http://moyix.blogspot.com/2009/01/registry-code-updates.html).

## hivescan ##

To find the physical addresses of CMHIVEs (registry hives) in memory, use the hivescan command. For more information, see BDG's [Enumerating Registry Hives](http://moyix.blogspot.com/2008/02/enumerating-registry-hives.html).

This plugin isn't generally useful by itself. Its meant to be inherited by other plugins (such as [CommandReference21#hivelist](CommandReference21#hivelist.md) below) that build on and interpret the information found in CMHIVEs.

```
$python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 hivescan
Volatile Systems Volatility Framework 2.1_alpha
Offset(P)         
------------------
0x0000000008c95010
0x000000000aa1a010
0x000000000acf9010
0x000000000b1a9010
0x000000000c2b4010
0x000000000cd20010
0x000000000da51010
[snip]
```

## hivelist ##

To locate the virtual addresses of registry hives in memory, and the full paths to the corresponding hive on disk, use the hivelist command. If you want to print values from a certain hive, run this command first so you can see the address of the hives.

```
$ python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 hivelist
Volatile Systems Volatility Framework 2.1_alpha
Virtual            Physical           Name
------------------ ------------------ ----
0xfffff8a001053010 0x000000000b1a9010 \??\C:\System Volume Information\Syscache.hve
0xfffff8a0016a7420 0x0000000012329420 \REGISTRY\MACHINE\SAM
0xfffff8a0017462a0 0x00000000101822a0 \??\C:\Windows\ServiceProfiles\NetworkService\NTUSER.DAT
0xfffff8a001abe420 0x000000000eae0420 \??\C:\Windows\ServiceProfiles\LocalService\NTUSER.DAT
0xfffff8a002ccf010 0x0000000014659010 \??\C:\Users\testing\AppData\Local\Microsoft\Windows\UsrClass.dat
0xfffff80002b53b10 0x000000000a441b10 [no name]
0xfffff8a00000d010 0x000000000ddc6010 [no name]
0xfffff8a000022010 0x000000000da51010 \REGISTRY\MACHINE\SYSTEM
0xfffff8a00005c010 0x000000000dacd010 \REGISTRY\MACHINE\HARDWARE
0xfffff8a00021d010 0x000000000cd20010 \SystemRoot\System32\Config\SECURITY
0xfffff8a0009f1010 0x000000000aa1a010 \Device\HarddiskVolume1\Boot\BCD
0xfffff8a000a15010 0x000000000acf9010 \SystemRoot\System32\Config\SOFTWARE
0xfffff8a000ce5010 0x0000000008c95010 \SystemRoot\System32\Config\DEFAULT
0xfffff8a000f95010 0x000000000c2b4010 \??\C:\Users\testing\ntuser.dat
```

## printkey ##

To display the subkeys, values, data, and data types contained within a specified registry key, use the printkey command. By default, printkey will search all hives and print the key information (if found) for the requested key.  Therefore, if the key is located in more than one hive, the information for the key will be printed for each hive that contains it.

Say you want to traverse into the HKEY\_LOCAL\_MACHINE\Microsoft\Security Center\Svc key. You can do that in the following manner. Note: if you're running Volatility on Windows, enclose the key in double quotes (see [issue 166](https://code.google.com/p/volatility/issues/detail?id=166)).

```
$ python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 printkey -K "Microsoft\Security Center\Svc"
Volatile Systems Volatility Framework 2.1_alpha
Legend: (S) = Stable   (V) = Volatile

----------------------------
Registry: \SystemRoot\System32\Config\SOFTWARE
Key name: Svc (S)
Last updated: 2012-02-22 20:04:44 

Subkeys:
  (V) Vol

Values:
REG_QWORD     VistaSp1        : (S) 128920218544262440
REG_DWORD     AntiSpywareOverride : (S) 0
REG_DWORD     ConfigMask      : (S) 4361
```

Here you can see how the output appears when multiple hives (DEFAULT and ntuser.dat) contain the same key "Software\Microsoft\Windows NT\CurrentVersion".

```
$ python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 printkey -K "Software\Microsoft\Windows NT\CurrentVersion"
Volatile Systems Volatility Framework 2.1_alpha
Legend: (S) = Stable   (V) = Volatile

----------------------------
Registry: \SystemRoot\System32\Config\DEFAULT
Key name: CurrentVersion (S)
Last updated: 2009-07-14 04:53:31 

Subkeys:
  (S) Devices
  (S) PrinterPorts

Values:
----------------------------
Registry: \??\C:\Users\testing\ntuser.dat
Key name: CurrentVersion (S)
Last updated: 2012-02-22 11:26:13 

Subkeys:
  (S) Devices
  (S) EFS
  (S) MsiCorruptedFileRecovery
  (S) Network
  (S) PeerNet
  (S) PrinterPorts
  (S) Windows
  (S) Winlogon

[snip]
```

If you want to limit your search to a specific hive, printkey also accepts a virtual address to the hive. For example, to see the contents of HKEY\_LOCAL\_MACHINE, use the command below. Note: the offset is taken from the previous [CommandReference21#hivelist](CommandReference21#hivelist.md) output.

```
$ python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 printkey -o 0xfffff8a000a15010
Volatile Systems Volatility Framework 2.1_alpha
Legend: (S) = Stable   (V) = Volatile

----------------------------
Registry: User Specified
Key name: CMI-CreateHive{199DAFC2-6F16-4946-BF90-5A3FC3A60902} (S)
Last updated: 2009-07-14 07:13:38 

Subkeys:
  (S) ATI Technologies
  (S) Classes
  (S) Clients
  (S) Intel
  (S) Microsoft
  (S) ODBC
  (S) Policies
  (S) RegisteredApplications
  (S) Sonic
  (S) Wow6432Node
```

## hivedump ##

To recursively list all subkeys in a hive, use the hivedump command and pass it the virtual address to the desired hive.

```
$ python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 hivedump -o 0xfffff8a000a15010
Volatile Systems Volatility Framework 2.1_alpha
Last Written         Key
2009-07-14 07:13:38  \CMI-CreateHive{199DAFC2-6F16-4946-BF90-5A3FC3A60902}
2009-07-14 04:48:57  \CMI-CreateHive{199DAFC2-6F16-4946-BF90-5A3FC3A60902}\ATI Technologies
2009-07-14 04:48:57  \CMI-CreateHive{199DAFC2-6F16-4946-BF90-5A3FC3A60902}\ATI Technologies\Install
2009-07-14 04:48:57  \CMI-CreateHive{199DAFC2-6F16-4946-BF90-5A3FC3A60902}\ATI Technologies\Install\South Bridge
2009-07-14 04:48:57  \CMI-CreateHive{199DAFC2-6F16-4946-BF90-5A3FC3A60902}\ATI Technologies\Install\South Bridge\ATI_AHCI_RAID
2009-07-14 07:13:39  \CMI-CreateHive{199DAFC2-6F16-4946-BF90-5A3FC3A60902}\Classes
2009-07-14 04:53:38  \CMI-CreateHive{199DAFC2-6F16-4946-BF90-5A3FC3A60902}\Classes\*
2009-07-14 04:53:38  \CMI-CreateHive{199DAFC2-6F16-4946-BF90-5A3FC3A60902}\Classes\*\OpenWithList
2009-07-14 04:53:38  \CMI-CreateHive{199DAFC2-6F16-4946-BF90-5A3FC3A60902}\Classes\*\OpenWithList\Excel.exe
2009-07-14 04:53:38  \CMI-CreateHive{199DAFC2-6F16-4946-BF90-5A3FC3A60902}\Classes\*\OpenWithList\IExplore.exe
[snip]
```

## hashdump ##

To extract and decrypt cached domain credentials stored in the registry, use the hashdump command. For more information, see BDG's [Cached Domain Credentials](http://moyix.blogspot.com/2008/02/cached-domain-credentials.html) and [SANS Forensics 2009 - Memory Forensics and Registry Analysis](http://www.slideshare.net/mooyix/sans-forensics-2009-memory-forensics-and-registry-analysis).

To use hashdump, pass the virtual address of the SYSTEM hive as -y and the virtual address of the SAM hive as -s, like this:

```
$ python vol.py hashdump -f image.dd -y 0xe1035b60 -s 0xe165cb60 
Administrator:500:08f3a52bdd35f179c81667e9d738c5d9:ed88cccbc08d1c18bcded317112555f4::: 
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::: 
HelpAssistant:1000:ddd4c9c883a8ecb2078f88d729ba2e67:e78d693bc40f92a534197dc1d3a6d34f::: 
SUPPORT_388945a0:1002:aad3b435b51404eeaad3b435b51404ee:8bfd47482583168a0ae5ab020e1186a9::: 
phoenix:1003:07b8418e83fad948aad3b435b51404ee:53905140b80b6d8cbe1ab5953f7c1c51::: 
ASPNET:1004:2b5f618079400df84f9346ce3e830467:aef73a8bb65a0f01d9470fadc55a411c::: 
S----:1006:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::: 
```

Hashes can now be cracked using John the Ripper, rainbow tables, etc.

It is possible that a registry key is not available in memory.  When this happens, you may see the following error:

"ERROR   : volatility.plugins.registry.lsadump: Unable to read hashes from registry"

You can try to see if the correct keys are available: "CurrentControlSet\Control\lsa" from SYSTEM and "SAM\Domains\Account" from SAM.  First you need to get the "CurrentControlSet", for this we can use volshell (replace `[SYSTEM REGISTRY ADDRESS]` below with the offset you get from hivelist), for example:

```
$ ./vol.py -f XPSP3.vmem --profile=WinXPSP3x86 volshell
Volatile Systems Volatility Framework 2.1_alpha
Current context: process System, pid=4, ppid=0 DTB=0x319000
Welcome to volshell! Current memory image is: 
file:///XPSP3.vmem
To get help, type 'hh()'
>>> import volatility.win32.hashdump as h
>>> import volatility.win32.hive as hive
>>> addr_space = utils.load_as(self._config)
>>> sysaddr = hive.HiveAddressSpace(addr_space, self._config, [SYSTEM REGISTRY ADDRESS])
>>> print h.find_control_set(sysaddr)
1
>>> ^D
```

Then you can use the printkey plugin to make sure the keys and their data are there.  Since the "CurrentControlSet" is 1 in our previous example, we use "ControlSet001" in the first command:

```
$ ./vol.py -f XPSP3.vmem --profile=WinXPSP3x86 printkey -K "ControlSet001\Control\lsa" 

$ ./vol.py -f XPSP3.vmem --profile=WinXPSP3x86 printkey -K "SAM\Domains\Account"
```

If the key is missing you should see an error message:

"The requested key could not be found in the hive(s) searched"

## lsadump ##

To dump LSA secrets from the registry, use the lsadump command. This exposes information such as the default password (for systems with autologin enabled), the RDP public key, and credentials used by DPAPI.

For more information, see BDG's [Decrypting LSA Secrets](http://moyix.blogspot.com/2008/02/decrypting-lsa-secrets.html).

To use lsadump, pass the virtual address of the SYSTEM hive as the -y parameter and the virtual address of the SECURITY hive as the -s parameter.

```
$ python vol.py -f laqma.vmem lsadump -y 0xe1035b60 -s 0xe16a6b60
Volatile Systems Volatility Framework 2.0
L$RTMTIMEBOMB_1320153D-8DA3-4e8e-B27B-0D888223A588

0000   00 92 8D 60 01 FF C8 01                            ...`....

_SC_Dnscache

L$HYDRAENCKEY_28ada6da-d622-11d1-9cb9-00c04fb16e75

0000   52 53 41 32 48 00 00 00 00 02 00 00 3F 00 00 00    RSA2H.......?...
0010   01 00 01 00 37 CE 0C C0 EF EC 13 C8 A4 C5 BC B8    ....7...........
0020   AA F5 1A 7C 50 95 A4 E9 3B BA 41 C8 53 D7 CE C6    ...|P...;.A.S...
0030   CB A0 6A 46 7C 70 F3 21 17 1C FB 79 5C C1 83 68    ..jF|p.!...y...h
0040   91 E5 62 5E 2C AC 21 1E 79 07 A9 21 BB F0 74 E8    ..b^,.!.y..!..t.
0050   85 66 F4 C4 00 00 00 00 00 00 00 00 F9 D7 AD 5C    .f..............
0060   B4 7C FB F6 88 89 9D 2E 91 F2 60 07 10 42 CA 5A    .|........`..B.Z
0070   FC F0 D1 00 0F 86 29 B5 2E 1E 8C E0 00 00 00 00    ......).........
0080   AF 43 30 5F 0D 0E 55 04 57 F9 0D 70 4A C8 36 01    .C0_..U.W..pJ.6.
0090   C2 63 45 59 27 62 B5 77 59 84 B7 65 8E DB 8A E0    .cEY'b.wY..e....
00A0   00 00 00 00 89 19 5E D8 CB 0E 03 39 E2 52 04 37    ......^....9.R.7
00B0   20 DC 03 C8 47 B5 2A B3 9C 01 65 15 FF 0F FF 8F     ...G.*...e.....
00C0   17 9F C1 47 00 00 00 00 1B AC BF 62 4E 81 D6 2A    ...G.......bN..*
00D0   32 98 36 3A 11 88 2D 99 3A EA 59 DE 4D 45 2B 9E    2.6:..-.:.Y.ME+.
00E0   74 15 14 E1 F2 B5 B2 80 00 00 00 00 75 BD A0 36    t...........u..6
00F0   20 AD 29 0E 88 E0 FD 5B AD 67 CA 88 FC 85 B9 82     .)....[.g......
0100   94 15 33 1A F1 65 45 D1 CA F9 D8 4C 00 00 00 00    ..3..eE....L....
0110   71 F0 0B 11 F2 F1 AA C5 0C 22 44 06 E1 38 6C ED    q........"D..8l.
0120   6E 38 51 18 E8 44 5F AD C2 CE 0A 0A 1E 8C 68 4F    n8Q..D_.......hO
0130   4D 91 69 07 DE AA 1A EC E6 36 2A 9C 9C B6 49 1F    M.i......6*...I.
0140   B3 DD 89 18 52 7C F8 96 4F AF 05 29 DF 17 D8 48    ....R|..O..)...H
0150   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
0160   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
0170   00 00 00 00 00 00 00 00 00 00 00 00                ............

DPAPI_SYSTEM

0000   01 00 00 00 24 04 D6 B0 DA D1 3C 40 BB EE EC 89    ....$.....<@....
0010   B4 BB 90 5B 9A BF 60 7D 3E 96 72 CD 9A F6 F8 BE    ...[..`}>.r.....
0020   D3 91 5C FA A5 8B E6 B4 81 0D B6 D4                ............
```

## userassist ##

To get the UserAssist keys from a sample you can use the userassist plugin.  For more information see Gleeda's [Volatility UserAssist plugin](http://gleeda.blogspot.com/2011/04/volatility-14-userassist-plugin.html) post.

```
$ ./vol.py -f win7.vmem --profile=Win7SP0x86 userassist 
Volatile Systems Volatility Framework 2.0
----------------------------
Registry: \??\C:\Users\admin\ntuser.dat
Key name: Count
Last updated: 2010-07-06 22:40:25 

Subkeys:

Values:
REG_BINARY    Microsoft.Windows.GettingStarted : 
Count:          14
Focus Count:    21
Time Focused:   0:07:00.500000
Last updated:   2010-03-09 19:49:20 

0000   00 00 00 00 0E 00 00 00 15 00 00 00 A0 68 06 00    .............h..
0010   00 00 80 BF 00 00 80 BF 00 00 80 BF 00 00 80 BF    ................
0020   00 00 80 BF 00 00 80 BF 00 00 80 BF 00 00 80 BF    ................
0030   00 00 80 BF 00 00 80 BF FF FF FF FF EC FE 7B 9C    ..............{.
0040   C1 BF CA 01 00 00 00 00                            ........

REG_BINARY    UEME_CTLSESSION : 
Count:          187
Focus Count:    1205
Time Focused:   6:25:06.216000
Last updated:   1970-01-01 00:00:00 

[snip]

REG_BINARY    %windir%\system32\calc.exe : 
Count:          12
Focus Count:    17
Time Focused:   0:05:40.500000
Last updated:   2010-03-09 19:49:20 

0000   00 00 00 00 0C 00 00 00 11 00 00 00 20 30 05 00    ............ 0..
0010   00 00 80 BF 00 00 80 BF 00 00 80 BF 00 00 80 BF    ................
0020   00 00 80 BF 00 00 80 BF 00 00 80 BF 00 00 80 BF    ................
0030   00 00 80 BF 00 00 80 BF FF FF FF FF EC FE 7B 9C    ..............{.
0040   C1 BF CA 01 00 00 00 00                            ........
                          ........

REG_BINARY    Z:\vmware-share\apps\odbg110\OLLYDBG.EXE : 
Count:          11
Focus Count:    266
Time Focused:   1:19:58.045000
Last updated:   2010-03-18 01:56:31 

0000   00 00 00 00 0B 00 00 00 0A 01 00 00 69 34 49 00    ............i4I.
0010   00 00 80 BF 00 00 80 BF 00 00 80 BF 00 00 80 BF    ................
0020   00 00 80 BF 00 00 80 BF 00 00 80 BF 00 00 80 BF    ................
0030   00 00 80 BF 00 00 80 BF FF FF FF FF 70 3B CB 3A    ............p;.:
0040   3E C6 CA 01 00 00 00 00                            >.......
[snip]
```

## shimcache ##

This plugin parses the Application Compatibility Shim Cache registry key.

```
$ python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 shimcache
Volatile Systems Volatility Framework 2.1_alpha
Last Modified: 2009-07-14 01:39:15 , Path: \??\C:\Windows\system32\LogonUI.exe
Last Modified: 2009-07-14 01:39:46 , Path: \??\C:\Windows\System32\svchost.exe
Last Modified: 2009-07-14 01:39:50 , Path: \??\C:\Windows\system32\vssvc.exe
Last Modified: 2009-06-10 20:39:58 , Path: \??\C:\Windows\Microsoft.NET\Framework64\v2.0.50727\mscorsvw.exe
Last Modified: 2009-06-10 21:23:09 , Path: \??\C:\Windows\Microsoft.NET\Framework\v2.0.50727\mscorsvw.exe
Last Modified: 2009-06-10 20:39:44 , Path: \??\C:\Windows\WinSxS\amd64_netfx-clrgc_b03f5f7f11d50a3a_6.1.7600.16385_none_ada52b8ba0da82ba\clrgc.exe
Last Modified: 2009-07-14 01:39:25 , Path: \??\C:\Windows\System32\netsh.exe
Last Modified: 2009-07-14 01:39:07 , Path: \??\C:\Windows\system32\DrvInst.exe
```

# Crash Dumps, Hibernation, and Conversion #

Volatility supports Microsoft crash dumps and hibernation files in addition to raw memory dumps. All commands that work on raw dumps also work on crash and hiber images.

## crashinfo ##

Information from the crashdump header can be printed using the crashinfo command.  You will see information like that of the Microsoft [dumpcheck](http://support.microsoft.com/kb/119490) utility.

```
$ python vol.py -f win7_x64.dmp --profile=Win7SP0x64 crashinfo
Volatile Systems Volatility Framework 2.1_alpha
_DMP_HEADER64:
 Majorversion:         0x0000000f (15)
 Minorversion:         0x00001db0 (7600)
 KdSecondaryVersion    0x00000000
 DirectoryTableBase    0x32a44000
 PfnDataBase           0xfffff80002aa8220
 PsLoadedModuleList    0xfffff80002a3de50
 PsActiveProcessHead   0xfffff80002a1fb30
 MachineImageType      0x00008664
 NumberProcessors      0x00000002
 BugCheckCode          0x00000000
 KdDebuggerDataBlock   0xfffff800029e9070
 ProductType           0x00000001
 SuiteMask             0x00000110
 WriterStatus          0x00000000
 Comment               PAGEPAGEPAGEPAGEPAGEPAGE[snip]

Physical Memory Description:
Number of runs: 3
FileOffset    Start Address    Length
00002000      00001000         0009e000
000a0000      00100000         3fde0000
3fe80000      3ff00000         00100000
3ff7f000      3ffff000
```

## hibinfo ##

The hibinfo command reveals additional information stored in the hibernation file, including the state of the Control Registers, such as CR0, etc.  It also identifies the time at which the hibernation file was created, the state of the hibernation file, and the version of windows being hibernated.  Example output for the function is shown below:

```
$ python vol.py -f hiberfil.sys --profile=Win7SP1x64 hibinfo
IMAGE_HIBER_HEADER:
Signature: HIBR
SystemTime: 2011-12-23 16:34:27 

Control registers flags
CR0: 80050031
CR0[PAGING]: 1
CR3: 00187000
CR4: 000006f8
CR4[PSE]: 1
CR4[PAE]: 1

Windows Version is 6.1 (7601)
```

## imagecopy ##

The imagecopy command allows one to convert any existing type of address space (such as a crashdump, hibernation file, or live firewire session) to a raw memory image. This conversion be necessary if some of your other forensic tools only support reading raw memory dumps.

The profile should be specified for this command, so if you don't know it already, use the [CommandReference21#imageinfo](CommandReference21#imageinfo.md) or [CommandReference21#kdbgscan](CommandReference21#kdbgscan.md) commands first.  The output file is specified with the -O flag.  The progress is updated as the file is converted:

```
$ python vol.py -f win7_x64.dmp --profile=Win7SP0x64 imagecopy -O copy.raw
Volatile Systems Volatility Framework 2.1_alpha
Writing data (5.00 MB chunks): |.......................................|
```

## raw2dmp ##

To convert a raw memory dump (for example from a win32dd acquisition or a VMware .vmem file) into a Microsoft crash dump, use the raw2dmp command. This is useful if you want to load the memory in the WinDbg kernel debugger for analysis.

```
$ python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 raw2dmp -O copy.dmp
Volatile Systems Volatility Framework 2.1_alpha
Writing data (5.00 MB chunks): |..............................................................................|
```

# Malware and Rootkits #

Although all Volatility commands can help you hunt malware in one way or another, there are a few designed specifically for hunting rootkits and malicious code. The most comprehensive documentation for these commands can be found in the [Malware Analyst's Cookbook and DVD: Tools and Techniques For Fighting Malicious Code](http://www.amazon.com/dp/0470613033).

## malfind ##

The malfind command helps find hidden or injected code/DLLs in user mode memory, based on characteristics such as VAD tag and page permissions.

Note: malfind does not detect DLLs injected into a process using CreateRemoteThread->LoadLibrary. DLLs injected with this technique are not hidden and thus you can view them with [CommandReference21#dlllist](CommandReference21#dlllist.md). The purpose of malfind is to locate DLLs that standard methods/tools do not see. For more information see [Issue #178](https://code.google.com/p/volatility/issues/detail?id=#178).

Here is an example of using it to detect the presence of Zeus. The first memory segment (starting at 0x01600000) was detected because its executable, marked as private (not shared between processes) and has a VadS tag...which means there is no memory mapped file already occupying the space. Based on a disassembly of the data found at this address, it seems to contain some API hook trampoline stubs.

The second memory segment (starting at 0x015D0000) was detected because it contained an executable that isn't listed in the PEB's module lists.

If you want to save extracted copies of the memory segments identified by malfind, just supply an output directory with -D or --dump-dir=DIR. In this case, an unpacked copy of the Zeus binary that was injected into explorer.exe would be written to disk.

```
$ python vol.py -f zeus.vmem malfind -p 1724
Volatile Systems Volatility Framework 2.1_alpha

Process: explorer.exe Pid: 1724 Address: 0x1600000
Vad Tag: VadS Protection: PAGE_EXECUTE_READWRITE
Flags: CommitCharge: 1, MemCommit: 1, PrivateMemory: 1, Protection: 6

0x01600000  b8 35 00 00 00 e9 cd d7 30 7b b8 91 00 00 00 e9   .5......0{......
0x01600010  4f df 30 7b 8b ff 55 8b ec e9 ef 17 c1 75 8b ff   O.0{..U......u..
0x01600020  55 8b ec e9 95 76 bc 75 8b ff 55 8b ec e9 be 53   U....v.u..U....S
0x01600030  bd 75 8b ff 55 8b ec e9 d6 18 c1 75 8b ff 55 8b   .u..U......u..U.

0x1600000 b835000000       MOV EAX, 0x35
0x1600005 e9cdd7307b       JMP 0x7c90d7d7
0x160000a b891000000       MOV EAX, 0x91
0x160000f e94fdf307b       JMP 0x7c90df63
0x1600014 8bff             MOV EDI, EDI
0x1600016 55               PUSH EBP

Process: explorer.exe Pid: 1724 Address: 0x15d0000
Vad Tag: VadS Protection: PAGE_EXECUTE_READWRITE
Flags: CommitCharge: 38, MemCommit: 1, PrivateMemory: 1, Protection: 6

0x015d0000  4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00   MZ..............
0x015d0010  b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00   ........@.......
0x015d0020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x015d0030  00 00 00 00 00 00 00 00 00 00 00 00 d0 00 00 00   ................

0x15d0000 4d               DEC EBP
0x15d0001 5a               POP EDX
0x15d0002 90               NOP
0x15d0003 0003             ADD [EBX], AL
0x15d0005 0000             ADD [EAX], AL
0x15d0007 000400           ADD [EAX+EAX], AL
0x15d000a 0000             ADD [EAX], AL
```

## yarascan ##

Volatility has several built-in scanning engines to help you find simple patterns like pool tags in physical or virtual address spaces. However, if you need to scan for more complex things like regular expressions or compound rules (i.e. search for "this" and not "that"), you can use the yarascan command. This plugin can help you locate any sequence of bytes (like assembly instructions with wild cards), regular expressions, ANSI strings, or Unicode strings in user mode or kernel memory.

You can create a YARA rules file and specify it as --yara-file=RULESFILE. Or, if you're just looking for something simple, and only plan to do the search a few times, then you can specify the criteria like --yara-rules=RULESTEXT.

To search for signatures defined in the file rules.yar, in any process, and simply display the results on screen:

```
$ python vol.py -f zeus.vmem yarascan --yara-file=/path/to/rules.yar
```

To search for a simple string in any process and dump the memory segments containing a match:

```
$ python vol.py -f zeus.vmem yarascan -D dump_files --yara-rules="simpleStringToFind"
```

To search for a byte pattern in kernel memory, use the following technique. This searches through memory in 1MB chunks, in all sessions. The TDL3 malware applies a hard-patch to SCSI adaptors on disk (sometimes atapi.sys or vmscsi.sys). In particular, it adds some shell code to the .rsrc section of the file, and then modifies the AddressOfEntryPoint so that it points at the shell code. This is TDL3's main persistence method. One of the unique instructions in the shell code is `cmp dword ptr [eax], ‘3LDT’` so I made a YARA signature from those opcodes:

```
$ python vol.py -f tdl3.vmem yarascan --yara-rules="{8B 00 81 38 54 44 4C 33 75 5A}" -K 
Volatile Systems Volatility Framework 2.1_alpha
Rule: r1
Owner: (Unknown Kernel Memory)
0x8138dcc0  8b 00 81 38 54 44 4c 33 75 5a 8b 45 f4 05 fd 29   ...8TDL3uZ.E...)
0x8138dcd0  b7 f0 50 b8 08 03 00 00 8b 80 00 00 df ff ff b0   ..P.............
0x8138dce0  00 01 00 00 b8 08 03 00 00 8b 80 00 00 df ff 8b   ................
0x8138dcf0  40 04 8b 4d ec 03 41 20 ff d0 ff 75 e0 b8 08 03   @..M..A....u....
Rule: r1
Owner: dump_vmscsi.sys
0xf94bb4c3  8b 00 81 38 54 44 4c 33 75 5a 8b 45 f4 05 fd 29   ...8TDL3uZ.E...)
0xf94bb4d3  b7 f0 50 b8 08 03 00 00 8b 80 00 00 df ff ff b0   ..P.............
0xf94bb4e3  00 01 00 00 b8 08 03 00 00 8b 80 00 00 df ff 8b   ................
0xf94bb4f3  40 04 8b 4d ec 03 41 20 ff d0 ff 75 e0 b8 08 03   @..M..A....u....
Rule: r1
Owner: vmscsi.sys
0xf9dba4c3  8b 00 81 38 54 44 4c 33 75 5a 8b 45 f4 05 fd 29   ...8TDL3uZ.E...)
0xf9dba4d3  b7 f0 50 b8 08 03 00 00 8b 80 00 00 df ff ff b0   ..P.............
0xf9dba4e3  00 01 00 00 b8 08 03 00 00 8b 80 00 00 df ff 8b   ................
0xf9dba4f3  40 04 8b 4d ec 03 41 20 ff d0 ff 75 e0 b8 08 03   @..M..A....u....
```

Search for a given byte pattern in a particular process:

```
$ python vol.py -f zeus.vmem yarascan --yara-rules="{eb 90 ff e4 88 32 0d}" --pid=624
```

Search for a regular expression in a particular process:

```
$ python vol.py -f zeus.vmem yarascan --yara-rules="/my(regular|expression{0,2})/" --pid=624
```

## svcscan ##

Volatility is the only memory forensics framework with the ability to list services without using the Windows API on a live machine. To see which services are registered on your memory image, use the svcscan command. The output shows the process ID of each service (if its active and pertains to a usermode process), the service name, service display name, service type, and current status. It also shows the binary path for the registered service - which will be an EXE for usermode services and a driver name for services that run from kernel mode.

```
$ python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 svcscan
Volatile Systems Volatility Framework 2.1_alpha
Offset: 0xa26e70
Order: 71
Process ID: 1104
Service Name: DPS
Display Name: Diagnostic Policy Service
Service Type: SERVICE_WIN32_SHARE_PROCESS
Service State: SERVICE_RUNNING
Binary Path: C:\Windows\system32\svchost.exe -k LocalServiceNoNetwork

Offset: 0xa25620
Order: 70
Process ID: -
Service Name: dot3svc
Display Name: Wired AutoConfig
Service Type: SERVICE_WIN32_SHARE_PROCESS
Service State: SERVICE_STOPPED
Binary Path: -

Offset: 0xa25440
Order: 68
Process ID: -
Service Name: Disk
Display Name: Disk Driver
Service Type: SERVICE_KERNEL_DRIVER
Service State: SERVICE_RUNNING
Binary Path: \Driver\Disk

[snip]
```

## ldrmodules ##

There are many ways to hide a DLL. One of the ways involves unlinking the DLL from one (or all) of the linked lists in the PEB. However, when this is done, there is still information contained within the VAD (Virtual Address Descriptor) which identifies the base address of the DLL and its full path on disk. To cross-reference this information (known as memory mapped files) with the 3 PEB lists, use the ldrmodules command.

For each memory mapped PE file, the ldrmodules command prints True or False if the PE exists in the PEB lists.

```
$ python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 ldrmodules
Volatile Systems Volatility Framework 2.1_alpha
Pid      Process              Base               InLoad InInit InMem MappedPath
-------- -------------------- ------------------ ------ ------ ----- ----------
     208 smss.exe             0x0000000047a90000 True   False  True  \Windows\System32\smss.exe
     296 csrss.exe            0x0000000049700000 True   False  True  \Windows\System32\csrss.exe
     344 csrss.exe            0x0000000000390000 False  False  False \Windows\Fonts\vgasys.fon
     344 csrss.exe            0x00000000007a0000 False  False  False \Windows\Fonts\vgaoem.fon
     344 csrss.exe            0x00000000020e0000 False  False  False \Windows\Fonts\ega40woa.fon
     344 csrss.exe            0x0000000000a60000 False  False  False \Windows\Fonts\dosapp.fon
     344 csrss.exe            0x0000000000a70000 False  False  False \Windows\Fonts\cga40woa.fon
     344 csrss.exe            0x00000000020d0000 False  False  False \Windows\Fonts\cga80woa.fon
     428 services.exe         0x0000000000020000 False  False  False \Windows\System32\en-US\services.exe.mui
     428 services.exe         0x00000000ff670000 True   False  True  \Windows\System32\services.exe
     444 lsass.exe            0x0000000000180000 False  False  False \Windows\System32\en-US\crypt32.dll.mui
     444 lsass.exe            0x0000000076b20000 True   True   True  \Windows\System32\kernel32.dll
     444 lsass.exe            0x0000000076c40000 True   True   True  \Windows\System32\user32.dll
     444 lsass.exe            0x0000000074a70000 True   True   True  \Windows\System32\msprivs.dll
     444 lsass.exe            0x0000000076d40000 True   True   True  \Windows\System32\ntdll.dll
     568 svchost.exe          0x00000000001e0000 False  False  False \Windows\System32\en-US\umpnpmgr.dll.mui
[snip]
```

Since the PEB and the DLL lists that it contains all exist in user mode, its also possible for malware to hide (or obscure) a DLL by simply overwriting the path. Tools that only look for unlinked entries may miss the fact that malware could overwrite C:\bad.dll to show C:\windows\system32\kernel32.dll. So you can also pass -v or --verbose to ldrmodules to see the full path of all entries.

For concrete examples, see [ZeroAccess Misleads Memory-File Link](http://blogs.mcafee.com/mcafee-labs/zeroaccess-misleads-memory-file-link) and [QuickPost: Flame & Volatility](http://mnin.blogspot.com/2012/06/quickpost-flame-volatility.html).

```
$ python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 ldrmodules -v
Volatile Systems Volatility Framework 2.1_alpha
Pid      Process              Base               InLoad InInit InMem MappedPath
-------- -------------------- ------------------ ------ ------ ----- ----------
     208 smss.exe             0x0000000047a90000 True   False  True  \Windows\System32\smss.exe
  Load Path: \SystemRoot\System32\smss.exe : smss.exe
  Mem Path:  \SystemRoot\System32\smss.exe : smss.exe
     296 csrss.exe            0x0000000049700000 True   False  True  \Windows\System32\csrss.exe
  Load Path: C:\Windows\system32\csrss.exe : csrss.exe
  Mem Path:  C:\Windows\system32\csrss.exe : csrss.exe
     344 csrss.exe            0x0000000000390000 False  False  False \Windows\Fonts\vgasys.fon
     344 csrss.exe            0x00000000007a0000 False  False  False \Windows\Fonts\vgaoem.fon
     344 csrss.exe            0x00000000020e0000 False  False  False \Windows\Fonts\ega40woa.fon
     344 csrss.exe            0x0000000000a60000 False  False  False \Windows\Fonts\dosapp.fon
     344 csrss.exe            0x0000000000a70000 False  False  False \Windows\Fonts\cga40woa.fon
     344 csrss.exe            0x00000000020d0000 False  False  False \Windows\Fonts\cga80woa.fon
     428 services.exe         0x0000000000020000 False  False  False \Windows\System32\en-US\services.exe.mui
     428 services.exe         0x00000000ff670000 True   False  True  \Windows\System32\services.exe
  Load Path: C:\Windows\system32\services.exe : services.exe
  Mem Path:  C:\Windows\system32\services.exe : services.exe
     444 lsass.exe            0x0000000000180000 False  False  False \Windows\System32\en-US\crypt32.dll.mui
     444 lsass.exe            0x0000000076b20000 True   True   True  \Windows\System32\kernel32.dll
  Load Path: C:\Windows\system32\kernel32.dll : kernel32.dll
  Init Path: C:\Windows\system32\kernel32.dll : kernel32.dll
  Mem Path:  C:\Windows\system32\kernel32.dll : kernel32.dll
[snip]
```

## impscan ##

In order to fully reverse engineer code that you find in memory dumps, its necessary to see which functions the code imports. In other words, which API functions it calls. When you dump binaries with [CommandReference21#dlldump](CommandReference21#dlldump.md), [CommandReference21#moddump](CommandReference21#moddump.md), or [CommandReference21#procexedump](CommandReference21#procexedump.md), the IAT (Import Address Table) may not properly be reconstructed due to the high likelihood that one or more pages in the PE header or IAT are not memory resident (paged). Thus, we created impscan. Impscan identifies calls to APIs without parsing a PE's IAT. It even works if malware completely erases the PE header, and it works on kernel drivers.

Previous versions of impscan automatically created a labeled IDB for use with IDA Pro. This functionality has temporarily been disabled, but will return sometime in the future when other similar functionality is introduced.

Take Coreflood for example. This malware deleted its PE header once it loaded in the target process (by calling VirtualFree on the injected DLL's ImageBase). You can use [CommandReference21#malfind](CommandReference21#malfind.md) to detect the presence of Coreflood based on the typical criteria (page permissions, VAD tags, etc). Notice how the PE's base address doesn't contain the usual 'MZ' header:

```
$ python vol.py -f coreflood.vmem -p 2044 malfind
Volatile Systems Volatility Framework 2.1_alpha

Process: IEXPLORE.EXE Pid: 2044 Address: 0x7ff80000
Vad Tag: VadS Protection: PAGE_EXECUTE_READWRITE
Flags: CommitCharge: 45, PrivateMemory: 1, Protection: 6

0x7ff80000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x7ff80010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x7ff80020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x7ff80030  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................

0x7ff80000 0000             ADD [EAX], AL
0x7ff80002 0000             ADD [EAX], AL
0x7ff80004 0000             ADD [EAX], AL
0x7ff80006 0000             ADD [EAX], AL
```

Let's assume you want to extract the unpacked copy of Coreflood and see its imported APIs. Use impscan by specifying the base address provided to you by malfind. In this case, we fixup the base address by 0x1000 to account for the missing page at the real ImageBase.

```
$ python vol.py -f coreflood.vmem -p 2044 impscan -b 0x7ff81000
Volatile Systems Volatility Framework 2.1_alpha
IAT        Call       Module               Function
---------- ---------- -------------------- --------
0x7ff9e000 0x77dd77b3 ADVAPI32.dll         SetSecurityDescriptorDacl
0x7ff9e004 0x77dfd4c9 ADVAPI32.dll         GetUserNameA
0x7ff9e008 0x77dd6bf0 ADVAPI32.dll         RegCloseKey
0x7ff9e00c 0x77ddeaf4 ADVAPI32.dll         RegCreateKeyExA
0x7ff9e010 0x77dfc123 ADVAPI32.dll         RegDeleteKeyA
0x7ff9e014 0x77ddede5 ADVAPI32.dll         RegDeleteValueA
0x7ff9e018 0x77ddd966 ADVAPI32.dll         RegNotifyChangeKeyValue
0x7ff9e01c 0x77dd761b ADVAPI32.dll         RegOpenKeyExA
0x7ff9e020 0x77dd7883 ADVAPI32.dll         RegQueryValueExA
0x7ff9e024 0x77ddebe7 ADVAPI32.dll         RegSetValueExA
0x7ff9e028 0x77dfc534 ADVAPI32.dll         AdjustTokenPrivileges
0x7ff9e02c 0x77e34c3f ADVAPI32.dll         InitiateSystemShutdownA
0x7ff9e030 0x77dfd11b ADVAPI32.dll         LookupPrivilegeValueA
0x7ff9e034 0x77dd7753 ADVAPI32.dll         OpenProcessToken
0x7ff9e038 0x77dfc8c1 ADVAPI32.dll         RegEnumKeyExA
[snip]
```

If you don't specify a base address with -b or --base, then you'll end up scanning the process's main module (i.e. IEXPLORE.EXE since that's -p 2044) for imported functions. You can also specify the base address of a kernel driver to scan the driver for imported kernel-mode functions.

Laqma loads a kernel driver named lanmandrv.sys. If you extract it with [CommandReference21#moddump](CommandReference21#moddump.md), the IAT will be corrupt. So use impscan to rebuild it:

```
$ python vol.py -f laqma.vmem impscan -b 0xfca29000
Volatile Systems Volatility Framework 2.1_alpha
IAT        Call       Module               Function
---------- ---------- -------------------- --------
0xfca2a080 0x804ede90 ntoskrnl.exe         IofCompleteRequest
0xfca2a084 0x804f058c ntoskrnl.exe         IoDeleteDevice
0xfca2a088 0x80568140 ntoskrnl.exe         IoDeleteSymbolicLink
0xfca2a08c 0x80567dcc ntoskrnl.exe         IoCreateSymbolicLink
0xfca2a090 0x805a2130 ntoskrnl.exe         MmGetSystemRoutineAddress
0xfca2a094 0x805699e0 ntoskrnl.exe         IoCreateDevice
0xfca2a098 0x80544080 ntoskrnl.exe         ExAllocatePoolWithTag
0xfca2a09c 0x80536dc3 ntoskrnl.exe         wcscmp
0xfca2a0a0 0x804fdbc0 ntoskrnl.exe         ZwOpenKey
0xfca2a0a4 0x80535010 ntoskrnl.exe         _except_handler3
0xfca2a3ac 0x8056df44 ntoskrnl.exe         NtQueryDirectoryFile
0xfca2a3b4 0x8060633e ntoskrnl.exe         NtQuerySystemInformation
0xfca2a3bc 0x805bfb78 ntoskrnl.exe         NtOpenProcess
```

The next example shows impscan on an x64 driver and using the render\_idc output format. This gives you an IDC file you can import into IDA Pro to apply labels to the function calls.

```
$ python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 impscan -b 0xfffff88003980000 --output=idc --output-file=imps.idc
Volatile Systems Volatility Framework 2.1_alpha

$ cat imps.idc 
#include <idc.idc>
static main(void) {
   MakeDword(0xFFFFF8800398A000);
   MakeName(0xFFFFF8800398A000, "KeSetEvent");
   MakeDword(0xFFFFF8800398A008);
   MakeName(0xFFFFF8800398A008, "PsTerminateSystemThread");
   MakeDword(0xFFFFF8800398A010);
   MakeName(0xFFFFF8800398A010, "KeInitializeEvent");
   MakeDword(0xFFFFF8800398A018);
   MakeName(0xFFFFF8800398A018, "PsCreateSystemThread");
   MakeDword(0xFFFFF8800398A020);
   MakeName(0xFFFFF8800398A020, "KeWaitForSingleObject");
   MakeDword(0xFFFFF8800398A028);
   MakeName(0xFFFFF8800398A028, "ZwClose");
   MakeDword(0xFFFFF8800398A030);
   MakeName(0xFFFFF8800398A030, "RtlInitUnicodeString");
[snip]
   MakeDword(0xFFFFF8800398A220);
   MakeName(0xFFFFF8800398A220, "RtlAnsiCharToUnicodeChar");
   MakeDword(0xFFFFF8800398A228);
   MakeName(0xFFFFF8800398A228, "__C_specific_handler");
Exit(0);}
```

## apihooks ##

To find API hooks in user mode or kernel mode, use the apihooks plugin. This finds IAT, EAT, Inline style hooks, and several special types of hooks. For Inline hooks, it detects CALLs and JMPs to direct and indirect locations, and it detects PUSH/RET instruction sequences. The special types of hooks that it detects include syscall hooking in ntdll.dll and calls to unknown code pages in kernel memory.

As of Volatility 2.1, apihooks also detects hooked winsock procedure tables, includes an easier to read output format, supports multiple hop disassembly, and can optionally scan quicker through memory by ignoring non-critical processes and DLLs.

Here is an example of detecting IAT hooks installed by Coreflood. The hooking module is unknown because there is no module (DLL) associated with the memory in which the rootkit code exists. If you want to extract the code containing the hooks, you have a few options:

1. See if [CommandReference21#malfind](CommandReference21#malfind.md) can automatically find and extract it.

2. Use [CommandReference21#volshell](CommandReference21#volshell.md) dd/db commands to scan backwards and look for an MZ header. Then pass that address to [CommandReference#dlldump](CommandReference#dlldump.md) as the --base value.

3. Use [CommandReference21#vaddump](CommandReference21#vaddump.md) to extract all code segments to individual files (named according to start and end address), then find the file that contains the 0x7ff82 ranges.

```
$ python vol.py -f coreflood.vmem -p 2044 apihooks 
Volatile Systems Volatility Framework 2.1_alpha
************************************************************************
Hook mode: Usermode
Hook type: Import Address Table (IAT)
Process: 2044 (IEXPLORE.EXE)
Victim module: iexplore.exe (0x400000 - 0x419000)
Function: kernel32.dll!GetProcAddress at 0x7ff82360
Hook address: 0x7ff82360
Hooking module: <unknown>

Disassembly(0):
0x7ff82360 e8fbf5ffff       CALL 0x7ff81960
0x7ff82365 84c0             TEST AL, AL
0x7ff82367 740b             JZ 0x7ff82374
0x7ff82369 8b150054fa7f     MOV EDX, [0x7ffa5400]
0x7ff8236f 8b4250           MOV EAX, [EDX+0x50]
0x7ff82372 ffe0             JMP EAX
0x7ff82374 8b4c2408         MOV ECX, [ESP+0x8]

************************************************************************
Hook mode: Usermode
Hook type: Import Address Table (IAT)
Process: 2044 (IEXPLORE.EXE)
Victim module: iexplore.exe (0x400000 - 0x419000)
Function: kernel32.dll!LoadLibraryA at 0x7ff82a50
Hook address: 0x7ff82a50
Hooking module: <unknown>

Disassembly(0):
0x7ff82a50 51               PUSH ECX
0x7ff82a51 e80aefffff       CALL 0x7ff81960
0x7ff82a56 84c0             TEST AL, AL
0x7ff82a58 7414             JZ 0x7ff82a6e
0x7ff82a5a 8b442408         MOV EAX, [ESP+0x8]
0x7ff82a5e 8b0d0054fa7f     MOV ECX, [0x7ffa5400]
0x7ff82a64 8b512c           MOV EDX, [ECX+0x2c]
0x7ff82a67 50               PUSH EAX

[snip]
```

Here is an example of detecting the Inline hooks installed by Silentbanker. Note the multiple hop disassembly which is new in 2.1. It shows the first hop of the hook at 0x7c81caa2 jumps to 0xe50000. Then you also see a disassembly of the code at 0xe50000 which executes the rest of the trampoline.

```
$ python vol.py -f silentbanker.vmem -p 1884 apihooks
Volatile Systems Volatility Framework 2.1_alpha
************************************************************************
Hook mode: Usermode
Hook type: Inline/Trampoline
Process: 1884 (IEXPLORE.EXE)
Victim module: kernel32.dll (0x7c800000 - 0x7c8f4000)
Function: kernel32.dll!ExitProcess at 0x7c81caa2
Hook address: 0xe50000
Hooking module: <unknown>

Disassembly(0):
0x7c81caa2 e959356384       JMP 0xe50000
0x7c81caa7 6aff             PUSH -0x1
0x7c81caa9 68b0f3e877       PUSH DWORD 0x77e8f3b0
0x7c81caae ff7508           PUSH DWORD [EBP+0x8]
0x7c81cab1 e846ffffff       CALL 0x7c81c9fc

Disassembly(1):
0xe50000 58               POP EAX
0xe50001 680500e600       PUSH DWORD 0xe60005
0xe50006 6800000000       PUSH DWORD 0x0
0xe5000b 680000807c       PUSH DWORD 0x7c800000
0xe50010 6828180310       PUSH DWORD 0x10031828
0xe50015 50               PUSH EAX

[snip]
```

Here is an example of detecting the PUSH/RET Inline hooks installed by Laqma:

```
$ python vol.py -f laqma.vmem -p 1624 apihooks
Volatile Systems Volatility Framework 2.1_alpha
************************************************************************
Hook mode: Usermode
Hook type: Inline/Trampoline
Process: 1624 (explorer.exe)
Victim module: USER32.dll (0x7e410000 - 0x7e4a0000)
Function: USER32.dll!MessageBoxA at 0x7e45058a
Hook address: 0xac10aa
Hooking module: Dll.dll

Disassembly(0):
0x7e45058a 68aa10ac00       PUSH DWORD 0xac10aa
0x7e45058f c3               RET
0x7e450590 3dbc04477e       CMP EAX, 0x7e4704bc
0x7e450595 00742464         ADD [ESP+0x64], DH
0x7e450599 a118000000       MOV EAX, [0x18]
0x7e45059e 6a00             PUSH 0x0
0x7e4505a0 ff               DB 0xff
0x7e4505a1 70               DB 0x70

Disassembly(1):
0xac10aa 53               PUSH EBX
0xac10ab 56               PUSH ESI
0xac10ac 57               PUSH EDI
0xac10ad 90               NOP
0xac10ae 90               NOP

[snip]
```

Here is an example of using apihooks to detect the syscall patches in ntdll.dll (using a Carberp sample):

```
$ python vol.py -f carberp.vmem -p 1004 apihooks
Volatile Systems Volatility Framework 2.1_alpha
************************************************************************
Hook mode: Usermode
Hook type: NT Syscall
Process: 1004 (explorer.exe)
Victim module: ntdll.dll (0x7c900000 - 0x7c9af000)
Function: NtQueryDirectoryFile
Hook address: 0x1da658f
Hooking module: <unknown>

Disassembly(0):
0x7c90d750 b891000000       MOV EAX, 0x91
0x7c90d755 ba84ddda01       MOV EDX, 0x1dadd84
0x7c90d75a ff12             CALL DWORD [EDX]
0x7c90d75c c22c00           RET 0x2c
0x7c90d75f 90               NOP
0x7c90d760 b892000000       MOV EAX, 0x92
0x7c90d765 ba               DB 0xba
0x7c90d766 0003             ADD [EBX], AL

Disassembly(1):
0x1da658f 58               POP EAX
0x1da6590 8d056663da01     LEA EAX, [0x1da6366]
0x1da6596 ffe0             JMP EAX
0x1da6598 c3               RET
0x1da6599 55               PUSH EBP
0x1da659a 8bec             MOV EBP, ESP
0x1da659c 51               PUSH ECX
0x1da659d 8365fc00         AND DWORD [EBP+0xfffffffc], 0x0
0x1da65a1 688f88d69b       PUSH DWORD 0x9bd6888f

[snip]
```

Here is an example of using apihooks to detect the Inline hook of a kernel mode function:

```
$ python vol.py apihooks -f rustock.vmem 
************************************************************************
Hook mode: Kernelmode
Hook type: Inline/Trampoline
Victim module: ntoskrnl.exe (0x804d7000 - 0x806cf980)
Function: ntoskrnl.exe!IofCallDriver at 0x804ee130
Hook address: 0xb17a189d
Hooking module: <unknown>

Disassembly(0):
0x804ee130 ff2580c25480     JMP DWORD [0x8054c280]
0x804ee136 cc               INT 3
0x804ee137 cc               INT 3
0x804ee138 cc               INT 3
0x804ee139 cc               INT 3
0x804ee13a cc               INT 3
0x804ee13b cc               INT 3
0x804ee13c 8bff             MOV EDI, EDI
0x804ee13e 55               PUSH EBP
0x804ee13f 8bec             MOV EBP, ESP
0x804ee141 8b4d08           MOV ECX, [EBP+0x8]
0x804ee144 83f929           CMP ECX, 0x29
0x804ee147 72               DB 0x72

Disassembly(1):
0xb17a189d 56               PUSH ESI
0xb17a189e 57               PUSH EDI
0xb17a189f 8bf9             MOV EDI, ECX
0xb17a18a1 8b7708           MOV ESI, [EDI+0x8]
0xb17a18a4 3b35ab6d7ab1     CMP ESI, [0xb17a6dab]
0xb17a18aa 7509             JNZ 0xb17a18b5
0xb17a18ac 52               PUSH EDX
0xb17a18ad 57               PUSH EDI
0xb17a18ae e8c6430000       CALL 0xb17a5c79
0xb17a18b3 eb6a             JMP 0xb17a191f
```

Here is an example of using apihooks to detect the calls to an unknown code page from a kernel driver. In this case, malware has patched tcpip.sys with some malicious redirections.

```
$ python vol.py -f rustock-c.vmem apihooks 
Volatile Systems Volatility Framework 2.1_alpha
************************************************************************
Hook mode: Kernelmode
Hook type: Unknown Code Page Call
Victim module: tcpip.sys (0xf7bac000 - 0xf7c04000)
Function: <unknown>
Hook address: 0x81ecd0c0
Hooking module: <unknown>

Disassembly(0):
0xf7be2514 ff15bcd0ec81     CALL DWORD [0x81ecd0bc]
0xf7be251a 817dfc03010000   CMP DWORD [EBP+0xfffffffc], 0x103
0xf7be2521 7506             JNZ 0xf7be2529
0xf7be2523 57               PUSH EDI
0xf7be2524 e8de860000       CALL 0xf7beac07
0xf7be2529 83               DB 0x83
0xf7be252a 66               DB 0x66
0xf7be252b 10               DB 0x10

Disassembly(1):
0x81ecd0c0 0e               PUSH CS
0x81ecd0c1 90               NOP
0x81ecd0c2 83ec04           SUB ESP, 0x4
0x81ecd0c5 c704246119c481   MOV DWORD [ESP], 0x81c41961
0x81ecd0cc cb               RETF

[snip]
```

## idt ##

To print the system's IDT (Interrupt Descriptor Table), use the idt command. If there are multiple processors on the system, the IDT for each individual CPU is displayed. You'll see the CPU number, the GDT selector, the current address and owning module, and the name of the PE section in which the IDT function resides. If you supply the --verbose parameter, a disassembly of the IDT function will be shown.

Some rootkits hook the IDT entry for KiSystemService, but point it at a routine inside the NT module (where KiSystemService should point). However, at that address, there is an Inline hook. The following output shows an example of how Volatility can point this out for you. Notice how the 0x2E entry for KiSystemService is in the .rsrc section of ntoskrnl.exe instead of .text like all others.

```
$ python vol.py -f rustock.vmem idt 
Volatile Systems Volatility Framework 2.1_alpha
   CPU  Index Selector Value      Module               Section     
------ ------ -------- ---------- -------------------- ------------
     0      0        8 0x8053e1cc ntoskrnl.exe         .text       
     0      1        8 0x8053e344 ntoskrnl.exe         .text       
     0      2       88 0x00000000 ntoskrnl.exe                     
     0      3        8 0x8053e714 ntoskrnl.exe         .text       
     0      4        8 0x8053e894 ntoskrnl.exe         .text       
     0      5        8 0x8053e9f0 ntoskrnl.exe         .text       
     0      6        8 0x8053eb64 ntoskrnl.exe         .text       
     0      7        8 0x8053f1cc ntoskrnl.exe         .text       
     0      8       80 0x00000000 ntoskrnl.exe                     
[snip]    
     0     2B        8 0x8053db10 ntoskrnl.exe         .text       
     0     2C        8 0x8053dcb0 ntoskrnl.exe         .text       
     0     2D        8 0x8053e5f0 ntoskrnl.exe         .text       
     0     2E        8 0x806b01b8 ntoskrnl.exe         .rsrc
[snip]
```

To get more details about the possible IDT modification, use --verbose:

```
$ python vol.py -f rustock.vmem idt --verbose
Volatile Systems Volatility Framework 2.1_alpha
   CPU  Index Selector Value      Module               Section     
------ ------ -------- ---------- -------------------- ------------
[snip]
     0     2E        8 0x806b01b8 ntoskrnl.exe         .rsrc       
0x806b01b8 e95c2c0f31       JMP 0xb17a2e19
0x806b01bd e9832c0f31       JMP 0xb17a2e45
0x806b01c2 4e               DEC ESI
0x806b01c3 44               INC ESP
0x806b01c4 4c               DEC ESP
0x806b01c5 45               INC EBP
0x806b01c6 44               INC ESP
0x806b01c7 5f               POP EDI
```

## gdt ##

To print the system's GDT (Global Descriptor Table), use the gdt command. This is useful for detecting rootkits like Alipop that install a call gate so that user mode programs can call directly into kernel mode (using a CALL FAR instruction).

If your system has multiple CPUs, the GDT for each processor is shown.

In the output below, you can see that selector 0x3e0 has been infected and used for the purposes of a 32-bit call gate. The call gate address is 0x8003f000, which is where execution continues.

```
$ python vol.py -f alipop.vmem gdt 
Volatile Systems Volatility Framework 2.1_alpha
   CPU        Sel Base            Limit Type              DPL Gr   Pr  
------ ---------- ---------- ---------- -------------- ------ ---- ----
     0        0x0 0x00ffdf0a     0xdbbb TSS16 Busy          2 By   P   
     0        0x8 0x00000000 0xffffffff Code RE Ac          0 Pg   P   
     0       0x10 0x00000000 0xffffffff Data RW Ac          0 Pg   P   
     0       0x18 0x00000000 0xffffffff Code RE Ac          3 Pg   P   
     0       0x20 0x00000000 0xffffffff Data RW Ac          3 Pg   P   
     0       0x28 0x80042000     0x20ab TSS32 Busy          0 By   P   
     0       0x30 0xffdff000     0x1fff Data RW Ac          0 Pg   P   
     0       0x38 0x00000000      0xfff Data RW Ac          3 By   P   
     0       0x40 0x00000400     0xffff Data RW             3 By   P   
     0       0x48 0x00000000        0x0 <Reserved>          0 By   Np 
[snip]
     0      0x3d0 0x00008003     0xf3d8 <Reserved>          0 By   Np  
     0      0x3d8 0x00008003     0xf3e0 <Reserved>          0 By   Np  
     0      0x3e0 0x8003f000        0x0 CallGate32          3 -    P   
     0      0x3e8 0x00000000 0xffffffff Code RE Ac          0 Pg   P   
     0      0x3f0 0x00008003     0xf3f8 <Reserved>          0 By   Np  
     0      0x3f8 0x00000000        0x0 <Reserved>          0 By   Np 
```

If you want to further investigate the infection, you can break into a [CommandReference21#volshell](CommandReference21#volshell.md) as shown below. Then disassemble code at the call gate address.

```
$ python vol.py -f alipop.vmem volshell
Volatile Systems Volatility Framework 2.1_alpha
Current context: process System, pid=4, ppid=0 DTB=0x320000
Welcome to volshell! Current memory image is:
file:///Users/Michael/Desktop/alipop.vmem
To get help, type 'hh()'

>>> dis(0xffdf0adb, length=32)
0xffdf0adb c8000000                         ENTER 0x0, 0x0
0xffdf0adf 31c0                             XOR EAX, EAX
0xffdf0ae1 60                               PUSHA
0xffdf0ae2 8b5508                           MOV EDX, [EBP+0x8]
0xffdf0ae5 bb00704d80                       MOV EBX, 0x804d7000
0xffdf0aea 8b4b3c                           MOV ECX, [EBX+0x3c]
0xffdf0aed 8b6c0b78                         MOV EBP, [EBX+ECX+0x78]

>>> db(0xffdf0adb + 75, length = 512)
ffdf0b26   d9 03 1c 81 89 5c 24 1c 61 c9 c2 04 00 7e 00 80    ......$.a....~..
ffdf0b36   00 3b 0b df ff 5c 00 52 00 65 00 67 00 69 00 73    .;.....R.e.g.i.s
ffdf0b46   00 74 00 72 00 79 00 5c 00 4d 00 61 00 63 00 68    .t.r.y...M.a.c.h
ffdf0b56   00 69 00 6e 00 65 00 5c 00 53 00 4f 00 46 00 54    .i.n.e...S.O.F.T
ffdf0b66   00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63    .W.A.R.E...M.i.c
ffdf0b76   00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57    .r.o.s.o.f.t...W
ffdf0b86   00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43    .i.n.d.o.w.s...C
ffdf0b96   00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65    .u.r.r.e.n.t.V.e
ffdf0ba6   00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75    .r.s.i.o.n...R.u
ffdf0bb6   00 6e 00 00 00 06 00 08 00 c3 0b df ff 71 00 51    .n...........q.Q
ffdf0bc6   00 00 00 43 00 3a 00 5c 00 57 00 49 00 4e 00 44    ...C.:...W.I.N.D
ffdf0bd6   00 4f 00 57 00 53 00 5c 00 61 00 6c 00 69 00 2e    .O.W.S...a.l.i..
ffdf0be6   00 65 00 78 00 65 00 00 00 26 00 28 00 f7 0b df    .e.x.e...&.(....
ffdf0bf6   ff 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 52    ...S.y.s.t.e.m.R
ffdf0c06   00 6f 00 6f 00 74 00 5c 00 61 00 6c 00 69 00 2e    .o.o.t...a.l.i..
ffdf0c16   00 65 00 78 00 65 00 00 00 00 00 e8 03 00 ec 00    .e.x.e..........
ffdf0c26   00 ff ff 00 00 00 9a cf 00 4d 5a 90 00 03 00 00    .........MZ.....
ffdf0c36   00 04 00 00 00 ff ff 00 00 b8 00 00 00 00 00 00    ................
ffdf0c46   00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00    .@..............
ffdf0c56   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
ffdf0c66   00 00 00 00 00 e0 00 00 00 0e 1f ba 0e 00 b4 09    ................
ffdf0c76   cd 21 b8 01 4c cd 21 54 68 69 73 20 70 72 6f 67    .!..L.!This prog
ffdf0c86   72 61 6d 20 63 61 6e 6e 6f 74 20 62 65 20 72 75    ram cannot be ru
ffdf0c96   6e 20 69 6e 20 44 4f 53 20 6d 6f 64 65 2e 0d 0d    n in DOS mode...
```

## threads ##

The command gives you extensive details on threads, including the contents of each thread's registers (if available), a disassembly of code at the thread's start address, and various other fields that may be relevant to an investigation. Since any given system has hundreds of threads, making it difficult to sort through, this command associates descriptive tags to the threads it finds - and then you can filter by tag name with the -F or --filter parameter.

To see a list of available tags/filters, use -L like this:

```
$ python vol.py -f test.vmem threads -L
Volatile Systems Volatility Framework 2.1_alpha
Tag                  Description
--------------       --------------
DkomExit             Detect inconsistencies wrt exit times and termination
HwBreakpoints        Detect threads with hardware breakpoints
ScannerOnly          Detect threads no longer in a linked list
HideFromDebug        Detect threads hidden from debuggers
OrphanThread         Detect orphan threads
AttachedProcess      Detect threads attached to another process
HookedSSDT           Detect threads using a hooked SSDT
SystemThread         Detect system threads
```

If you don't specify any filters, then the command will output information on all threads. Otherwise, you can specify a single filter or multiple filters separated by commas. Here is an example of hunting for threads that are currently executing in the context of a process other than the process which owns the thread:

```
$ python vol.py -f XPSP3.vmem threads -F AttachedProcess
Volatile Systems Volatility Framework 2.1_alpha
------
ETHREAD: 0x81eda7a0 Pid: 4 Tid: 484
Tags: SystemThread,AttachedProcess,HookedSSDT
Created: 2011-04-18 16:03:38
Exited: -
Owning Process: 0x823c8830 System
Attached Process: 0x81e3c458 services.exe
State: Running
BasePriority: THREAD_PRIORITY_NORMAL
TEB: 0x00000000
StartAddress: 0xb1805f1a windev-5e93-fd3.sys
ServiceTable: 0x80553020
[0] 0x80501bbc
[0x47] NtEnumerateKey 0xb1805944 windev-5e93-fd3.sys
[0x49] NtEnumerateValueKey 0xb1805aca windev-5e93-fd3.sys
[0x91] NtQueryDirectoryFile 0xb18055ee windev-5e93-fd3.sys
[1] -
[2] -
[3] -
Win32Thread: 0x00000000
CrossThreadFlags: PS_CROSS_THREAD_FLAGS_SYSTEM
b1805f1a: 8bff                         MOV EDI, EDI
b1805f1c: 55                           PUSH EBP
b1805f1d: 8bec                         MOV EBP, ESP
b1805f1f: 51                           PUSH ECX
b1805f20: 51                           PUSH ECX
```

First, you see the virtual address of the ETHREAD object along with the process ID and thread ID. Next you see all tags associated with the thread (SystemThread, AttachedProcess, !HookedSSDT), the creation/exit times, state, priority, start address, etc. It shows the SSDT base along with the address of each service table and any hooked functions in the tables. Finally, you see a disassembly of the thread's start address.

For a detailed description of each tag/filter and instructions on how to add your own heuristics to the threads command, see [Investigating Windows Threads with Volatility](http://mnin.blogspot.com/2011/04/investigating-windows-threads-with.html).

Note: with the introduction of this command, two older commands (orphan\_threads and ssdt\_by\_threads) have been deprecated.

## callbacks ##

Volatility is the only memory forensics platform with the ability to print an assortment of important notification routines and kernel callbacks. Rootkits, anti-virus suites, dynamic analysis tools (such as Sysinternals' Process Monitor and Tcpview), and many components of the Windows kernel use of these callbacks to monitor and/or react to events. We detect the following:

  * PsSetCreateProcessNotifyRoutine (process creation).
  * PsSetCreateThreadNotifyRoutine (thread creation).
  * PsSetImageLoadNotifyRoutine (DLL/image load).
  * IoRegisterFsRegistrationChange (file system registration).
  * KeRegisterBugCheck and KeRegisterBugCheckReasonCallback.
  * CmRegisterCallback (registry callbacks on XP).
  * CmRegisterCallbackEx (registry callbacks on Vista and 7).
  * IoRegisterShutdownNotification (shutdown callbacks).
  * DbgSetDebugPrintCallback (debug print callbacks on Vista and 7).
  * DbgkLkmdRegisterCallback (debug callbacks on 7).

Here's an example of detecting the thread creation callback installed by the BlackEnergy 2 malware. You can spot the malicious callback because the owner is 00004A2A - and BlackEnergy 2 uses a module name composed of eight hex characters.

```
$ python vol.py -f be2.vmem callbacks
Volatile Systems Volatility Framework 2.1_alpha
Type                                 Callback   Owner
PsSetCreateThreadNotifyRoutine       0xff0d2ea7 00004A2A
PsSetCreateProcessNotifyRoutine      0xfc58e194 vmci.sys
KeBugCheckCallbackListHead           0xfc1e85ed NDIS.sys (Ndis miniport)
KeBugCheckCallbackListHead           0x806d57ca hal.dll (ACPI 1.0 - APIC platform UP)
KeRegisterBugCheckReasonCallback     0xfc967ac0 mssmbios.sys (SMBiosData)
KeRegisterBugCheckReasonCallback     0xfc967a78 mssmbios.sys (SMBiosRegistry)
[snip]
```

Here is an example of detecting the malicious process creation callback installed by the Rustock rootkit (points to memory owned by \Driver\pe386).

```
$ python vol.py -f rustock.vmem callbacks
Volatile Systems Volatility Framework 2.1_alpha
Type                                 Callback   Owner
PsSetCreateProcessNotifyRoutine      0xf88bd194 vmci.sys
PsSetCreateProcessNotifyRoutine      0xb17a27ed '\\Driver\\pe386'
KeBugCheckCallbackListHead           0xf83e65ef NDIS.sys (Ndis miniport)
KeBugCheckCallbackListHead           0x806d77cc hal.dll (ACPI 1.0 - APIC platform UP)
KeRegisterBugCheckReasonCallback     0xf8b7aab8 mssmbios.sys (SMBiosData)
KeRegisterBugCheckReasonCallback     0xf8b7aa70 mssmbios.sys (SMBiosRegistry)
KeRegisterBugCheckReasonCallback     0xf8b7aa28 mssmbios.sys (SMBiosDataACPI)
KeRegisterBugCheckReasonCallback     0xf76201be USBPORT.SYS (USBPORT)
KeRegisterBugCheckReasonCallback     0xf762011e USBPORT.SYS (USBPORT)
KeRegisterBugCheckReasonCallback     0xf7637522 VIDEOPRT.SYS (Videoprt)
[snip]
```

Here is an example of detecting the malicious registry change callback installed by the Ascesso rootkit. There is one CmRegisterCallback pointing to 0x8216628f which does not have an owner. You also see two GenericKernelCallback with the same address. This is because notifyroutines finds callbacks in multiple ways. It combines list traversal and pool tag scanning. This way, if the list traversal fails, we can still find information with pool tag scanning. However, the Windows kernel uses the same types of pool tags for various callbacks, so we label those as generic.

```
$ python vol.py -f ascesso.vmem callbacks
Volatile Systems Volatility Framework 2.1_alpha
Type                                 Callback   Owner
IoRegisterShutdownNotification       0xf853c2be ftdisk.sys (\Driver\Ftdisk)
IoRegisterShutdownNotification       0x805f5d66 ntoskrnl.exe (\Driver\WMIxWDM)
IoRegisterShutdownNotification       0xf83d98f1 Mup.sys (\FileSystem\Mup)
IoRegisterShutdownNotification       0xf86aa73a MountMgr.sys (\Driver\MountMgr)
IoRegisterShutdownNotification       0x805cdef4 ntoskrnl.exe (\FileSystem\RAW)
CmRegisterCallback                   0x8216628f UNKNOWN (--)
GenericKernelCallback                0xf888d194 vmci.sys
GenericKernelCallback                0x8216628f UNKNOWN
GenericKernelCallback                0x8216628f UNKNOWN
```

## driverirp ##

To print a driver's IRP (Major Function) table, use the driverirp command. This command inherits from driverscan so that its able to locate DRIVER\_OBJECTs. Then it cycles through the function table, printing the purpose of each function, the function's address, and the owning module of the address.

Many drivers forward their IRP functions to other drivers for legitimate purposes, so detecting hooked IRP functions based on containing modules is not a good method. Instead, we print everything and let you be the judge. The command also checks for Inline hooks of IRP functions and optionally prints a disassembly of the instructions at the IRP address (pass -v or --verbose to enable this).

This command outputs information for all drivers, unless you specify a regular expression filter.

```
$ python vol.py -f tdl3.vmem driverirp -r vmscsi
Volatile Systems Volatility Framework 2.1_alpha
--------------------------------------------------
DriverName: vmscsi
DriverStart: 0xf9db8000
DriverSize: 0x2c00
DriverStartIo: 0xf97ea40e
   0 IRP_MJ_CREATE                        0xf9db9cbd vmscsi.sys
   1 IRP_MJ_CREATE_NAMED_PIPE             0xf9db9cbd vmscsi.sys
   2 IRP_MJ_CLOSE                         0xf9db9cbd vmscsi.sys
   3 IRP_MJ_READ                          0xf9db9cbd vmscsi.sys
   4 IRP_MJ_WRITE                         0xf9db9cbd vmscsi.sys
   5 IRP_MJ_QUERY_INFORMATION             0xf9db9cbd vmscsi.sys
   6 IRP_MJ_SET_INFORMATION               0xf9db9cbd vmscsi.sys
   7 IRP_MJ_QUERY_EA                      0xf9db9cbd vmscsi.sys
[snip]
```

In the output, it is not apparent that the vmscsi.sys driver has been infected by the TDL3 rootkit. Although all IRPs point back into vmscsi.sys, they point at a stub staged in that region by TDL3 for the exact purpose of bypassing rootkit detection tools. To get extended information, use --verbose:

```
$ python vol.py -f tdl3.vmem driverirp -r vmscsi --verbose
Volatile Systems Volatility Framework 2.1_alpha
--------------------------------------------------
DriverName: vmscsi
DriverStart: 0xf9db8000
DriverSize: 0x2c00
DriverStartIo: 0xf97ea40e
   0 IRP_MJ_CREATE                        0xf9db9cbd vmscsi.sys

0xf9db9cbd a10803dfff       MOV EAX, [0xffdf0308]
0xf9db9cc2 ffa0fc000000     JMP DWORD [EAX+0xfc]
0xf9db9cc8 0000             ADD [EAX], AL
0xf9db9cca 0000             ADD [EAX], AL

   1 IRP_MJ_CREATE_NAMED_PIPE             0xf9db9cbd vmscsi.sys
0xf9db9cbd a10803dfff       MOV EAX, [0xffdf0308]
0xf9db9cc2 ffa0fc000000     JMP DWORD [EAX+0xfc]
0xf9db9cc8 0000             ADD [EAX], AL
0xf9db9cca 0000             ADD [EAX], AL

[snip]
```

Now you can see that TDL3 redirects all IRPs to its own stub in the vmscsi.sys driver. That code jumps to whichever address is pointed to by 0xffdf0308 - a location in the KUSER\_SHARED\_DATA region.

## devicetree ##

Windows uses a layered driver architecture, or driver chain so that multiple drivers can inspect or respond to an IRP. Rootkits often insert drivers (or devices) into this chain for filtering purposes (to hide files, hide network connections, steal keystrokes or mouse movements). The devicetree plugin shows the relationship of a driver object to its devices (by walking `_DRIVER_OBJECT.DeviceObject.NextDevice`) and any attached devices (`_DRIVER_OBJECT.DeviceObject.AttachedDevice`).

In the example below, Stuxnet has infected \FileSystem\Ntfs by attaching a malicious unnamed device. Although the device itself is unnamed, the device object identifies its driver (\Driver\MRxNet).

```
$ python vol.py -f stuxnet.vmem devicetree
Volatile Systems Volatility Framework 2.1_alpha
[snip]
DRV 0x0253d180 '\\FileSystem\\Ntfs'
---| DEV 0x82166020 (unnamed) FILE_DEVICE_DISK_FILE_SYSTEM
------| ATT 0x8228c6b0 (unnamed) - '\\FileSystem\\sr' FILE_DEVICE_DISK_FILE_SYSTEM
---------| ATT 0x81f47020 (unnamed) - '\\FileSystem\\FltMgr' FILE_DEVICE_DISK_FILE_SYSTEM
------------| ATT 0x81fb9680 (unnamed) - '\\Driver\\MRxNet' FILE_DEVICE_DISK_FILE_SYSTEM
---| DEV 0x8224f790 Ntfs FILE_DEVICE_DISK_FILE_SYSTEM
------| ATT 0x81eecdd0 (unnamed) - '\\FileSystem\\sr' FILE_DEVICE_DISK_FILE_SYSTEM
---------| ATT 0x81e859c8 (unnamed) - '\\FileSystem\\FltMgr' FILE_DEVICE_DISK_FILE_SYSTEM
------------| ATT 0x81f0ab90 (unnamed) - '\\Driver\\MRxNet' FILE_DEVICE_DISK_FILE_SYSTEM
[snip]
```

The devicetree plugin uses "DRV" to indicate drivers, "DEV" to indicate devices, and "ATT" to indicate attached devices (just like OSR's DeviceTree utility).

The x64 version looks very similar:

```
$ /usr/bin/python2.6 vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 devicetreeVolatile Systems Volatility Framework 2.1_alpha
DRV 0x174c6350 \Driver\mouhid
---| DEV 0xfffffa8000dfbc90  FILE_DEVICE_MOUSE
------| ATT 0xfffffa8000ec7060  - \Driver\mouclass FILE_DEVICE_MOUSE
DRV 0x17660cb0 \Driver\rspndr
---| DEV 0xfffffa80005a1c20 rspndr FILE_DEVICE_NETWORK
DRV 0x17663e70 \Driver\lltdio
---| DEV 0xfffffa8000c78b70 lltdio FILE_DEVICE_NETWORK
DRV 0x17691d70 \Driver\cdrom
---| DEV 0xfffffa8000d00060 CdRom0 FILE_DEVICE_CD_ROM
DRV 0x176a7280 \FileSystem\Msfs
---| DEV 0xfffffa8000cac060 Mailslot FILE_DEVICE_MAILSLOT
DRV 0x176ac6f0 \FileSystem\Npfs
---| DEV 0xfffffa8000cac320 NamedPipe FILE_DEVICE_NAMED_PIPE
DRV 0x176ade70 \Driver\tdx
---| DEV 0xfffffa8000cb8c00 RawIp6 FILE_DEVICE_NETWORK
---| DEV 0xfffffa8000cb8e30 RawIp FILE_DEVICE_NETWORK
---| DEV 0xfffffa8000cb7510 Udp6 FILE_DEVICE_NETWORK
---| DEV 0xfffffa8000cb7740 Udp FILE_DEVICE_NETWORK
---| DEV 0xfffffa8000cb7060 Tcp6 FILE_DEVICE_NETWORK
---| DEV 0xfffffa8000cad140 Tcp FILE_DEVICE_NETWORK
---| DEV 0xfffffa8000cadbb0 Tdx FILE_DEVICE_TRANSPORT
DRV 0x176ae350 \Driver\Psched
---| DEV 0xfffffa8000cc4590 Psched FILE_DEVICE_NETWORK
DRV 0x176aee70 \Driver\WfpLwf
DRV 0x176b93a0 \Driver\AFD
---| DEV 0xfffffa8000cb9180 Afd FILE_DEVICE_NAMED_PIPE
DRV 0x176c28a0 \Driver\NetBT
---| DEV 0xfffffa8000db4060 NetBT_Tcpip_{EE0434CC-82D1-47EA-B5EB-AF721863ACC2} FILE_DEVICE_NETWORK
---| DEV 0xfffffa8000c1d8f0 NetBt_Wins_Export FILE_DEVICE_NETWORK
DRV 0x176c3930 \FileSystem\NetBIOS
---| DEV 0xfffffa8000cc3680 Netbios FILE_DEVICE_TRANSPORT
[snip]
```

## psxview ##

This plugin helps you detect hidden processes by comparing what  PsActiveProcessHead contains with what is reported by various other sources of process listings. It compares the following:

  * PsActiveProcessHead linked list
  * EPROCESS pool scanning
  * ETHREAD pool scanning (then it references the owning EPROCESS)
  * PspCidTable
  * Csrss.exe handle table
  * Csrss.exe internal linked list

On Windows Vista and Windows 7 the internal list of processes in csrss.exe is not available. It also may not be available in some XP images where certain pages are not memory resident.

Here is an example of detecting the Prolaco malware with psxview. A "False" in any column indicates that the respective process is missing. You can tell "1\_doc\_RCData\_61" is suspicious since it shows up in every column except pslist (PsActiveProcessHead).

```
$ python vol.py -f prolaco.vmem psxview
Volatile Systems Volatility Framework 2.1_alpha
Offset(P)  Name                    PID pslist psscan thrdproc pspcdid csrss
---------- -------------------- ------ ------ ------ -------- ------- -----
0x06499b80 svchost.exe            1148 True   True   True     True    True 
0x04b5a980 VMwareUser.exe          452 True   True   True     True    True 
0x0655fc88 VMUpgradeHelper        1788 True   True   True     True    True 
0x0211ab28 TPAutoConnSvc.e        1968 True   True   True     True    True 
0x04c2b310 wscntfy.exe             888 True   True   True     True    True 
0x061ef558 svchost.exe            1088 True   True   True     True    True 
0x06945da0 spoolsv.exe            1432 True   True   True     True    True 
0x05471020 smss.exe                544 True   True   True     True    False
0x04a544b0 ImmunityDebugge        1136 True   True   True     True    True 
0x069d5b28 vmtoolsd.exe           1668 True   True   True     True    True 
0x06384230 vmacthlp.exe            844 True   True   True     True    True 
0x010f7588 wuauclt.exe             468 True   True   True     True    True 
0x066f0da0 csrss.exe               608 True   True   True     True    False
0x05f027e0 alg.exe                 216 True   True   True     True    True 
0x06015020 services.exe            676 True   True   True     True    True 
0x04a065d0 explorer.exe           1724 True   True   True     True    True 
0x049c15f8 TPAutoConnect.e        1084 True   True   True     True    True 
0x0115b8d8 svchost.exe             856 True   True   True     True    True 
0x01214660 System                    4 True   True   True     True    False
0x01122910 svchost.exe            1028 True   True   True     True    True 
0x04be97e8 VMwareTray.exe          432 True   True   True     True    True 
0x05f47020 lsass.exe               688 True   True   True     True    True 
0x063c5560 svchost.exe             936 True   True   True     True    True 
0x066f0978 winlogon.exe            632 True   True   True     True    True 
0x0640ac10 msiexec.exe            1144 False  True   False    False   False
0x005f23a0 rundll32.exe           1260 False  True   False    False   False
0x0113f648 1_doc_RCData_61        1336 False  True   True     True    True 
```

The output looks similar for x64 systems:

```
$ python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 psxview
Volatile Systems Volatility Framework 2.1_alpha
Offset(P)          Name                    PID pslist psscan thrdproc pspcdid csrss
------------------ -------------------- ------ ------ ------ -------- ------- -----
0x00000000173c5700 lsass.exe               444 True   True   True     True    True 
0x00000000176006c0 csrss.exe               296 True   True   True     True    False
0x0000000017803b30 rundll32.exe           2016 True   True   True     True    True 
0x0000000017486690 spoolsv.exe            1076 True   True   True     True    True 
0x0000000017db7960 svchost.exe             856 True   True   True     True    True 
0x0000000017dd09e0 svchost.exe             916 True   True   True     True    True 
0x0000000017606b30 csrss.exe               344 True   True   True     True    False
0x000000001769a630 regsvr32.exe           1180 True   True   False    True    False
0x0000000017692300 wininit.exe             332 True   True   True     True    True 
[snip]
```

## timers ##

This command prints installed kernel timers (KTIMER) and any associated DPCs (Deferred Procedure Calls). Rootkits such as Zero Access, Rustock, and Stuxnet register timers with a DPC. Although the malware tries to be stealthy and hide in kernel space in a number of different ways, by finding the KTIMERs and looking at the address of the DPC, you can quickly find the malicious code ranges.

Here's an example. Notice how one of the timers has an UNKNOWN module (the DPC points to an unknown region of kernel memory). This is ultimately where the rootkit is hiding.

```
$ python vol.py -f rustock-c.vmem timers
Volatile Systems Volatility Framework 2.1_alpha
Offset(V)  DueTime                  Period(ms) Signaled   Routine    Module
---------- ------------------------ ---------- ---------- ---------- ------
0xf730a790 0x00000000:0x6db0f0b4             0 -          0xf72fb385 srv.sys
0x80558a40 0x00000000:0x68f10168          1000 Yes        0x80523026 ntoskrnl.exe
0x821cb240 0x00000000:0x68fa8ad0             0 -          0xf84b392e sr.sys
0x8054f288 0x00000000:0x69067692             0 -          0x804e5aec ntoskrnl.exe
0xf7c13fa0 0x00000000:0x74f6fd46         60000 Yes        0xf7c044d3 ipsec.sys
0xf7c13b08 0x00000000:0x74f6fd46             0 -          0xf7c04449 ipsec.sys
0x8055a300 0x00000008:0x61e82b46             0 -          0x80533bf8 ntoskrnl.exe
0xf7c13b70 0x00000008:0x6b719346             0 -          0xf7c04449 ipsec.sys
0xf7befbf0 0x00000000:0x690d9da0             0 -          0xf89aa3f0 TDI.SYS
0x81ea5ee8 0x00000000:0x7036f590             0 -          0x80534016 ntoskrnl.exe
0x81d69180 0x80000000:0x3ae334ee             0 -          0x80534016 ntoskrnl.exe
0xf70d0040 0x00000000:0x703bd2ae             0 -          0xf70c3ae8 HTTP.sys
0xf7a74260 0x00000000:0x75113724         60000 Yes        0xf7a6cf98 ipnat.sys
0x82012e08 0x00000000:0x8a87d2d2             0 -          0xf832653c ks.sys
0x81f01358 0x00000008:0x6b97b8e6             0 -          0xf7b8448a netbt.sys
0x81f41218 0x00000000:0x6933c340             0 -          0xf7b8448a netbt.sys
0x805508d0 0x00000000:0x6ba6cdb6         60000 Yes        0x804f3b72 ntoskrnl.exe
0x80559160 0x00000000:0x695c4b3a             0 -          0x80526bac ntoskrnl.exe
0x820822e4 0x00000000:0xa2a56bb0        150000 Yes        0x81c1642f UNKNOWN
0xf842f150 0x00000000:0xb5cb4e80             0 -          0xf841473e Ntfs.sys
0x821811b0 0x00000131:0x34c6cb8e             0 -          0xf83fafdf NDIS.sys
...
```

Please note: the timers are enumerated in different ways depending on the target operating system. Windows stores the timers in global variables for XP, 2003, 2008, and Vista. Since Windows 7, the timers are are in processor-specific regions off of KPCR (Kernel Processor Control Region). As of Volatility 2.1, if there are multiple CPUs, the timers plugin finds all KPCRs and prints the timers associated with each CPU.

For more information on timer objects, see [Ain't Nuthin But a K(Timer) Thing, Baby](http://mnin.blogspot.com/2011/10/aint-nuthin-but-ktimer-thing-baby.html).

# Miscellaneous #

## strings ##

For a given image and a file with lines of the form `<decimal_offset>:<string>`,
output the corresponding process and virtual addresses where that
string can be found. Expected input for this tool is the output of
[Microsoft Sysinternals' Strings utility](http://technet.microsoft.com/en-us/sysinternals/bb897439), or another utility that
provides similarly formatted offset:string mappings. Note that the
input offsets are physical offsets from the start of the file/image.

Sysinternals Strings can be used on Linux/Mac using [Wine](http://www.winehq.org/).  Output should be redirected to a file to be fed to the Volatility strings plugin. If you're using GNU strings command, use the -td flags to produce offsets in decimal (the plugin does not accept hex offsets). Some example usages are as follows:

**Windows**

```
C:\> strings.exe –q –o -accepteula win7.dd > win7_strings.txt
```

**Linux/Mac**

```
$ wine strings.exe –q –o -accepteula win7.dd > win7_strings.txt
```

It can take a while for the Sysinternals strings program to finish. The –q and –o switches are imperative, since they make sure the header is not output (-q) and that there is an offset for each line (-o).
The result should be a text file that contains the offset and strings from the image for example:

```
16392:@@@
17409:
17441:!!!
17473:""" 
17505:###
17537:$$$
17569:%%%
17601:&&&
17633:'''
17665:(((
17697:)))
17729:***
```

**EnCase Keyword Export**

You can also use EnCase to export keywords and offsets in this format with some tweaking.  One thing to note is that EnCase exports text in UTF-16 with a BOM of (U+FEFF) which can cause issues with the `strings` plugin.  An example look at the exported keyword file:

```
File Offset Hit Text
114923  DHCP
114967  DHCP
115892  DHCP
115922  DHCP
115952  DHCP
116319  DHCP

[snip]
```

Now tweaking the file by removing the header and tabs we have:

```
114923:DHCP
114967:DHCP
115892:DHCP
115922:DHCP
115952:DHCP
116319:DHCP

[snip]
```

We can see that it is UTF-16 and has a BOM of (U+FEFF) by using a hex editor.

```
$ file export.txt 
export.txt: Little-endian UTF-16 Unicode text, with CRLF, CR line terminators

$ xxd export.txt |less

0000000: fffe 3100 3100 3400 3900 3200 3300 3a00  ..1.1.4.9.2.3.:.

[snip]
```

We have to convert this to ANSI or UTF-8.  In Windows you can open the text file and use the "Save As" dialog to save the file as ANSI (in the "Encoding" drop-down menu).  In Linux you can use `iconv`:

```
$ iconv -f UTF-16 -t UTF-8 export.txt > export1.txt
```

**NOTE:** You must make sure there are NO blank lines in your final "strings" file.

Now we can see a difference in how these two files are handled:

```
$ ./vol.py -f Bob.vmem --profile=WinXPSP2x86 strings -s export.txt 
Volatile Systems Volatility Framework 2.1_alpha
ERROR   : volatility.plugins.strings: String file format invalid.

$ ./vol.py -f Bob.vmem --profile=WinXPSP2x86 strings -s export1.txt 
Volatile Systems Volatility Framework 2.1_alpha
0001c0eb [kernel:2147598571] DHCP
0001c117 [kernel:2147598615] DHCP
0001c4b4 [kernel:2147599540] DHCP
0001c4d2 [kernel:2147599570] DHCP
0001c4f0 [kernel:2147599600] DHCP
0001c65f [kernel:2147599967] DHCP
0001c686 [kernel:2147600006] DHCP

[snip]
```

**NOTE:** The Volatility strings output is very verbose and it is best to redirect or save to a file.  The following command saves the output using the `--output-file` option and filename "win7\_vol\_strings.txt"

```
$ python vol.py --profile=Win7SP0x86 strings –f win7.dd –s win7_strings.txt --output-file=win7_vol_strings.txt
```

By default `strings` will only provide output for processes found by walking the doubly linked list pointed to by PsActiveProcessHead (see [pslist](http://code.google.com/p/volatility/wiki/CommandReference#pslist)) in addition to kernel addresses.  `strings` can also provide output for hidden processes (see [psscan](http://code.google.com/p/volatility/wiki/CommandReference#psscan)) by using the (capital) -S switch:

```
$ python vol.py --profile=Win7SP0x86 strings –f win7.dd –s win7_strings.txt --output-file=win7_vol_strings.txt -S 
```

Also an EPROCESS offset can be provided:

```
$ python vol.py --profile=Win7SP0x86 strings –f win7.dd –s win7_strings.txt --output-file=win7_vol_strings.txt -o 0x04a291a8
```

The strings plugin takes a while to complete. When it completes, you should have an output file with each line in the following format:

```
physical_address [kernel_or_pid:virtual_address] string
```

In the example output you can see PIDs/kernel references:

```
$ less win7_vol_strings.txt

000003c1 [kernel:4184445889] '<'@
00000636 [kernel:4184446518] 8,t
000006c1 [kernel:4184446657] w#r
000006d8 [kernel:4184446680] sQOtN2
000006fc [kernel:4184446716] t+a`j
00000719 [kernel:4184446745] aas
0000072c [kernel:4184446764] Invalid partition ta
00000748 [kernel:4184446792] r loading operating system
00000763 [kernel:4184446819] Missing operating system
000007b5 [kernel:4184446901] ,Dc
0000400b [kernel:2147500043 kernel:4184461323] 3TYk
00004056 [kernel:2147500118 kernel:4184461398] #:s
000040b0 [kernel:2147500208 kernel:4184461488] CO0
000040e9 [kernel:2147500265 kernel:4184461545] BrvWo
000040f0 [kernel:2147500272 kernel:4184461552] %Sz
000040fc [kernel:2147500284 kernel:4184461564] A0?0=
00004106 [kernel:2147500294 kernel:4184461574] 7http://crl.microsoft.com/pki/crl/products/WinIntPCA.crl0U

[snip]

00369f14 [1648:1975394068] Ph$!
00369f2e [1648:1975394094] 9}$
00376044 [1372:20422724] Ju0w
0037616d [1372:20423021] msxml6.dll
003761e8 [1372:20423144] U'H
003762e3 [1372:20423395] }e_
0037632e [1372:20423470] xnA

[snip]

03678031 [360:2089816113 596:2089816113 620:2089816113 672:2089816113 684:2089816113 844:2089816113 932:2089816113 1064:2089816113 1164:2089816113 1264:2089816113 1516:2089816113 1648
:2089816113 1896:2089816113 1904:2089816113 1756:2089816113 512:2089816113 1372:2089816113 560:2089816113] A$9B
```

Once you have the strings output, you can see which process(es) have the suspicious string in memory and can then narrow your focus. You can grep for the string or pattern depending on the context you were given. For example, if you are looking for a particular command:

```
$ grep [command or pattern] win7_vol_strings.txt > strings_of_interest.txt
```

For all IPs:
```
$ cat win7_vol_strings.txt | \
perl -e 'while(<>){if(/(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/){print $_;}}' > IPs.txt
```

For all URLs:
```
$ cat win7_vol_strings.txt | \
perl -e 'while(<>){ if(/(http|https|ftp|mail)\:[\/\w.]+/){print $_;}}' > URLs.txt
```

Depending on the context, your searches will vary.


## volshell ##

If you want to interactively explore a memory image, use the volshell command. This gives you an interface similar to WinDbg into the memory dump. For example, you can:

  * List processes
  * Switch into a process's context
  * Display types of structures/objects
  * Overlay a type over a given address
  * Walk linked lists
  * Disassemble code at a given address

Note: volshell can take advantage of [IPython](http://ipython.org/) if you have it installed. This will add tab-completion and saved command history.

To break into a volshell:

```
$ python vol.py --profile=Win7SP0x86 -f win7.dmp volshell
Volatile Systems Volatility Framework 2.0
Current context: process System, pid=4, ppid=0 DTB=0x185000
Welcome to volshell! Current memory image is:
file:///Users/M/Desktop/win7.dmp
To get help, type 'hh()'
>>> hh()
ps()                                     : Print a process listing.
cc(offset=None, pid=None, name=None)     : Change current shell context.
dd(address, length=128, space=None)      : Print dwords at address.
db(address, length=128, width=16, space=None) : Print bytes as canonical hexdump.
hh(cmd=None)                             : Get help on a command.
dt(objct, address=None, address_space=None)  : Describe an object or show type info.
list_entry(head, objname, offset=-1, fieldname=None, forward=True) : Traverse a _LIST_ENTRY.
dis(address, length=128, space=None)     : Disassemble code at a given address.

For help on a specific command, type 'hh(<command>)'
>>> 
```

Let's say you want to see what's at 0x779f0000 in the memory of explorer.exe. First display the processes so you can get the PID or offset of Explorer's EPROCESS. (Note: if you want to view data in kernel memory, you do not need to switch contexts first.)

```
>>> ps()
Name             PID    PPID   Offset  
System           4      0      0x83dad960
smss.exe         252    4      0x84e47840
csrss.exe        348    340    0x8d5ffd40
wininit.exe      384    340    0x84e6e3d8
csrss.exe        396    376    0x8d580530
winlogon.exe     424    376    0x8d598530
services.exe     492    384    0x8d4cc030
lsass.exe        500    384    0x8d6064a0
lsm.exe          508    384    0x8d6075d8
svchost.exe      616    492    0x8d653030
svchost.exe      680    492    0x8d673b88
svchost.exe      728    492    0x8d64fb38
taskhost.exe     1156   492    0x8d7ee030
dwm.exe          956    848    0x8d52bd40
explorer.exe     1880   1720   0x8d66c1a8
wuauclt.exe      1896   876    0x83ec3238
VMwareTray.exe   2144   1880   0x83f028d8
VMwareUser.exe   2156   1880   0x8d7893b0
[snip]
```

Now switch into Explorer's context and print the data with either db (display as canonical hexdump) or dd (display as double-words):

```
>>> dd(0x779f0000)
779f0000  00905a4d 00000003 00000004 0000ffff
779f0010  000000b8 00000000 00000040 00000000
779f0020  00000000 00000000 00000000 00000000
779f0030  00000000 00000000 00000000 000000e0
779f0040  0eba1f0e cd09b400 4c01b821 685421cd
779f0050  70207369 72676f72 63206d61 6f6e6e61
779f0060  65622074 6e757220 206e6920 20534f44
779f0070  65646f6d 0a0d0d2e 00000024 00000000
>>> db(0x779f0000)
779f0000   4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00    MZ..............
779f0010   b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00    ........@.......
779f0020   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
779f0030   00 00 00 00 00 00 00 00 00 00 00 00 e0 00 00 00    ................
779f0040   0e 1f ba 0e 00 b4 09 cd 21 b8 01 4c cd 21 54 68    ........!..L.!Th
779f0050   69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f    is program canno
779f0060   74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20    t be run in DOS 
779f0070   6d 6f 64 65 2e 0d 0d 0a 24 00 00 00 00 00 00 00    mode....$.......
```

So there is a PE at 0x779f0000 in explorer.exe. If you want to disassemble instructions at RVA 0x2506 in the PE, do this:

```
>>> dis(0x779f0000 + 0x2506)
0x779f2506 8d0c48                           LEA ECX, [EAX+ECX*2]
0x779f2509 8b4508                           MOV EAX, [EBP+0x8]
0x779f250c 8b4c4802                         MOV ECX, [EAX+ECX*2+0x2]
0x779f2510 8d0448                           LEA EAX, [EAX+ECX*2]
0x779f2513 e9c07f0300                       JMP 0x77a2a4d8
0x779f2518 85f6                             TEST ESI, ESI
0x779f251a 0f85c12c0700                     JNZ 0x77a651e1
0x779f2520 8b4310                           MOV EAX, [EBX+0x10]
0x779f2523 8b407c                           MOV EAX, [EAX+0x7c]
0x779f2526 8b4b18                           MOV ECX, [EBX+0x18]
0x779f2529 0fb7444102                       MOVZX EAX, [ECX+EAX*2+0x2]
0x779f252e 894520                           MOV [EBP+0x20], EAX
[snip]
```

If you want to remind yourself of the members in an EPROCESS object for the given OS, do this:

```
>>> dt("_EPROCESS")
'_EPROCESS' (704 bytes)
0x0   : Pcb                            ['_KPROCESS']
0x98  : ProcessLock                    ['_EX_PUSH_LOCK']
0xa0  : CreateTime                     ['_LARGE_INTEGER']
0xa8  : ExitTime                       ['_LARGE_INTEGER']
0xb0  : RundownProtect                 ['_EX_RUNDOWN_REF']
0xb4  : UniqueProcessId                ['pointer', ['void']]
0xb8  : ActiveProcessLinks             ['_LIST_ENTRY']
0xc0  : ProcessQuotaUsage              ['array', 2, ['unsigned long']]
0xc8  : ProcessQuotaPeak               ['array', 2, ['unsigned long']]
0xd0  : CommitCharge                   ['unsigned long']
0xd4  : QuotaBlock                     ['pointer', ['_EPROCESS_QUOTA_BLOCK']]
[snip]
```

To overlay the EPROCESS types onto the offset for explorer.exe, do this:

```
>>> dt("_EPROCESS", 0x8d66c1a8)
[_EPROCESS _EPROCESS] @ 0x8D66C1A8
0x0   : Pcb                            2372321704
0x98  : ProcessLock                    2372321856
0xa0  : CreateTime                     2010-07-06 22:38:07 
0xa8  : ExitTime                       1970-01-01 00:00:00 
0xb0  : RundownProtect                 2372321880
0xb4  : UniqueProcessId                1880
0xb8  : ActiveProcessLinks             2372321888
0xc0  : ProcessQuotaUsage              -
0xc8  : ProcessQuotaPeak               -
0xd0  : CommitCharge                   4489
0xd4  : QuotaBlock                     2372351104
[snip]
```

The db, dd, dt, and dis commands all accept an optional "space" parameter which allows you to specify an address space. You will see different data depending on which address space you're using. Volshell has some defaults and rules that are important to note:

  * If you don't supply an address space and **have not** switched into a process context with cc, then you'll be using the default kernel space (System process).

  * If you don't supply an address space and **have** switched into a process context with cc, then you'll be using the space of the active/current process.

  * If you explicitly supply an address space, the one you supplied will be used.

Imagine you're using one of the scan commands (psscan, connscan, etc.) and you think it has picked up a false positive. The scan commands output a physical offset (offset into the memory dump file). You want to explore the data around the potential false positive to determine for yourself if any structure members appear sane or not. One way you could do that is by opening the memory dump in a hex viewer and going to the physical offset to view the raw bytes. However, a better way is to use volshell and overlay the structure question to the alleged physical offset. This allows you to see the fields interpreted as their intended type (DWORD, string, short, etc.)

Here's an example. First instantiate a physical address space:

```
>>> physical_space = utils.load_as(self._config, astype = 'physical')
```

Assuming the alleged false positive for an EPROCESS is at 0x433308, you would then do:

```
>>> dt("_EPROCESS", 0x433308, physical_space)
[_EPROCESS _EPROCESS] @ 0x00433308
0x0   : Pcb                            4403976
0x6c  : ProcessLock                    4404084
0x70  : CreateTime                     1970-01-01 00:00:00 
0x78  : ExitTime                       1970-01-01 00:00:00
...
```

Another neat trick is to use volshell in a non-interactive manner. For example, say you want to translate an address in kernel memory to its corresponding physical offset.

```
$ echo "hex(self.addrspace.vtop(0x823c8830))" | python vol.py -f stuxnet.vmem volshell
Volatile Systems Volatility Framework 2.1_alpha
Current context: process System, pid=4, ppid=0 DTB=0x319000
Welcome to volshell! Current memory image is:
file:///mem/stuxnet.vmem
To get help, type 'hh()'
>>> '0x25c8830'
```

Thus the kernel address 0x823c8830 translates to physical offset 0x25c8830 in the memory dump file.

You can execute multiple commands sequentially like this:

```
$ echo "cc(pid=4); dd(0x10000)" | [...]
```

For more information, see BDG's [Introducing Volshell](http://moyix.blogspot.com/2008/08/indroducing-volshell.html).

## bioskbd ##

To read keystrokes from the BIOS area of memory, use the bioskbd command. This can reveal passwords typed into HP, Intel, and Lenovo BIOS and SafeBoot, TrueCrypt, and BitLocker software. Depending on the tool used to acquire memory, not all memory samples will contain the necessary BIOS area. For more information, see Andreas Schuster's [Reading Passwords From the Keyboard Buffer](http://computer.forensikblog.de/en/2009/04/read_password_from_keyboard_buffer.html#more), David Sharpe's [Duplicating Volatility Bioskbd Command Function on Live Windows Systems](http://blog.sharpesecurity.com/2011/05/09/duplicating-volatility-bioskbd-command-function-on-live-windows-systems/), and Jonathan Brossard's [Bypassing pre-boot authentication passwords by instrumenting the BIOS keyboard buffer](http://www.ivizsecurity.com/research/preboot/preboot_whitepaper.pdf).

## patcher ##

The patcher plugin accepts a single argument of '-x' followed by an XML file.  The XML file then specifies any required patches as in the following example:

```
<patchfile>
  <patchinfo method="pagescan" name="Some Descriptive Name">
    <constraints>
      <match offset="0x123">554433221100</match>
    </constraints>
    <patches>
      <setbytes offset="0x234">001122334455</setbytes>
    </patches>
  </patchinfo>
  <patchinfo>
    ...
  </patchinfo>
</patchfile>
```

The XML root element is always `patchfile`, and contains any number of `patchinfo` elements.  When the patchfile is run, it will scan over the memory once for each `patchinfo`, attempting to scan using the method specified in the `method` attribute.  Currently the only support method is `pagescan` and this must be explicitly declared in each `patchinfo` element.

Each `pagescan` type `patchinfo` element contains a single `constraints` element and a single `patches` element.  The scan then proceeds over each page in memory, verifying that all constraints are met, and if so, the instructions specified in the `patches` element are carried out.

The `constraints` element contains any number of `match` elements which take a specific offset attribute (specifying where within the page the match should occur) and then contain a hexadecimal string for the bytes that are supposed to match.

The `patches` element contains any number of `setbytes` elements which take a specific offset attribute (specifying where with the page the patch should modify data) and then contains a hexidecimal string for the bytes that should be written into the page.

Note: When running the patcher plugin, there will be no modification made to memory unless the **write** option (-w) has been specified on the command line.

## pagecheck ##

The pagecheck plugin uses a kernel DTB (from the System/Idle process) and determines which pages should be memory resident (using the AddressSpace.get\_available\_pages method). For each page, it attempts to access the page data and reports details, such as the PDE and PTE addresses if the attempt fails. This is a diagnostic plugin, usually helpful in troubleshooting "holes" in an address space.

This plugin is not well-supported. It is in the contrib directory and currently only works with non-PAE x86 address spaces.

```
$ python vol.py --plugins=contrib/plugins/ -f pat-2009-11-16.mddramimage pagecheck
Volatile Systems Volatility Framework 2.1_rc1
(V): 0x06a5a000 [PDE] 0x038c3067 [PTE] 0x1fe5e047 (P): 0x1fe5e000 Size: 0x00001000
(V): 0x06c5f000 [PDE] 0x14d62067 [PTE] 0x1fe52047 (P): 0x1fe52000 Size: 0x00001000
(V): 0x06cd5000 [PDE] 0x14d62067 [PTE] 0x1fe6f047 (P): 0x1fe6f000 Size: 0x00001000
(V): 0x06d57000 [PDE] 0x14d62067 [PTE] 0x1fe5c047 (P): 0x1fe5c000 Size: 0x00001000
(V): 0x06e10000 [PDE] 0x14d62067 [PTE] 0x1fe62047 (P): 0x1fe62000 Size: 0x00001000
(V): 0x070e4000 [PDE] 0x1cac7067 [PTE] 0x1fe1e047 (P): 0x1fe1e000 Size: 0x00001000
(V): 0x077a8000 [PDE] 0x1350a067 [PTE] 0x1fe06047 (P): 0x1fe06000 Size: 0x00001000
(V): 0x07a41000 [PDE] 0x05103067 [PTE] 0x1fe05047 (P): 0x1fe05000 Size: 0x00001000
(V): 0x07c05000 [PDE] 0x103f7067 [PTE] 0x1fe30047 (P): 0x1fe30000 Size: 0x00001000
...
```