

# Image Identification #

## imageinfo ##

If you don't know what type of system your image came from, use the imageinfo command.

```
$ python vol.py -f win7.dmp imageinfo
Volatile Systems Volatility Framework 2.0
Determining profile based on KDBG search...
             Suggested Profile : Win7SP1x86, Win7SP0x86
                     AS Layer1 : JKIA32PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (/Users/M/Desktop/win7.dmp)
                      PAE type : No PAE
                           DTB : 0x185000
                          KDBG : 0x8296cbe8
                          KPCR : 0x8296dc00
             KUSER_SHARED_DATA : 0xffdf0000
           Image date and time : 2010-07-06 22:40:28 
     Image local date and time : 2010-07-06 22:40:28 
          Number of Processors : 2
                    Image Type : 
```

Among other things, the `imageinfo` output tells you the suggested profile that you should pass as the parameter to --profile=PROFILE; there may be more than one profile suggestion if profiles are closely related.  You can figure out which one is more appropriate by checking the "Image Type" field, which is blank for Service Pack 0 and filled in for other Service Packs.  The `imageinfo` output also tells you the address of the KPCR and KDBG (short for `_KDDEBUGGER_DATA64`).  Plugins automatically scan for these values when they need them, however you can specify them directly for any plugin by providing --kpcr=ADDRESS or --kdbg=ADDRESS. By supplying the profile and KDBG (or failing that KPCR) to other Volatility commands, you'll get the most accurate and fastest results possible.

## kdbgscan ##

Use this command to scan for potential KDBG structures. For more information on how KDBG structures are identified read [Finding Kernel Global Variables in Windows](http://moyix.blogspot.com/2008/04/finding-kernel-global-variables-in.html) and [Identifying Memory Images](http://gleeda.blogspot.com/2010/12/identifying-memory-images.html)

```
$ python vol.py --profile=Win7SP0x86 -f win7.dmp kdbgscan
Volatile Systems Volatility Framework 2.0
Potential KDBG structure addresses (P = Physical, V = Virtual):
 _KDBG: V 0x80544ce0  (WinXPSP3x86)
 _KDBG: P 0x00544ce0  (WinXPSP3x86)
 _KDBG: V 0x80544ce0  (WinXPSP2x86)
 _KDBG: P 0x00544ce0  (WinXPSP2x86)
```

## kprcscan ##

Use this command to scan for potential KPCR structures. On a multi-core system, each processor has its own KPCR. Therefore, you'll should see **at least** as many KPCR addresses as there are processors on the machine from which the memory dump was acquired.

For information on how potential KPCR structures are found, read [Finding Object Roots in Vista](http://blog.schatzforensic.com.au/2010/07/finding-object-roots-in-vista-kpcr/).

```
$ python vol.py --profile=Win7SP0x86 -f win7.dmp kpcrscan
Volatile Systems Volatility Framework 2.0
Potential KPCR structure virtual addresses:
 _KPCR: 0x8296dc00
```

An example of a multi-core system:

```
$ python vol.py --profile=Win7SP0x86 -f mem.dmp kpcrscan
Volatile Systems Volatility Framework 2.1_alpha
Potential KPCR structure virtual addresses:
 _KPCR: 0x807c3000
 _KPCR: 0x8296fc00
 _KPCR: 0x8cd00000
 _KPCR: 0x8cd36000
```

Some plugins such as [idt](http://code.google.com/p/volatility/wiki/CommandReference#idt) and [timers](http://code.google.com/p/volatility/wiki/CommandReference#timers) reference fields in a processor's KPCR. Thus to be thorough, for example if you want to print the Interrupt Descriptor Table for all processors, you should run kpcrscan first and then pass each address to the plugin along with the --kpcr parameter.

# Processes and DLLs #

## pslist ##

To list the processes of a system, use the pslist command. This walks the doubly-linked list pointed to by PsActiveProcessHead. It does not detect hidden or unlinked processes.

Also, if you see processes with 0 threads and 0 handles, the process may not actually still be active. For more information, see [The Missing Active in PsActiveProcessHead](http://mnin.blogspot.com/2011/03/mis-leading-active-in.html).

```
$ python vol.py --profile=Win7SP0x86 -f win7.dmp pslist
Volatile Systems Volatility Framework 2.0
 Offset(V)  Name                 PID    PPID   Thds   Hnds   Time 
---------- -------------------- ------ ------ ------ ------ ------------------- 
0x84133a30 System                    4      0     88    486 2010-06-16 15:24:58       
0x852e7020 smss.exe                252      4      2     29 2010-06-16 15:24:58       
0x859f3d40 csrss.exe               352    316      9    406 2010-06-16 15:25:12       
0x85a5a530 wininit.exe             392    316      3     75 2010-06-16 15:25:15       
0x85a5f530 csrss.exe               400    384     10    361 2010-06-16 15:25:15       
0x859f5bc0 winlogon.exe            464    384      3    112 2010-06-16 15:25:18       
0x85b0b318 services.exe            508    392      6    185 2010-06-16 15:25:18       
0x85d393f8 lsass.exe               516    392      6    584 2010-06-16 15:25:18       
0x841d1750 lsm.exe                 524    392     10    143 2010-06-16 15:25:18       
0x85d5b8f8 svchost.exe             628    508      9    361 2010-06-16 15:25:19       
0x850c67e0 svchost.exe             688    508      7    268 2010-06-16 15:25:20   
[snip]
```

The columns display the offset, process name, process ID, the parent process ID, number of threads, number of handles, and date/time when the process started.  The offset is a virtual address by default, but the physical offset can be obtained with the -P switch:

```
$ python vol.py --profile=Win7SP0x86 -f win7.dmp pslist -P
Volatile Systems Volatility Framework 2.0
 Offset(P)  Name                 PID    PPID   Thds   Hnds   Time 
---------- -------------------- ------ ------ ------ ------ ------------------- 
0x3fff3a30 System                    4      0     88    486 2010-06-16 15:24:58       
0x3ece7020 smss.exe                252      4      2     29 2010-06-16 15:24:58       
0x3e7f3d40 csrss.exe               352    316      9    406 2010-06-16 15:25:12       
0x3e45a530 wininit.exe             392    316      3     75 2010-06-16 15:25:15       
0x3e45f530 csrss.exe               400    384     10    361 2010-06-16 15:25:15       
0x3e7f5bc0 winlogon.exe            464    384      3    112 2010-06-16 15:25:18       
0x3e50b318 services.exe            508    392      6    185 2010-06-16 15:25:18       
0x3e3393f8 lsass.exe               516    392      6    584 2010-06-16 15:25:18       
0x3ff11750 lsm.exe                 524    392     10    143 2010-06-16 15:25:18       
0x3e35b8f8 svchost.exe             628    508      9    361 2010-06-16 15:25:19       
0x3eec67e0 svchost.exe             688    508      7    268 2010-06-16 15:25:20
[snip]       
```

## pstree ##

To view the process listing in tree form, use the pstree command. This enumerates processes using the same technique as pslist, so it will also not show hidden or unlinked processes. Child process are indicated using indention and periods.

```
$ python vol.py --profile=Win7SP0x86 -f win7.dmp pstree
Volatile Systems Volatility Framework 2.0
Name                                        Pid    PPid   Thds   Hnds   Time  
 0x84E6E3D8:wininit.exe                        384    340      3     73 2010-07-06 22:28:53       
. 0x8D4CC030:services.exe                      492    384     12    216 2010-07-06 22:28:54       
.. 0x84E19030:svchost.exe                     1920    492      8    115 2010-07-06 22:33:17       
.. 0x8D4E5BB0:schtasks.exe                    2512    492      2     60 2010-07-06 22:39:09       
.. 0x8D7E9030:wsqmcons.exe                    2576    492      1      3 2010-07-06 22:39:11       
.. 0x8D5B18A8:dllhost.exe                     1944    492     16    187 2010-07-06 22:31:21       
.. 0x8D7EE030:taskhost.exe                    1156    492     10    155 2010-07-06 22:37:54       
.. 0x84D79D40:msdtc.exe                        284    492     15    152 2010-07-06 22:31:24       
.. 0x8D6781D8:svchost.exe                     1056    492     16    589 2010-07-06 22:29:31       
.. 0x8D777D40:taskhost.exe                    2520    492     11    224 2010-07-06 22:39:10       
.. 0x8D759470:sdclt.exe                       2504    492      1      4 2010-07-06 22:39:09       
.. 0x8D5574D8:rundll32.exe                    2484    492      1      5 2010-07-06 22:39:08       
.. 0x84D82C08:SearchIndexer.                  1464    492     18    624 2010-07-06 22:33:20       
... 0x8D759760:SearchFilterHo                 1724   1464      6     82 2010-07-06 22:37:36       
... 0x8D55E678:SearchProtocol                 2680   1464      8    231 2010-07-06 22:39:27       
.. 0x8D5CC030:svchost.exe                     1140    492     17    375 2010-07-06 22:29:51
[snip]
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

## dlllist ##

To display a process's loaded DLLs, use the dlllist command. It walks the doubly-linked list of LDR\_DATA\_TABLE\_ENTRY structures which is pointed to by the PEB's InLoadOrderModuleList. DLLs are automatically added to this list when a process calls LoadLibrary (or some derivative such as LdrLoadDll) and they aren't removed until FreeLibrary is called and the reference count reaches zero.

```
$ python vol.py --profile=Win7SP0x86 -f win7.dmp dlllist

[snip]

************************************************************************
services.exe pid:    492
Command line : C:\Windows\system32\services.exe

Base         Size         Path
0x00a50000   0x041000     C:\Windows\system32\services.exe
0x778a0000   0x13c000     C:\Windows\SYSTEM32\ntdll.dll
0x779f0000   0x0d4000     C:\Windows\system32\kernel32.dll
0x75ca0000   0x04a000     C:\Windows\system32\KERNELBASE.dll
0x75e40000   0x0ac000     C:\Windows\system32\msvcrt.dll
0x76650000   0x0a1000     C:\Windows\system32\RPCRT4.dll
0x758d0000   0x01a000     C:\Windows\system32\SspiCli.dll
0x759f0000   0x00b000     C:\Windows\system32\profapi.dll
0x75d80000   0x019000     C:\Windows\SYSTEM32\sechost.dll
0x75940000   0x00c000     C:\Windows\system32\CRYPTBASE.dll
0x758c0000   0x00f000     C:\Windows\system32\scext.dll
0x764a0000   0x0c9000     C:\Windows\system32\USER32.dll
0x765b0000   0x04e000     C:\Windows\system32\GDI32.dll
0x76330000   0x00a000     C:\Windows\system32\LPK.dll
[snip]
```

To display the DLLs for a specific process instead of all processes, use the -p or --pid filter like this:

```
$ python vol.py --profile=Win7SP0x86 -f win7.dmp dlllist --pid=492
```

To display the DLLs for a process that is hidden or unlinked by a rootkit, first use the psscan to get the physical offset of the EPROCESS object and then:

```
$ python vol.py --profile=Win7SP0x86 -f win7.dmp dlllist --offset=0x04a291a8
```

For more ways to list DLLs in a process, see the [ldrmodules](http://code.google.com/p/volatility/wiki/CommandReference#ldrmodules) command.

## dlldump ##

To extract a DLL from a process's memory space and dump it to disk for analysis, use the dlldump command. The syntax is nearly the same as what we've shown for dlllist above. You can:

  * Dump all DLLs from all processes
  * Dump all DLLs from a specific process (with --pid=PID)
  * Dump all DLLs from a hidden/unlinked process (with --offset=OFFSET)
  * Dump a PE from anywhere in process memory (with --base=BASEADDR), this option is useful for extracting hidden DLLs

To specify an output directory, use --dump-dir=DIR or -d DIR. You can also supply a regular expression to dump a DLL with a particular pattern in its name.

```
$ python vol.py --profile=Win7SP0x86 -f win7.dmp dlldump -r kernel32 -D out
Cannot dump TrustedInstall@kernel32.dll at 779f0000
Cannot dump WmiPrvSE.exe@kernel32.dll at 779f0000
Dumping kernel32.dll, Process: SearchFilterHo, Base: 779f0000 output: module.623.da1d760.779f0000.dll
Dumping kernel32.dll, Process: taskhost.exe, Base: 779f0000 output: module.484.546d030.779f0000.dll
Cannot dump dwm.exe@kernel32.dll at 779f0000
Dumping kernel32.dll, Process: explorer.exe, Base: 779f0000 output: module.758.4a291a8.779f0000.dll
Cannot dump wuauclt.exe@kernel32.dll at 779f0000
Dumping kernel32.dll, Process: VMwareTray.exe, Base: 779f0000 output: module.860.fe828d8.779f0000.dll
[snip]
```

If the extraction fails, as it did for a few processes above, it probably means that some of the memory pages in that process were not memory resident at the time (due to paging).

To dump a PE file that doesn't exist in the DLLs list (for example, due to code injection or malicious unlinking), just specify the base address of the PE in process memory:

```
$ python vol.py --profile=Win7SP0x86 -f win7.dmp dlldump --pid=492 -D out --base=0x00680000
```

You can also specify an EPROCESS offset if the DLL you want is in a hidden process:

```
$ python vol.py --profile=Win7SP0x86 -f win7.dmp dlldump -o 0x3e3f64e8 -D out --base=0x00680000
```

## handles ##

To display the open handles in a process, use the handles command. A process can obtain a file handle by calling functions such as CreateFile, and the handle will stay valid until CloseHandle is called. The same concept applies for registry keys, mutexes, named pipes, events, window stations, desktops, threads, and all other types of objects. This command replaces the older "files" and "regobjkeys" commands.

```
$ python vol.py --profile=Win7SP0x86 -f win7.dmp handles
Volatile Systems Volatility Framework 1.4_rc1
Offset(V)    Pid    Type             Details
0x823c8818   4      Process          System(4)
0x823c7008   4      Thread           TID 12 PID 4
0xe13f8fa0   4      Key              MACHINE\SYSTEM\CONTROLSET001\CONTROL\SESSION MANAGER\MEMORY MANAGEMENT\PREFETCHPARAMETERS
0xe100f418   4      Key              MACHINE\SYSTEM\WPA\MEDIACENTER
0xe1406418   4      Key              MACHINE\SYSTEM\WPA\KEY-4F3B2RFXKC9C637882MBM
0xe1404b20   4      Key              MACHINE\SYSTEM\WPA\PNP
0xe1000480   4      Key              MACHINE\SYSTEM\WPA\SIGNINGHASH-V44KQMCFXKQCTQ
0xe1013b80   4      Key              MACHINE\SYSTEM\CONTROLSET001\CONTROL\PRODUCTOPTIONS
0xe142cc28   4      Key              MACHINE\SYSTEM\CONTROLSET001\SERVICES\EVENTLOG
0x823c1778   4      Event            'TRKWKS_EVENT'
0x81ebb938   4      File             '\\Documents and Settings\\NetworkService\\NTUSER.DAT'
0xe14dc268   4      Key              MACHINE\HARDWARE\DEVICEMAP\SCSI
[snip]
```

Similar to other commands, you can display handles for a particular process by specifying a process ID (--pid) or the physical offset of an eprocess structure (--physical-offset). You can also filter by object type using -t or --object-type. For example to only display handles to process objects for pid 600, do the following:

```
$ python vol.py --profile=Win7SP0x86 -f win7.dmp handles -p 600 -t Process
Volatile Systems Volatility Framework 1.4_rc1
Offset(V)    Pid    Type             Details
0x81da5638   600    Process          winlogon.exe(624)
0x82073008   600    Process          services.exe(668)
0x81e6b648   600    Process          VMwareUser.exe(1356)
0x81e70008   600    Process          lsass.exe(680)
0x823315c0   600    Process          vmacthlp.exe(844)
0x81db8d88   600    Process          svchost.exe(856)
[snip]
```

In some cases, the Details column will be blank (for example, if the objects don't have names). By default, you'll see both named and un-named objects. However, if you want to hide the less meaningful results and only show named objects, use the --silent parameter to this plugin.

## getsids ##

To view the SIDs (Security Identifiers) associated with a process, use the getsids command. Among other things, this can help you identify processes which have maliciously escalated privileges.

For more information, see BDG's [Linking Processes To Users](http://moyix.blogspot.com/2008/08/linking-processes-to-users.html).

```
$ python vol.py --profile=Win7SP0x86 -f win7.dmp getsids 
Volatile Systems Volatility Framework 2.0
System (4): S-1-5-18 (Local System)
System (4): S-1-5-32-544 (Administrators)
System (4): S-1-1-0 (Everyone)
System (4): S-1-5-11 (Authenticated Users)
System (4): S-1-16-16384 (System Mandatory Level)
smss.exe (252): S-1-5-18 (Local System)
smss.exe (252): S-1-5-32-544 (Administrators)
smss.exe (252): S-1-1-0 (Everyone)
smss.exe (252): S-1-5-11 (Authenticated Users)
smss.exe (252): S-1-16-16384 (System Mandatory Level)
[snip]
```

## verinfo ##

To display the version information embedded in PE files, use the verinfo command. Not all PE files have version information, and many malware authors forge it to include false data, but nonetheless this command can be very helpful with identifying binaries and for making correlations with other files.

This command supports filtering by process ID, regular expression, and EPROCESS offset.  Note that this plugin resides in the contrib directory, therefore you'll need to tell volatility to look there using the --plugins option.

```
$ python vol.py --plugins=contrib/plugins --profile=Win7SP0x86 -f win7.dmp verinfo
[snip]

C:\Windows\system32\CRYPTBASE.dll
C:\Windows\system32\winlogon.exe
  File version    : 6.1.7600.16447
  Product version : 6.1.7600.16447
  Flags           : 
  OS              : Windows NT
  File Type       : Application
  File Date       : 
  CompanyName : Microsoft Corporation
  FileDescription : Windows Logon Application
  FileVersion : 6.1.7600.16447 (win7_gdr.091027-1503)
  InternalName : winlogon
  LegalCopyright : \xa9 Microsoft Corporation. All rights reserved.
  OriginalFilename : WINLOGON.EXE
  ProductName : Microsoft\xae Windows\xae Operating System
  ProductVersion : 6.1.7600.16447

[snip] 

C:\Windows\System32\ntlanman.dll
  File version    : 6.1.7600.16385
  Product version : 6.1.7600.16385
  Flags           : 
  OS              : Windows NT
  File Type       : Dynamic Link Library
  File Date       : 
  CompanyName : Microsoft Corporation
  FileDescription : Microsoft\xae Lan Manager
  FileVersion : 6.1.7600.16385 (win7_rtm.090713-1255)
  InternalName : ntlanman.dll
  LegalCopyright : \xa9 Microsoft Corporation. All rights reserved.
  OriginalFilename : ntlanman.dll
  ProductName : Microsoft\xae Windows\xae Operating System
  ProductVersion : 6.1.7600.16385

[snip]
```

## enumfunc ##

This plugin enumerates imported and exported functions from processes, dlls, and kernel drivers. Specifically, it handles functions imported by name or ordinal, functions exported by name or ordinal, and forwarded exports. The output will be very verbose in most cases (functions exported by ntdll, msvcrt, and kernel32 can reach 1000+ alone). So you can either reduce the verbosity by filtering criteria with the command-line options (shown below) or you can use look at the code in enumfunc.py and use it as an example of how to use the IAT and EAT parsing API functions in your own plugin.

Also note this plugin is in the contrib directory, so you can pass that to --plugins like this:

```
$ python vol.py --plugins=contrib/plugins --profile=Win7SP0x86 -f win7.dmp enumfunc -h
....
  -s, --scan            Scan for objects
  -P, --process-only    Process only
  -K, --kernel-only     Kernel only
  -I, --import-only     Imports only
  -E, --export-only     Exports only
```

To only show imported functions in process memory, use -P -I. To only show exported functions in kernel memory, use -K -E. To use pool scanners for finding processes and kernel drivers instead of walking linked lists, use the -s option.

Here is an example of the output:

```
$ python vol.py --plugins=contrib/plugins --profile=Win7SP0x86 -f win7.dmp enumfunc -P -E
Process              Type       Module               Ordinal    Address              Name
winlogon.exe         Export     ntdll.dll            18         0x00000000778b657b A_SHAFinal
winlogon.exe         Export     ntdll.dll            19         0x00000000778b6392 A_SHAInit
winlogon.exe         Export     ntdll.dll            20         0x00000000778b63e8 A_SHAUpdate
winlogon.exe         Export     ntdll.dll            21         0x00000000779185fe AlpcAdjustCompletionListConcurrencyCount
winlogon.exe         Export     ntdll.dll            22         0x0000000077918b8e AlpcFreeCompletionListMessage
winlogon.exe         Export     ntdll.dll            23         0x000000007794858d AlpcGetCompletionListLastMessageInformation
winlogon.exe         Export     ntdll.dll            24         0x0000000077948559 AlpcGetCompletionListMessageAttributes
winlogon.exe         Export     ntdll.dll            25         0x00000000778fb0ff AlpcGetHeaderSize
[snip]
```

# Process Memory #

## memmap ##

For a brief inspection of the addressable memory pages in a process, use the memmap command.

```
$ python vol.py --profile=Win7SP0x86 -f win7.dmp -p 1880 memmap 
explorer.exe pid:   1880
Virtual      Physical     Size        
0x0000010000 0x00075cb000 0x000000001000
0x0000021000 0x0009c2c000 0x000000001000
0x0000030000 0x0002adf000 0x000000001000
0x0000031000 0x0000d99000 0x000000001000
0x0000032000 0x000583a000 0x000000001000
0x0000040000 0x000a25b000 0x000000001000
0x0000041000 0x00044d6000 0x000000001000
0x0000050000 0x00099ee000 0x000000001000
0x0000060000 0x000b155000 0x000000001000
[snip]
```

## memdump ##

To extract all data from the various memory segments in a process and dump them to a single file, use the memdump command.

```
$ python vol.py --profile=Win7SP0x86 -f win7.dmp -p 1880 memdump -D memory/
Volatile Systems Volatility Framework 2.0
************************************************************************
Writing explorer.exe [  1880] to 1880.dmp

$ ls -alh memory/1880.dmp 
-rw-r--r--  1 User  staff   140M Feb  8 15:13 memory/1880.dmp
```

## procmemdump ##

To dump a process's executable (including the slack space), use the procmemdump command. Optionally, pass the --unsafe or -u flags to bypass certain sanity checks used when parsing the PE header. Some malware will intentionally forge size fields in the PE header so that memory dumping tools fail.

For more information, see Andreas Schuster's 4-part series on [Reconstructing a Binary](http://computer.forensikblog.de/en/2006/04/reconstructing_a_binary.html#more). Also see [impscan](http://code.google.com/p/volatility/wiki/CommandReference#impscan) for help rebuilding a binary's import address table.

```
$ python vol.py --profile=Win7SP0x86 -f win7.dmp -p 1880 procmemdump -D memory/
Volatile Systems Volatility Framework 2.0
************************************************************************
Dumping explorer.exe, pid:   1880 output: executable.1880.exe

$ file memory/executable.1880.exe 
memory/executable.1880.exe: PE32 executable for MS Windows (GUI) Intel 80386 32-bit
```

## procexedump ##

To dump a process's executable (**not** including the slack space), use the procexedump command. The syntax is identical to procmemdump.

## vadwalk ##

To briefly inspect a process's VAD nodes, use the vadwalk command. For more information on the VAD, see BDG's [The VAD Tree: A Process-Eye View of Physical Memory](http://www.dfrws.org/2007/proceedings/p62-dolan-gavitt.pdf).

```
$ python vol.py --profile=Win7SP0x86 -f win7.dmp -p 1880 vadwalk
Volatile Systems Volatility Framework 2.0
************************************************************************
Pid:   1880
Address  Parent   Left     Right    Start    End      Tag  Flags
8d5487b8 00000000 8d6a4a20 8d7d5ef8 6ce80000 6ceeefff Vad 
8d6a4a20 00000000 8d57ed70 84e4e7f8 02e30000 02e31fff VadS
8d57ed70 8d6a4a20 8d6cffb8 8d7c5c20 01c90000 01e8ffff Vadm
8d6cffb8 00000000 8d760e58 8d457268 00a20000 00ca0fff Vadm
8d760e58 00000000 84d529c0 84d2a1b8 00090000 000cffff VadS
84d529c0 00000000 84e689a0 8d782428 00040000 00041fff Vad 
84e689a0 84d529c0 84d52708 83efff78 00020000 00021fff Vad 
84d52708 84e689a0 00000000 00000000 00010000 0001ffff Vad 
83efff78 84e689a0 00000000 00000000 00030000 00033fff Vad 
[snip]
```

## vadtree ##

To display the VAD nodes in a visual tree form, use the vadtree command.

```
$ python vol.py --profile=Win7SP0x86 -f win7.dmp -p 1880 vadtree
Volatile Systems Volatility Framework 2.0
************************************************************************
Pid:   1880
6ce80000 - 6ceeefff
02e30000 - 02e31fff
 01c90000 - 01e8ffff
00a20000 - 00ca0fff
00090000 - 000cffff
00040000 - 00041fff
 00020000 - 00021fff
  00010000 - 0001ffff
```

If you want to view the balanced binary tree in Graphviz format, use the dot output rendering:

```
$ python vol.py --profile=Win7SP0x86 -f win7.dmp -p 1880 vadtree --output=dot --output-file=graph.dot
```

Now you can open graph.dot in any Graphviz-compatible viewer.

## vadinfo ##

The vadinfo command displays extended information about a process's VAD nodes. In particular, it shows:

  * The address of the MMVAD structure in kernel memory
  * The starting and ending virtual addresses in process memory
  * The VAD Tag
  * The name of the memory mapped file (if one exists)
  * The memory protection constant (permissions). Note there is a difference between the original protection and current protection. The original protection is derived from the flProtect parameter to VirtualAlloc. For example you can reserve memory (MEM\_RESERVE) with protection PAGE\_NOACCESS (original protection). Later, you can call VirtualAlloc again to commit (MEM\_COMMIT) and specify PAGE\_READWRITE (becomes current protection). The vadinfo command shows the original protection only. Thus, just because you see PAGE\_NOACCESS here, it doesn't mean code in the region cannot be read, written, or executed.

```
$ python vol.py --profile=Win7SP0x86 -f win7.dmp -p 1880 vadinfo

VAD node @8d570798 Start 05330000 End 0536ffff Tag VadS
Flags: PrivateMemory
Commit Charge: 18 Protection: 4

VAD node @8d6d78a0 Start 05850000 End 0588ffff Tag VadS
Flags: PrivateMemory
Commit Charge: 16 Protection: 4

VAD node @84f40530 Start 6c750000 End 6c756fff Tag Vad 
Flags: UserPhysicalPages
Commit Charge: 2 Protection: 7
ControlArea @84d501e8 Segment 99e28118
Dereference list: Flink 00000000, Blink 00000000
NumberOfSectionReferences:          0 NumberOfPfnReferences:           1
NumberOfMappedViews:                1 NumberOfUserReferences:          1
WaitingForDeletion Event:  00000000
Flags: File, Image
FileObject @84e8e910 FileBuffer @ 9c52c7b0          , Name: \Windows\System32\msiltcfg.dll
First prototype PTE: 99e28144 Last contiguous PTE: fffffffc
Flags2: Inherit
File offset: 00000000

[snip]
```

## vaddump ##

To extract the data contained within each VAD segment, use the vaddump command. This is similar to [memdump](http://code.google.com/p/volatility/wiki/CommandReference#memdump), except the data ends up in separate files, named according to the address in process memory where the data was found.

```
$ python vol.py --profile=Win7SP0x86 -f win7.dmp vaddump -D vads
Volatile Systems Volatility Framework 2.0
Pid:      4
************************************************************************
Pid:    252
************************************************************************
Pid:    348
************************************************************************
Pid:    384
************************************************************************
Pid:    396
************************************************************************
Pid:    424
[snip]

$ ls -alh vads/
-rw-r--r--    1 User  staff   128K Feb  8 15:29 System.a2d960.00120000-0013ffff.dmp
-rw-r--r--    1 User  staff   128K Feb  8 15:29 System.a2d960.00140000-0015ffff.dmp
-rw-r--r--    1 User  staff   128K Feb  8 15:29 System.a2d960.00160000-0017ffff.dmp
-rw-r--r--    1 User  staff   128K Feb  8 15:29 System.a2d960.00180000-0019ffff.dmp
-rw-r--r--    1 User  staff   1.2M Feb  8 15:29 System.a2d960.778a0000-779dbfff.dmp
-rw-r--r--    1 User  staff   1.0M Feb  8 15:29 csrss.exe.3164d40.00000000-000fffff.dmp
-rw-r--r--    1 User  staff   412K Feb  8 15:29 csrss.exe.3164d40.00100000-00166fff.dmp
-rw-r--r--    1 User  staff   4.0K Feb  8 15:29 csrss.exe.3164d40.00170000-00170fff.dmp
-rw-r--r--    1 User  staff   8.0K Feb  8 15:29 csrss.exe.3164d40.00180000-00181fff.dmp
-rw-r--r--    1 User  staff   4.0K Feb  8 15:29 csrss.exe.3164d40.00190000-00190fff.dmp
[snip]
```

The files are named like this:

ProcessName.PhysicalOffset.StartingVPN.EndingVPN.dmp

The reason the PhysicalOffset field exists is so you can distinguish between two processes with the same name.

# Kernel Memory and Objects #

## modules ##

To view the list of kernel drivers loaded on the system, use the modules command. This walks the doubly-linked list of LDR\_DATA\_TABLE\_ENTRY structures pointed to by PsLoadedModuleList. It cannot find hidden/unlinked kernel drivers.

```
$ python vol.py --profile=Win7SP0x86 -f win7.dmp modules
Volatile Systems Volatility Framework 2.0
Offset(V)  File                                               Base         Size     Name
0x84131c98 \SystemRoot\system32\ntkrnlpa.exe                  0x008283c000 0x410000 ntoskrnl.exe
0x84131c20 \SystemRoot\system32\halmacpi.dll                  0x0082805000 0x037000 hal.dll
0x84131ba0 \SystemRoot\system32\kdcom.dll                     0x0080b99000 0x008000 kdcom.dll
0x84131b20 \SystemRoot\system32\mcupdate_GenuineIntel.dll     0x0082e24000 0x078000 mcupdate.dll
0x84131aa0 \SystemRoot\system32\PSHED.dll                     0x0082e9c000 0x011000 PSHED.dll
0x84131a20 \SystemRoot\system32\BOOTVID.dll                   0x0082ead000 0x008000 BOOTVID.dll
0x841319a8 \SystemRoot\system32\CLFS.SYS                      0x0082eb5000 0x042000 CLFS.SYS
0x84131930 \SystemRoot\system32\CI.dll                        0x0082ef7000 0x0ab000 CI.dll
0x841318b0 \SystemRoot\system32\drivers\Wdf01000.sys          0x0086a1b000 0x071000 Wdf01000.sys
0x84131830 \SystemRoot\system32\drivers\WDFLDR.SYS            0x0086a8c000 0x00e000 WDFLDR.SYS
0x841317b8 \SystemRoot\system32\DRIVERS\ACPI.sys              0x0086a9a000 0x048000 ACPI.sys
0x84131738 \SystemRoot\system32\DRIVERS\WMILIB.SYS            0x0086ae2000 0x009000 WMILIB.SYS
0x841316b8 \SystemRoot\system32\DRIVERS\msisadrv.sys          0x0086aeb000 0x008000 msisadrv.sys
0x8412be78 \SystemRoot\system32\DRIVERS\pci.sys               0x0086af3000 0x02a000 pci.sys
[snip] 
```

Included in the output is the offset of the module, which is a virtual address by default but can be specified as a physical address with the -P switch:

```
$ python vol.py --profile=Win7SP0x86 -f win7.dmp modules -P
Volatile Systems Volatility Framework 2.0
Offset(P)  File                                               Base         Size     Name
0x3fff1c98 \SystemRoot\system32\ntkrnlpa.exe                  0x008283c000 0x410000 ntoskrnl.exe
0x3fff1c20 \SystemRoot\system32\halmacpi.dll                  0x0082805000 0x037000 hal.dll
0x3fff1ba0 \SystemRoot\system32\kdcom.dll                     0x0080b99000 0x008000 kdcom.dll
0x3fff1b20 \SystemRoot\system32\mcupdate_GenuineIntel.dll     0x0082e24000 0x078000 mcupdate.dll
0x3fff1aa0 \SystemRoot\system32\PSHED.dll                     0x0082e9c000 0x011000 PSHED.dll
0x3fff1a20 \SystemRoot\system32\BOOTVID.dll                   0x0082ead000 0x008000 BOOTVID.dll
0x3fff19a8 \SystemRoot\system32\CLFS.SYS                      0x0082eb5000 0x042000 CLFS.SYS
0x3fff1930 \SystemRoot\system32\CI.dll                        0x0082ef7000 0x0ab000 CI.dll
0x3fff18b0 \SystemRoot\system32\drivers\Wdf01000.sys          0x0086a1b000 0x071000 Wdf01000.sys
0x3fff1830 \SystemRoot\system32\drivers\WDFLDR.SYS            0x0086a8c000 0x00e000 WDFLDR.SYS
0x3fff17b8 \SystemRoot\system32\DRIVERS\ACPI.sys              0x0086a9a000 0x048000 ACPI.sys
0x3fff1738 \SystemRoot\system32\DRIVERS\WMILIB.SYS            0x0086ae2000 0x009000 WMILIB.SYS
0x3fff16b8 \SystemRoot\system32\DRIVERS\msisadrv.sys          0x0086aeb000 0x008000 msisadrv.sys
0x3ffebe78 \SystemRoot\system32\DRIVERS\pci.sys               0x0086af3000 0x02a000 pci.sys
[snip]
```

## modscan ##

To scan physical memory for kernel modules, use the modscan command. This can pick up previously unloaded drivers and drivers that have been hidden/unlinked by rootkits.  Included in the output is the offset of the module, which is a physical address:

```
$ python vol.py --profile=Win7SP0x86 -f win7.dmp modscan
Volatile Systems Volatility Framework 2.0
Offset     File                                               Base         Size     Name
0x3e011200 '\\SystemRoot\\system32\\DRIVERS\\lltdio.sys'      0x008e7b6000 0x010000 'lltdio.sys'
0x3e020a50 '\\SystemRoot\\system32\\DRIVERS\\rspndr.sys'      0x008e7c6000 0x013000 'rspndr.sys'
0x3e03bec0 '\\SystemRoot\\system32\\DRIVERS\\asyncmac.sys'    0x0090b19000 0x009000 'asyncmac.sys'
0x3e067370 '\\??\\c:\\Users\\user\\Desktop\\win32dd.sys'      0x0090a00000 0x00c000 'win32dd.sys'
0x3e0dc7a0 '\\SystemRoot\\System32\\DRIVERS\\srv.sys'         0x0090a5e000 0x051000 'srv.sys'
0x3e364908 '\\SystemRoot\\system32\\drivers\\luafv.sys'       0x008e781000 0x01b000 'luafv.sys'
0x3e366608 '\\SystemRoot\\system32\\drivers\\WudfPf.sys'      0x008e79c000 0x01a000 'WudfPf.sys'
0x3e36b850 '\\SystemRoot\\system32\\drivers\\HTTP.sys'        0x008dc04000 0x085000 'HTTP.sys'
0x3e422648 '\\SystemRoot\\System32\\TSDDD.dll'                0x008fda0000 0x009000 'TSDDD.dll'
0x3e4291e0 '\\SystemRoot\\system32\\DRIVERS\\mouhid.sys'      0x008e76b000 0x00b000 'mouhid.sys'
0x3e429bd8 '\\SystemRoot\\system32\\DRIVERS\\HIDPARSE.SYS'    0x008e764000 0x007000 'HIDPARSE.SYS'
0x3e46a4d0 '\\SystemRoot\\System32\\cdd.dll'                  0x008fdd0000 0x01e000 'cdd.dll'
0x3e46aed0 '\\SystemRoot\\System32\\drivers\\mpsdrv.sys'      0x008dca2000 0x012000 'mpsdrv.sys'
0x3e474a38 '\\SystemRoot\\system32\\DRIVERS\\bowser.sys'      0x008dc89000 0x019000 'bowser.sys'
0x3e482870 '\\SystemRoot\\system32\\DRIVERS\\mrxsmb20.sys'    0x008dd12000 0x01b000 'mrxsmb20.sys'
0x3e482da0 '\\SystemRoot\\system32\\DRIVERS\\mrxsmb10.sys'    0x008dcd7000 0x03b000 'mrxsmb10.sys'
[snip]
```

## moddump ##

To extract a kernel driver to a file, use the moddump command. It supports filtering by regular expression (case sensitive or not) and by physical offsets. To dump all drivers, don't use any command-line filters.

For more information, see BDG's [Plugin Post: Moddump](http://moyix.blogspot.com/2008/10/plugin-post-moddump.html).

```
$ python vol.py --profile=Win7SP0x86 -f win7.dmp moddump -D mods/
Volatile Systems Volatility Framework 2.0
Dumping ntoskrnl.exe, Base: 8284c000 output: driver.8284c000.sys
Dumping hal.dll, Base: 82815000 output: driver.82815000.sys
Dumping fwpkclnt.sys, Base: 86550000 output: driver.86550000.sys
Dumping kdcom.dll, Base: 80bcc000 output: driver.80bcc000.sys
Dumping NDProxy.SYS, Base: 8c7ec000 output: driver.8c7ec000.sys
Dumping CLFS.SYS, Base: 85cbe000 output: driver.85cbe000.sys
Dumping luafv.sys, Base: 8840c000 output: driver.8840c000.sys
Dumping peauth.sys, Base: 8857c000 output: driver.8857c000.sys
[snip]
```

## ssdt ##

To list the functions in the Native and GUI SSDTs, use the ssdt command. This displays the index, function name, and owning driver for each entry in the SSDT. Please note the following very important facts:

  * Windows has 4 SSDTs by default (you can add more with KeAddSystemServiceTable), but only 2 of them are used - one for Native functions in the NT module, and one for GUI functions in the win32k.sys module.
  * There are multiple ways to locate the SSDTs in memory. Most tools do it by finding the exported KeServiceDescriptorTable symbol in the NT module, but this is not the way Volatility works. Volatility scans for ETHREAD objects (see the [thrdscan](http://code.google.com/p/volatility/wiki/CommandReference#thrdscan) command) and gathers all unique ETHREAD.Tcb.ServiceTable pointers. This method is more robust and complete, because it can detect when rootkits make copies of the existing SSDTs and assign them to particular threads. Also see the [threads](http://code.google.com/p/volatility/wiki/CommandReference#threads) command.
  * The order and total number of functions in the SSDT differs across operating system versions. Thus, Volatility stores the information in a per-profile (OS) manner.
  * For more information, see BDG's [Auditing the System Call Table](http://moyix.blogspot.com/2008/08/auditing-system-call-table.html).

```
$ python vol.py --profile=Win7SP0x86 -f win7.dmp ssdt 
Volatile Systems Volatility Framework 2.0
Gathering all referenced SSDTs from KTHREADs...
Finding appropriate address space for tables...
SSDT[0] at 828a8634 with 401 entries
  Entry 0x0000: 0x82a8530e (NtAcceptConnectPort) owned by ntoskrnl.exe
  Entry 0x0001: 0x828d6774 (NtAccessCheck) owned by ntoskrnl.exe
  Entry 0x0002: 0x82abd460 (NtAccessCheckAndAuditAlarm) owned by ntoskrnl.exe
  Entry 0x0003: 0x82901dea (NtAccessCheckByType) owned by ntoskrnl.exe
  Entry 0x0004: 0x82a9f99a (NtAccessCheckByTypeAndAuditAlarm) owned by ntoskrnl.exe
  Entry 0x0005: 0x8294145a (NtAccessCheckByTypeResultList) owned by ntoskrnl.exe

[snip]

SSDT[1] at 977a5000 with 825 entries
  Entry 0x1000: 0x9772eb34 (NtGdiAbortDoc) owned by win32k.sys
  Entry 0x1001: 0x9774752e (NtGdiAbortPath) owned by win32k.sys
  Entry 0x1002: 0x975adc1a (NtGdiAddFontResourceW) owned by win32k.sys
  Entry 0x1003: 0x9773e5ae (NtGdiAddRemoteFontToDC) owned by win32k.sys
  Entry 0x1004: 0x97748c89 (NtGdiAddFontMemResourceEx) owned by win32k.sys
  Entry 0x1005: 0x9772f351 (NtGdiRemoveMergeFont) owned by win32k.sys
  Entry 0x1006: 0x9772f3e5 (NtGdiAddRemoteMMInstanceToDC) owned by win32k.sys
  Entry 0x1007: 0x976545cc (NtGdiAlphaBlend) owned by win32k.sys

[snip]
```

To filter all functions which point to ntoskrnl.exe and win32k.sys, you can use egrep on command-line. This will only show hooked SSDT functions.

```
$ python vol.py --profile=Win7SP0x86 -f win7.dmp ssdt | egrep -v '(ntoskrnl|win32k)'
```

Note that the NT module on your system may be ntkrnlpa.exe or ntkrnlmp.exe - so check that before using egrep of you'll be filtering the wrong module name.

## driverscan ##

To scan for DRIVER\_OBJECTs in physical memory, use the driverscan command. This is another way to locate kernel modules, although not all kernel modules have an associated DRIVER\_OBJECT. The DRIVER\_OBJECT is what contains the 28 IRP (Major Function) tables, thus the [driverirp](http://code.google.com/p/volatility/wiki/CommandReference#driverirp) command is based on the methodology used by driverscan.

For more information, see Andreas Schuster's [Scanning for Drivers](http://computer.forensikblog.de/en/2009/04/scanning_for_drivers.html).

```
$ python vol.py --profile=Win7SP0x86 -f win7.dmp driverscan 
Volatile Systems Volatility Framework 2.0
Phys.Addr. Obj Type   #Ptr #Hnd Start        Size Service key          Name
0x007f1300 0x0000001a   67    0 0x85e2a000 294912 'ACPI'               'ACPI'       '\\Driver\\ACPI'
0x007f1b30 0x0000001a    3    0 0x85dab000 462848 'Wdf01000'           'Wdf01000'   '\\Driver\\Wdf01000'
0x00c630d8 0x0000001a    3    0 0x88427000  65536 'lltdio'             'lltdio'     '\\Driver\\lltdio'
0x00cb0108 0x0000001a    3    0 0x88437000  77824 'rspndr'             'rspndr'     '\\Driver\\rspndr'
0x00dedd38 0x0000001a    4    0 0x8844a000 544768 'HTTP'               'HTTP'       '\\Driver\\HTTP'
0x05533b88 0x0000001a    3    0 0x88573000  28672 'Parvdm'             'Parvdm'     '\\Driver\\Parvdm'
0x0ad99af8 0x0000001a    5    0 0x8c400000  94208 'usbccgp'            'usbccgp'    '\\Driver\\usbccgp'
0x0bd46650 0x0000001a    3    0 0x8857a000   7680 'VMMEMCTL'           'VMMEMCTL'   '\\Driver\\VMMEMCTL'
0x0c8b5400 0x0000001a    2    0 0x8840c000 110592 'luafv'              'luafv'      '\\FileSystem\\luafv'
0x0d747c18 0x0000001a    3    0 0x884cf000 102400 'bowser'             'bowser'     '\\FileSystem\\bowser'
0x0d98cc60 0x0000001a    3    0 0x8864b000 323584 'srv2'               'srv2'       '\\FileSystem\\srv2'
[snip]
```

## filescan ##

To scan physical memory for FILE\_OBJECTs, use the filescan command. This will find open files even if a rootkit is hiding the files on disk and if the rootkit hooks some API functions to hide the open handles on a live system. The output shows the physical offset of the FILE\_OBJECT, file name, number of pointers to the object, number of handles to the object, and the effective permissions granted to the object.

For more information, see Andreas Schuster's [Scanning for File Objects](http://computer.forensikblog.de/en/2009/04/scanning_for_file_objects.html) and [Linking File Objects To Processes](http://computer.forensikblog.de/en/2009/04/linking_file_objects_to_processes.html).

```
$ python vol.py --profile=Win7SP0x86 -f win7.dmp filescan
Volatile Systems Volatility Framework 2.0
Phys.Addr. Obj Type   #Ptr #Hnd Access Name
0x007b1020 0x0000001c   17    0 RW-rwd '\\$Directory'
0x007b1280 0x0000001c    8    1 R--r-d '\\Windows\\System32\\en-US\\gpsvc.dll.mui'
0x00921bb8 0x0000001c    2    0 R--r-d '\\Windows\\System32\\msftedit.dll'
0x00be5950 0x0000001c    1    1 R--rw- '\\Windows\\System32'
0x00be76b8 0x0000001c    7    0 R--r-- '\\Windows\\Fonts\\marlett.ttf'
0x00bf2370 0x0000001c    8    0 R--r-d '\\Windows\\System32\\sscore.dll'
0x00bf2520 0x0000001c    9    1 R--r-d '\\Windows\\System32\\en-US\\sysmain.dll.mui'
0x00c23a68 0x0000001c    3    0 R--r-d '\\Windows\\System32\\wkssvc.dll'
0x00c23db0 0x0000001c    1    1 ------ '\\srvsvc'
0x00c5a910 0x0000001c   17    0 RW-rwd '\\$Directory'
0x00c5ab10 0x0000001c    5    0 R--r-d '\\Windows\\System32\\w32time.dll'
0x00c64228 0x0000001c   16    1 RW-r-- '\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-GroupPolicy%4Operational.evtx'
0x00c64610 0x0000001c    8    0 R--r-d '\\Windows\\System32\\RpcRtRemote.dll'
0x00c648a0 0x0000001c    6    0 R--r-d '\\Windows\\System32\\ntlanman.dll'
0x00c70c70 0x0000001c    1    1 ------ '\\wkssvc'
0x00ca3530 0x0000001c    4    0 ------ '\\Windows\\System32\\locale.nls'
0x00ca3ea8 0x0000001c    3    0 R--r-d '\\Windows\\System32\\wiarpc.dll'
0x00ca4330 0x0000001c    3    0 R--r-d '\\Windows\\System32\\Sens.dll'
0x00ca4b48 0x0000001c    2    0 R--r-d '\\Windows\\System32\\ktmw32.dll'
0x00ca4c00 0x0000001c    6    0 R--r-d '\\Windows\\System32\\schedsvc.dll'
0x00cad020 0x0000001c    1    1 R--r-- '\\Windows\\Registration\\R000000000006.clb'
0x00cadc28 0x0000001c    1    1 ------ '\\wkssvc'
0x00cade78 0x0000001c    1    1 ------ '\\wkssvc'
[snip]
```

## mutantscan ##

To scan physical memory for KMUTANT objects, use the mutantscan command. By default, it displays all objects, but you can pass -s or --silent to only show named mutexes. The CID column contains the process ID and thread ID of the mutex owner if one exists.

For more information, see Andreas Schuster's [Searching for Mutants](http://computer.forensikblog.de/en/2009/04/searching_for_mutants.html).

Since mutexes can have seemingly random names, and there are so many of them, its difficult to spot malicious mutexes. For this reason, we built a proof-of-concept mutanscandb command which gathers mutex names from online sandboxes and populates an sqlite3 database with them. Then the Volatility command reads in the mutexes and highlights entries in your memory dump which also exist in the sqlite3 database.

```
$ python vol.py --profile=Win7SP0x86 -f win7.dmp mutantscan -s
Volatile Systems Volatility Framework 2.0
Phys.Addr. Obj Type   #Ptr #Hnd Signal Thread     CID        Name
0x07f955a0 0x0000000e    2    1      1 0x00000000            'TapiSrv_Perf_Library_Lock_PID_5d0'
0x081b5ce8 0x0000000e    2    1      1 0x00000000            'WininetProxyRegistryMutex'
0x08ffccc8 0x0000000e    3    2      1 0x00000000            'ZoneAttributeCacheCounterMutex'
0x099f21f8 0x0000000e    2    1      1 0x00000000            '_!MSFTHISTORY!_'
0x099f2e58 0x0000000e    2    1      1 0x00000000            'ZonesCacheCounterMutex'
0x09aa83a0 0x0000000e    2    1      1 0x00000000            'ZonesLockedCacheCounterMutex'
0x09aa8bd0 0x0000000e    2    1      1 0x00000000            'ZonesCacheCounterMutex'
0x09d06c18 0x0000000e    2    1      1 0x00000000            'VMwareGuestDnDDataMutex'
0x0afe45d8 0x0000000e    2    1      1 0x00000000            '__?_c:_programdata_microsoft_rac_temp_sql4c79.tmp:x'
0x0b6ea040 0x0000000e    2    1      0 0x83ecd030 2520:2616  'F659A567-8ACB-4E4A-92A7-5C2DD1884F72'
0x0be081e8 0x0000000e    2    1      1 0x00000000            'BITS_Perf_Library_Lock_PID_5d0'
[snip]
```

## symlinkscan ##

This plugin scans for symbolic link objects and outputs their information.

```
$ python vol.py -f win7.dd --profile=Win7SP0x86 symlinkscan
Volatile Systems Volatility Framework 2.1_alpha
Offset(P)  #Ptr #Hnd CreateTime               From                 To
0x00be60d8    1    0 2010-06-16 15:24:28      Global               '\\GLOBAL??'
0x00beabd0    1    0 2010-06-16 15:24:28      DosDevices           '\\??'
0x04675030    1    0 2010-06-16 15:27:40      {E2F8A220-AF88-446C-9A55-453E58DD3A33} '\\Device\\NDMP13'
0x05e02fe8    1    0 2010-06-16 19:46:13      PROCEXP113           '\\Device\\PROCEXP113'
0x09700bb0    1    0 2010-06-16 15:25:11      Root#MS_PPTPMINIPORT#0000#{cac88484-7515-4c03-82e6-71a87abac361} '\\Device\\0000003d'
0x09700dd8    1    0 2010-06-16 15:25:11      Root#MS_NDISWANIPV6#0000#{cac88484-7515-4c03-82e6-71a87abac361} '\\Device\\0000003b'
0x0a040d28    1    0 2010-06-16 15:25:11      Root#UMBUS#0000#{65a9a6cf-64cd-480b-843e-32c86e1ba19f} '\\Device\\00000043'
0x0e725450    1    0 2010-06-16 15:26:58      Global               '\\Global??'
0x0eae33f0    1    0 2010-06-16 15:26:57      Global               '\\Global??'
0x15780150    1    0 2010-06-16 15:25:11      Root#SYSTEM#0000#{4747b320-62ce-11cf-a5d6-28db04c10000} '\\Device\\00000042'
0x157806b8    1    0 2010-06-16 15:25:11      Root#SYSTEM#0000#{53172480-4791-11d0-a5d6-28db04c10000} '\\Device\\00000042'
0x15780a90    1    0 2010-06-16 15:25:11      Root#SYSTEM#0000#{cf1dda2c-9743-11d0-a3ee-00a0c9223196} '\\Device\\00000042'
0x15780e50    1    0 2010-06-16 15:25:11      Root#MS_SSTPMINIPORT#0000#{cac88484-7515-4c03-82e6-71a87abac361} '\\Device\\0000003e'
0x15ec5820    1    0 2010-06-16 15:25:29      $VDMLPT1             '\\Device\\ParallelVdm0'
0x160c4a38    1    0 2010-06-16 15:25:29      vmmemctl             '\\Device\\vmmemctl'
0x1655c890    1    0 2010-06-16 15:25:29      MpsDevice            '\\Device\\MPS'
[snip]
```

## thrdscan ##

To scan for ETHREAD objects in physical memory, use the thrdscan command. Since an ETHREAD contains fields that identify its parent process, you can use this technique to find hidden processes. One such use case is documented in the [threads](http://code.google.com/p/volatility/wiki/CommandReference#threads) command.

```
$ python vol.py --profile=Win7SP0x86 -f win7.dmp thrdscan
Volatile Systems Volatility Framework 2.0
Offset     PID    TID    Create Time               Exit Time                 StartAddr
---------- ------ ------ ------------------------- ------------------------- ----------
0x0637f030   1344 140                                                        0x778e64d8
0x06389d48    848 852                                                        0x778e64d8
0x064470f8    508 780                                                        0x778e64d8
0x064474b8    508 776                              2010-07-06 22:30:03       0x778e64d8
0x06447c10    728 772                                                        0x99f10ac8
0x0658fd48    424 2004                                                       0x778e64d8
0x06a87d48   2520 2552                             2010-07-06 22:39:15       0x778e64d8
0x06a902d8   1140 704                                                        0x778e64d8
0x06a908d0   1488 580                                                        0x778e64d8
0x06d3c820   1880 1220                                                       0x778e64d8
0x06e98d48   2312 2316                                                       0x778e64d8
0x06fa7d48   1156 1784                             2010-07-06 22:38:01       0x778e64d8
[snip]
```

# Networking #

## connections ##

To view the active connections, use the connections command. This walks the singly-linked list of connection structures pointed to by a non-exported symbol in the tcpip.sys module. This command is for Windows XP and Windows 2003 Server only.

```
$ python vol.py -f Bob.vmem connections
Volatile Systems Volatility Framework 2.0
 Offset(V)  Local Address             Remote Address            Pid   
---------- ------------------------- ------------------------- ------ 
0x81c6a9f0 192.168.0.176:1176        212.150.164.203:80           888
0x82123008 192.168.0.176:1184        193.104.22.71:80             880
0x81cd4270 192.168.0.176:2869        192.168.0.1:30379           1244
0x81cd4270 127.0.0.1:1168            127.0.0.1:1169               888
0x81e41108 127.0.0.1:1169            127.0.0.1:1168               888
0x82108890 192.168.0.176:1178        212.150.164.203:80          1752
0x82210440 192.168.0.176:1185        193.104.22.71:80             880
0x8207ac58 192.168.0.176:1171        66.249.90.104:80             888
0x81cef808 192.168.0.176:2869        192.168.0.1:30380              4
0x81cc57c0 192.168.0.176:1189        192.168.0.1:9393            1244
0x8205a448 192.168.0.176:1172        66.249.91.104:80             888
```

Output includes the virtual offset of the `_TCPT_OBJECT` by default.  The physical offset is obtained with the -P switch:

```
$ python vol.py -f Bob.vmem connections -P
Volatile Systems Volatility Framework 2.0
 Offset(P)  Local Address             Remote Address            Pid   
---------- ------------------------- ------------------------- ------ 
0x01e6a9f0 192.168.0.176:1176        212.150.164.203:80           888
0x02323008 192.168.0.176:1184        193.104.22.71:80             880
0x01ed4270 192.168.0.176:2869        192.168.0.1:30379           1244
0x01ed4270 127.0.0.1:1168            127.0.0.1:1169               888
0x02041108 127.0.0.1:1169            127.0.0.1:1168               888
0x02308890 192.168.0.176:1178        212.150.164.203:80          1752
0x02410440 192.168.0.176:1185        193.104.22.71:80             880
0x0227ac58 192.168.0.176:1171        66.249.90.104:80             888
0x01eef808 192.168.0.176:2869        192.168.0.1:30380              4
0x01ec57c0 192.168.0.176:1189        192.168.0.1:9393            1244
0x0225a448 192.168.0.176:1172        66.249.91.104:80             888
```

## connscan ##

To find connection structures using pool tag scanning, use the connscan command. This can find artifacts from previous connections that have since been terminated. In the output below, you'll notice some fields have been partially overwritten, but some of the information is still accurate. Thus, while it may find false positives sometimes, you also get the benefit of detecting as much information as possible. This command is for Windows XP and Windows 2003 Server only.

```
$ python vol.py -f Bob.vmem connscan
Volatile Systems Volatility Framework 2.0
 Offset     Local Address             Remote Address            Pid   
---------- ------------------------- ------------------------- ------ 
0x01e6a9f0 192.168.0.176:1176        212.150.164.203:80           888
0x01ec57c0 192.168.0.176:1189        192.168.0.1:9393            1244
0x01ed4270 192.168.0.176:2869        192.168.0.1:30379           1244
0x01eef808 192.168.0.176:2869        192.168.0.1:30380              4
0x01ffa7f8 0.0.0.0:0                 80.206.204.129:0               0
0x02041108 127.0.0.1:1168            127.0.0.1:1169               888
0x0225a448 192.168.0.176:1172        66.249.91.104:80             888
0x0226ac58 127.0.0.1:1169            127.0.0.1:1168               888
0x0227ac58 192.168.0.176:1171        66.249.90.104:80             888
0x02308890 192.168.0.176:1178        212.150.164.203:80          1752
0x02323008 192.168.0.176:1184        193.104.22.71:80             880
0x02410440 192.168.0.176:1185        193.104.22.71:80             880
```

## sockets ##

To detect listening sockets for any protocol (TCP, UDP, RAW, etc), use the sockets command. This walks a singly-linked list of socket structures which is pointed to by a non-exported symbol in the tcpip.sys module. This command is for Windows XP and Windows 2003 Server only.

```
$ python vol.py -f silentbanker.vmem --profile=WinXPSP3x86 sockets
Volatile Systems Volatility Framework 2.0
 Offset(V)  PID    Port   Proto  Address        Create Time               
---------- ------ ------ ------ -------------- -------------------------- 
0x80fd1008      4      0     47 0.0.0.0            2010-08-11 06:08:00       
0xff362d18   1088   1066     17 0.0.0.0            2010-08-15 18:54:13       
0xff258008    688    500     17 0.0.0.0            2010-08-11 06:06:35       
0xff367008      4    445      6 0.0.0.0            2010-08-11 06:06:17       
0x80ffc128    936    135      6 0.0.0.0            2010-08-11 06:06:24       
0xff225b70    688      0    255 0.0.0.0            2010-08-11 06:06:35       
0xff225b70   1028    123     17 127.0.0.1          2010-08-15 19:01:51       
0x80fce930   1088   1025     17 0.0.0.0            2010-08-11 06:06:38       
0xff127d28    216   1026      6 127.0.0.1          2010-08-11 06:06:39       
0xff2608c0   1088   1053     17 0.0.0.0            2010-08-15 18:54:09       
0x80fdc708   1884   1051     17 127.0.0.1          2010-08-15 18:54:07       
0x80fdc708   1148   1900     17 127.0.0.1          2010-08-15 19:01:51         
[snip]
```

Output includes the virtual offset of the `_ADDRESS_OBJECT` by default.  The physical offset is obtained with the -P switch:

```
$ python vol.py -f silentbanker.vmem --profile=WinXPSP3x86 sockets -P
Volatile Systems Volatility Framework 2.0
 Offset(P)  PID    Port   Proto  Address        Create Time               
---------- ------ ------ ------ -------------- -------------------------- 
0x01134008      4      0     47 0.0.0.0            2010-08-11 06:08:00       
0x04c2dd18   1088   1066     17 0.0.0.0            2010-08-15 18:54:13       
0x05f44008    688    500     17 0.0.0.0            2010-08-11 06:06:35       
0x04be7008      4    445      6 0.0.0.0            2010-08-11 06:06:17       
0x0115f128    936    135      6 0.0.0.0            2010-08-11 06:06:24       
0x06237b70    688      0    255 0.0.0.0            2010-08-11 06:06:35       
0x06237b70   1028    123     17 127.0.0.1          2010-08-15 19:01:51       
0x01131930   1088   1025     17 0.0.0.0            2010-08-11 06:06:38       
0x02daad28    216   1026      6 127.0.0.1          2010-08-11 06:06:39       
0x05e3c8c0   1088   1053     17 0.0.0.0            2010-08-15 18:54:09       
0x0113f708   1884   1051     17 127.0.0.1          2010-08-15 18:54:07       
0x0113f708   1148   1900     17 127.0.0.1          2010-08-15 19:01:51        
[snip]     
```


## sockscan ##

To find socket structures using pool tag scanning, use the sockscan command. As with connscan, this can pick up residual data and artifacts from previous sockets, and it only applies to Windows XP and Windows 2003 Server.

```
$ python vol.py -f silentbanker.vmem --profile=WinXPSP3x86 sockscan
Volatile Systems Volatility Framework 2.0
 Offset     PID    Port   Proto  Address        Create Time               
---------- ------ ------ ------ -------------- -------------------------- 
0x00096e08   1884   1069      6 0.0.0.0            2010-08-15 18:54:13       
0x0089bab8   1148   1900     17 127.0.0.1          2010-08-15 18:53:56       
0x01073910   1884   1077      6 0.0.0.0            2010-08-15 18:54:14       
0x01073e98   1884   1082      6 0.0.0.0            2010-08-15 18:54:15       
0x0107aba8   1884   1057      6 0.0.0.0            2010-08-15 18:54:10       
0x0107c500   1884   1073      6 0.0.0.0            2010-08-15 18:54:13       
0x0107db70   1884   1072      6 0.0.0.0            2010-08-15 18:54:13       
0x010f1e98   1884   1079      6 0.0.0.0            2010-08-15 18:54:15       
0x01120c40      4    445     17 0.0.0.0            2010-08-11 06:06:17       
0x0112ee30   1884   1071      6 0.0.0.0            2010-08-15 18:54:13       
0x01131930   1088   1025     17 0.0.0.0            2010-08-11 06:06:38       
0x01134008      4      0     47 0.0.0.0            2010-08-11 06:08:00       
0x01139e98   1884   1087      6 0.0.0.0            2010-08-15 18:54:17       
0x0113b7d0   1884   1076      6 0.0.0.0            2010-08-15 18:54:14       
0x011568a8      4    137     17 172.16.176.143     2010-08-15 18:53:56       
0x0115f128    936    135      6 0.0.0.0            2010-08-11 06:06:24 
[snip]
```

## netscan ##

To scan for network artifacts in Windows Vista, Windows 2008 Server and Windows 7 memory dumps, use the netscan command. This finds TCP endpoints, TCP listeners, UDP endpoints, and UDP listeners. It distinguishes between IPv4 and IPv6, prints the local and remote IP (if applicable), the local and remote port (if applicable), the time when the socket was bound or when the connection was established, and the current state (for TCP connections only). For more information, see [Volatility's New Netscan Module.](http://mnin.blogspot.com/2011/03/volatilitys-new-netscan-module.html)

```
$ python vol.py --profile=Win7SP0x86 -f win7.dmp netscan 
Volatile Systems Volatility Framework 2.0
Offset     Proto    Local Address                  Foreign Address      State            Pid      Owner          Created
0xca3008   TCPv4    192.168.181.133:139            0.0.0.0:0            LISTENING        4        System         1970-01-01 00:00:00 
0x3027008  TCPv4    0.0.0.0:49155                  0.0.0.0:0            LISTENING        876      svchost.exe    1970-01-01 00:00:00 
0x3027008  TCPv6    :::49155                       :::0                 LISTENING        876      svchost.exe    1970-01-01 00:00:00 
0x5ac5c80  TCPv4    0.0.0.0:49153                  0.0.0.0:0            LISTENING        728      svchost.exe    1970-01-01 00:00:00 
0x5ac5c80  TCPv6    :::49153                       :::0                 LISTENING        728      svchost.exe    1970-01-01 00:00:00 
0xbfe1208  TCPv4    0.0.0.0:49152                  0.0.0.0:0            LISTENING        384      wininit.exe    1970-01-01 00:00:00 
0xbfe1208  TCPv6    :::49152                       :::0                 LISTENING        384      wininit.exe    1970-01-01 00:00:00 
0xbfe1648  TCPv4    0.0.0.0:49152                  0.0.0.0:0            LISTENING        384      wininit.exe    1970-01-01 00:00:00 
0xc1fad48  TCPv4    0.0.0.0:49153                  0.0.0.0:0            LISTENING        728      svchost.exe    1970-01-01 00:00:00 
0xc5ae148  TCPv4    0.0.0.0:135                    0.0.0.0:0            LISTENING        680      svchost.exe    1970-01-01 00:00:00 
0xc6f5bb0  TCPv4    0.0.0.0:135                    0.0.0.0:0            LISTENING        680      svchost.exe    1970-01-01 00:00:00 
0xc6f5bb0  TCPv6    :::135                         :::0                 LISTENING        680      svchost.exe    1970-01-01 00:00:00 
0xd816270  TCPv4    0.0.0.0:445                    0.0.0.0:0            LISTENING        4        System         1970-01-01 00:00:00 
0xd816270  TCPv6    :::445                         :::0                 LISTENING        4        System         1970-01-01 00:00:00 
0xdc5a368  TCPv4    0.0.0.0:49156                  0.0.0.0:0            LISTENING        492      services.exe   1970-01-01 00:00:00 
0xde59008  TCPv4    0.0.0.0:49156                  0.0.0.0:0            LISTENING        492      services.exe   1970-01-01 00:00:00 
0xde59008  TCPv6    :::49156                       :::0                 LISTENING        492      services.exe   1970-01-01 00:00:00 
0xed29808  TCPv4    0.0.0.0:49155                  0.0.0.0:0            LISTENING        876      svchost.exe    1970-01-01 00:00:00 
0xee49450  TCPv4    0.0.0.0:49154                  0.0.0.0:0            LISTENING        500      lsass.exe      1970-01-01 00:00:00 
0xee52d98  TCPv4    0.0.0.0:49154                  0.0.0.0:0            LISTENING        500      lsass.exe      1970-01-01 00:00:00 
0xee52d98  TCPv6    :::49154                       :::0                 LISTENING        500      lsass.exe      1970-01-01 00:00:00 
0x4b5c008  TCPv4    0.0.0.0:49170                  65.54.89.134:80      CLOSED           876      svchost.exe    1970-01-01 00:00:00 
0x9b3ca30  TCPv4    192.168.181.133:49167          192.168.181.2:80     CLOSED           876      svchost.exe    1970-01-01 00:00:00 
0xee8e0c8  TCPv4    0.0.0.0:49159                  65.54.89.134:80      CLOSED           876      svchost.exe    1970-01-01 00:00:00 
0xf78d468  TCPv4    0.0.0.0:49164                  65.54.89.135:80      CLOSED           876      svchost.exe    1970-01-01 00:00:00 
0x3165c8   UDPv4    0.0.0.0:0                      *:*                                   1056     svchost.exe    2010-07-06 22:40:01 
0x3165c8   UDPv6    :::0                           *:*                                   1056     svchost.exe    2010-07-06 22:40:01 
0xea9868   UDPv4    127.0.0.1:1900                 *:*                                   1920     svchost.exe    2010-07-06 22:33:18 
0x12d6738  UDPv4    0.0.0.0:0                      *:*                                   1140     svchost.exe    2010-07-06 22:31:23 
0x12d6738  UDPv6    :::0                           *:*                                   1140     svchost.exe    2010-07-06 22:31:23
[snip]
```

# Registry #

Volatility is the only memory forensics framework with the ability to carve registry data. For more information, see BDG's [Memory Registry Tools](http://moyix.blogspot.com/2009/01/memory-registry-tools.html) and [Registry Code Updates](http://moyix.blogspot.com/2009/01/registry-code-updates.html).

## hivescan ##

To find the physical addresses of CMHIVEs (registry hives) in memory, use the hivescan command. For more information, see BDG's [Enumerating Registry Hives](http://moyix.blogspot.com/2008/02/enumerating-registry-hives.html).

```
$ python vol.py --profile=Win7SP0x86 -f win7.dmp hivescan
Volatile Systems Volatility Framework 2.0
Offset          (hex)          
1493000         0x0016c808
37018064        0x0234d9d0
66253488        0x03f2f2b0
73746896        0x046549d0
86327304        0x05254008
148837272       0x08df1398
148838864       0x08df19d0
153573840       0x092759d0
[snip]
```

## hivelist ##

To locate the virtual addresses of registry hives in memory, and the full paths to the corresponding hive on disk, use the hivelist command.

```
$ python vol.py --profile=Win7SP0x86 -f win7.dmp hivelist 
Volatile Systems Volatility Framework 2.0
Virtual     Physical    Name
0x99f0d008  0x0da7d008  \??\C:\Windows\ServiceProfiles\LocalService\NTUSER.DAT
0x9c1692b0  0x03f2f2b0  \??\C:\Users\admin\ntuser.dat
0x9c7dc5c8  0x0d46d5c8  \??\C:\Users\admin\AppData\Local\Microsoft\Windows\UsrClass.dat
0x9cc839d0  0x046549d0  \??\C:\Windows\System32\SMI\Store\Machine\SCHEMA.DAT
0x82baa140  0x02baa140  [no name]
0x8780c008  0x0ac97008  [no name]
0x878197b8  0x0ab5e7b8  \REGISTRY\MACHINE\SYSTEM
0x878419d0  0x0a7489d0  \REGISTRY\MACHINE\HARDWARE
0x8c089398  0x08df1398  \SystemRoot\System32\Config\SOFTWARE
0x8c0899d0  0x08df19d0  \SystemRoot\System32\Config\SECURITY
0x8c18f9d0  0x092759d0  \SystemRoot\System32\Config\DEFAULT
0x8e23e008  0x05254008  \SystemRoot\System32\Config\SAM
0x980e75e0  0x0dccd5e0  \??\C:\Windows\System32\config\COMPONENTS
0x984709d0  0x0234d9d0  \Device\HarddiskVolume1\Boot\BCD
0x99e22808  0x0016c808  \??\C:\System Volume Information\Syscache.hve
[snip]
```

## printkey ##

To display the subkeys, values, data, and data types contained within a specified registry key, use the printkey command. By default, printkey will search all hives and print the key information (if found) for the requested key.  Therefore, if the key is located in more than one hive, the information for the key will be printed for each hive that contains it.

Say you want to traverse into the HKEY\_LOCAL\_MACHINE\Microsoft\Security Center\Svc key. You can do that in the following manner. Note: if you're running Volatility on Windows, enclose the key in double quotes (see [issue 166](https://code.google.com/p/volatility/issues/detail?id=166)).

```
$ python vol.py --profile=Win7SP0x86 -f win7.dmp printkey -K "Microsoft\Security Center\Svc"
Volatile Systems Volatility Framework 2.0
Legend: (S) = Stable   (V) = Volatile

----------------------------
Registry: \SystemRoot\System32\Config\SOFTWARE
Key name: Svc (S)
Last updated: 2010-07-06 22:33:20 

Subkeys:
  (V) Vol

Values:
REG_QWORD     VistaSp1        : (S) 128920209537502489
REG_DWORD     AntiVirusOverride : (S) 0
REG_DWORD     AntiSpywareOverride : (S) 0
REG_DWORD     FirewallOverride : (S) 0
```

Here you can see output for more than one hive containing the key "Software\Microsoft\Windows NT\CurrentVersion\Winlogon"

```
$ python vol.py -f ds_fuzz_hidden_proc.img --profile=WinXPSP3x86 printkey -K "Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
Volatile Systems Volatility Framework 2.0
Legend: (S) = Stable (V) = Volatile

----------------------------
Registry: \Device\HarddiskVolume1\Documents and Settings\NetworkService\NTUSER.DAT
Key name: Winlogon (S)
Last updated: 2008-11-26 07:38:23

Subkeys:

Values:
REG_SZ ParseAutoexec : (S) 1
REG_SZ ExcludeProfileDirs : (S) Local Settings;Temporary Internet Files;History;Temp
REG_DWORD BuildNumber : (S) 2600
----------------------------
Registry: \Device\HarddiskVolume1\WINDOWS\system32\config\default
Key name: Winlogon (S)
Last updated: 2008-11-26 07:39:40

Subkeys:

Values:
REG_SZ ParseAutoexec : (S) 1
REG_SZ ExcludeProfileDirs : (S) Local Settings;Temporary Internet Files;History;Temp
REG_DWORD BuildNumber : (S) 2600
[snip]
```

Printkey also accepts a virtual address to the hive in which you want to search for a key. For example, to see the contents of HKEY\_LOCAL\_MACHINE, do the following:

```
$ python vol.py --profile=Win7SP0x86 -f win7.dmp printkey -o 0x8c089398 
Volatile Systems Volatility Framework 2.0
Legend: (S) = Stable   (V) = Volatile

----------------------------
Registry: User Specified
Key name: CMI-CreateHive{3D971F19-49AB-4000-8D39-A6D9C673D809} (S)
Last updated: 2010-03-10 22:48:38 

Subkeys:
  (S) AccessData
  (S) BreakPoint
  (S) Classes
  (S) Clients
  (S) Foxit Software
  (S) Intel
  (S) Microsoft
  (S) Mozilla
  (S) mozilla.org
[snip]
```

## hivedump ##

To recursively list all subkeys in a hive, use the hivedump command and pass it the virtual address to the desired hive.

```
$ python vol.py --profile=Win7SP0x86 -f win7.dmp hivedump -o 0x8e23e008
2010-03-09 19:50:19  \CMI-CreateHive{899121E8-11D8-44B6-ACEB-301713D5ED8C}\SAM\Domains\Builtin\Aliases\Names
2010-03-09 19:50:19  \CMI-CreateHive{899121E8-11D8-44B6-ACEB-301713D5ED8C}\SAM\Domains\Builtin\Aliases\Names\Administrators
2010-03-09 19:50:19  \CMI-CreateHive{899121E8-11D8-44B6-ACEB-301713D5ED8C}\SAM\Domains\Builtin\Aliases\Names\Backup Operators
2010-03-09 19:50:19  \CMI-CreateHive{899121E8-11D8-44B6-ACEB-301713D5ED8C}\SAM\Domains\Builtin\Aliases\Names\Cryptographic Operators
2010-03-09 19:50:19  \CMI-CreateHive{899121E8-11D8-44B6-ACEB-301713D5ED8C}\SAM\Domains\Builtin\Aliases\Names\Distributed COM Users
2010-03-09 19:50:19  \CMI-CreateHive{899121E8-11D8-44B6-ACEB-301713D5ED8C}\SAM\Domains\Builtin\Aliases\Names\Event Log Readers
2010-03-09 19:50:19  \CMI-CreateHive{899121E8-11D8-44B6-ACEB-301713D5ED8C}\SAM\Domains\Builtin\Aliases\Names\Guests
2010-03-09 19:50:19  \CMI-CreateHive{899121E8-11D8-44B6-ACEB-301713D5ED8C}\SAM\Domains\Builtin\Aliases\Names\IIS_IUSRS
2010-03-09 19:50:19  \CMI-CreateHive{899121E8-11D8-44B6-ACEB-301713D5ED8C}\SAM\Domains\Builtin\Aliases\Names\Network Configuration Operators
2010-03-09 19:50:19  \CMI-CreateHive{899121E8-11D8-44B6-ACEB-301713D5ED8C}\SAM\Domains\Builtin\Aliases\Names\Performance Log Users
2010-03-09 19:50:19  \CMI-CreateHive{899121E8-11D8-44B6-ACEB-301713D5ED8C}\SAM\Domains\Builtin\Aliases\Names\Performance Monitor Users
2010-03-09 19:50:19  \CMI-CreateHive{899121E8-11D8-44B6-ACEB-301713D5ED8C}\SAM\Domains\Builtin\Aliases\Names\Power Users
2010-03-09 19:50:19  \CMI-CreateHive{899121E8-11D8-44B6-ACEB-301713D5ED8C}\SAM\Domains\Builtin\Aliases\Names\Remote Desktop Users
2010-03-09 19:50:19  \CMI-CreateHive{899121E8-11D8-44B6-ACEB-301713D5ED8C}\SAM\Domains\Builtin\Aliases\Names\Replicator
2010-03-09 19:50:19  \CMI-CreateHive{899121E8-11D8-44B6-ACEB-301713D5ED8C}\SAM\Domains\Builtin\Aliases\Names\Users
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
$ ./vol.py -f XPSP3.vmem --profile=WinXPSP3x86 printkey -K "ControlSet001\Control\lsa" --no-cache

$ ./vol.py -f XPSP3.vmem --profile=WinXPSP3x86 printkey -K "SAM\Domains\Account" --no-cache
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

# Crash Dumps, Hibernation, and Conversion #

## crashinfo ##

Information from the crashdump header can be printed using the crashinfo command.  You will see information like that of the Microsoft [dumpcheck](http://support.microsoft.com/kb/119490) utility.

```
$ python vol.py crashinfo -f win7.dmp --profile=Win7SP0x86
Volatile Systems Volatility Framework 2.0
DUMP_HEADER32:
 Majorversion:         0x0000000f (15)
 Minorversion:         0x00001db0 (7600)
 KdSecondaryVersion    0x00000041
 DirectoryTableBase    0x00185000
 PfnDataBase           0x83a00000
 PsLoadedModuleList    0x82984810
 PsActiveProcessHead   0x8297ce98
 MachineImageType      0x0000014c
 NumberProcessors      0x00000001
 BugCheckCode          0x5454414d
 PaeEnabled            0x00000001
 KdDebuggerDataBlock   0x82964be8
 ProductType           0x45474150
 SuiteMask             0x45474150
 WriterStatus          0x45474150

Physical Memory Description:
Number of runs: 3
FileOffset    Start Address    Length
00001000      00001000         0009e000
0009f000      00100000         3fdf0000
3fe8f000      3ff00000         00100000
3ff8e000      3ffff000
```

## hibinfo ##

The hibinfo command reveals additional information stored in the hibernation file, including the state of the Control Registers, such as CR0, etc.  It also identifies the time at which the hibernation file was created, the state of the hibernation file, and the version of windows being hibernated.  Example output for the function is shown below:

```

$ python vol.py -f hiberfil.sys hibinfo
Volatile Systems Volatility Framework 2.0
IMAGE_HIBER_HEADER:
 Signature: hibr
 SystemTime: 2009-10-03 15:33:26 

Control registers flags
 CR0: 80010031
 CR0[PAGING]: 1
 CR3: 1a300060
 CR4: 000006f9
 CR4[PSE]: 1
 CR4[PAE]: 1

Windows Version is 5.1 (2600)
```

## imagecopy ##

The imagecopy command allows one to convert any existing type of address space (such as a crashdump, hibernation file, or live firewire session) to a raw memory image.  The profile should be specified for any address space from a machine other than Windows XP SP2.  Also the output file is specified with the -O flag.  The progress is updated as the file is converted:

```
$ python vol.py imagecopy -f win7.dmp --profile=Win7SP0x86 -O win7.raw
Volatile Systems Volatility Framework 2.0
Writing data (5.00 MB chunks): |.....................................................|
```

# Malware and Rootkits #

Although all Volatility commands can help you hunt malware in one way or another, there are a few designed specifically for hunting rootkits and malicious code. The most comprehensive documentation for these commands can be found in the [Malware Analyst's Cookbook and DVD: Tools and Techniques For Fighting Malicious Code](http://www.amazon.com/dp/0470613033).  The following malware plugins are available in the [malware.py](http://malwarecookbook.googlecode.com/svn/trunk/malware.py) plugin file in the [Malware Cookbook SVN](http://code.google.com/p/malwarecookbook/source/browse/#svn%2Ftrunk).  Place the malware.py file into the "volatility/plugins" directory to install.

When possible, we use [publicly available images](http://code.google.com/p/volatility/wiki/FAQ#Are_there_any_public_memory_samples_available_that_I_can_use_for) for the examples, so you can verify on your end.

## malfind ##

The malfind command has several purposes. You can use it to find hidden or injected code/DLLs in user mode memory, based on characteristics such as VAD tag and page permissions. You can also use it to locate any sequence of bytes, regular expressions, ANSI strings, or Unicode strings in user mode or kernel memory.

Note: malfind does not detect DLLs injected into a process using CreateRemoteThread->LoadLibrary. DLLs injected with this technique are not hidden and thus you can view them with [dlllist](http://code.google.com/p/volatility/wiki/CommandReference#dlllist). The purpose of malfind is to locate DLLs that standard methods/tools do not see. For more information see [Issue #178](https://code.google.com/p/volatility/issues/detail?id=#178).

Here is an example of using it to detect the presence of Zeus. The first memory segment (starting at 0x01600000) was detected because its executable and has a VadS tag...which means there is memory mapped file already occupying the space. Based on a disassembly of the data found at this address, it seems to contain some API hook trampoline stubs.

The second memory segment (starting at 0x015D0000) was detected because it contained an executable that isn't listed in the PEB's module lists. A copy of the PE file was saved to hidden\_dumps/explorer.exe.4a065d0.015d0000-015f5fff.dmp. This is an unpacked copy of the Zeus binary that was injected into explorer.exe.

```
$ python vol.py -f zeus.vmem malfind -p 1724 -D hidden_dumps/
Volatile Systems Volatility Framework 2.0
Name                 Pid    Start      End        Tag    Hits Protect
explorer.exe           1724 0x01600000 0x01600FFF VadS      0      6 (MM_EXECUTE_READWRITE)
Dumped to: hidden_dumps/explorer.exe.4a065d0.01600000-01600fff.dmp
0x01600000   b8 35 00 00 00 e9 cd d7 30 7b b8 91 00 00 00 e9    .5......0{......
0x01600010   4f df 30 7b 8b ff 55 8b ec e9 ef 17 c1 75 8b ff    O.0{..U......u..
0x01600020   55 8b ec e9 95 76 bc 75 8b ff 55 8b ec e9 be 53    U....v.u..U....S
0x01600030   bd 75 8b ff 55 8b ec e9 d6 18 c1 75 8b ff 55 8b    .u..U......u..U.
0x01600040   ec e9 14 95 bc 75 8b ff 55 8b ec e9 4f 7e bf 75    .....u..U...O~.u
0x01600050   8b ff 55 8b ec e9 0a 32 bd 75 8b ff 55 8b ec e9    ..U....2.u..U...
0x01600060   7d 61 bc 75 6a 2c 68 b8 8d 1c 77 e9 01 8c bc 75    }a.uj,h...w....u
0x01600070   8b ff 55 8b ec e9 c4 95 4b 70 8b ff 55 8b ec e9    ..U.....Kp..U...

Disassembly:
01600000: b835000000                       MOV EAX, 0x35
01600005: e9cdd7307b                       JMP 0x7c90d7d7
0160000a: b891000000                       MOV EAX, 0x91
0160000f: e94fdf307b                       JMP 0x7c90df63
01600014: 8bff                             MOV EDI, EDI
01600016: 55                               PUSH EBP
01600017: 8bec                             MOV EBP, ESP
01600019: e9ef17c175                       JMP 0x7721180d
0160001e: 8bff                             MOV EDI, EDI
01600020: 55                               PUSH EBP

explorer.exe           1724 0x015D0000 0x015F5FFF VadS      0      6 (MM_EXECUTE_READWRITE)
Dumped to: hidden_dumps/explorer.exe.4a065d0.015d0000-015f5fff.dmp
0x015d0000   4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00    MZ..............
0x015d0010   b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00    ........@.......
0x015d0020   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
0x015d0030   00 00 00 00 00 00 00 00 00 00 00 00 d0 00 00 00    ................
0x015d0040   0e 1f ba 0e 00 b4 09 cd 21 b8 01 4c cd 21 54 68    ........!..L.!Th
0x015d0050   69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f    is program canno
0x015d0060   74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20    t be run in DOS 
0x015d0070   6d 6f 64 65 2e 0d 0d 0a 24 00 00 00 00 00 00 00    mode....$.......
```

Now let's say you wanted to search for a pattern in process memory. You can create a YARA rules file and pass it to malfind as --yara-rules. Or, if you're just looking for something simple, and only plan to do the search a few times, then you can specify the criteria on command line instead. Here are some examples:

Search for signatures defined in the file rules.yar, in any process

```
$ python vol.py -f zeus.vmem malfind -D hidden_dumps --yara-rules=rules.yar
```

Search for a simple string in any process:

```
$ python vol.py -f zeus.vmem malfind -D hidden_dumps --yara-rules="simpleStringToFind"
```

Search for a byte pattern in kernel memory. This does not check the entire range of kernel memory, it only checks the memory that belongs to loaded kernel drivers. For example, TDL3 applies a hard-patch to atapi.sys on disk. In particular, it adds some shell code to the .rsrc section of the file, and then modifies the AddressOfEntryPoint so that it points at the shell code. This is TDL3's main persistence method. One of the unique instructions in the shell code is `cmp dword ptr [eax], ‘3LDT’` so I made a YARA signature from that.

```
$ python vol.py -f tdl3.dmp malfind --yara-rules=rules.yar -D hidden_dumps --kernel
Volatile Systems Volatility Framework 2.0
Name                 Pid    Start      End        Tag    Hits Protect
vmscsi.sys           -      0xF9DB8000 0xF9DBB000 -         1 -      (Unknown)
Hit: 8b00813854444c33755a
0xf9dba4c3   8b 00 81 38 54 44 4c 33 75 5a 8b 45 f4 05 fd 29    ...8TDL3uZ.E...)
0xf9dba4d3   b7 f0 50 b8 08 03 00 00 8b 80 00 00 df ff ff b0    ..P.............
0xf9dba4e3   00 01 00 00 b8 08 03 00 00 8b 80 00 00 df ff 8b    ................
0xf9dba4f3   40 04 8b 4d ec 03 41 20 ff d0 ff 75 e0 b8 08 03    @..M..A ...u....
0xf9dba503   00 00 8b 80 00 00 df ff ff b0 00 01 00 00 b8 08    ................
0xf9dba513   03 00 00 8b 80 00 00 df ff 8b 00 05 84 03 00 00    ................
0xf9dba523   ff d0 eb 10 8b 45 e0 8b 40 0c 89 45 e0 e9 66 fe    .....E..@..E..f.
0xf9dba533   ff ff 33 c0 c9 c2 08 00 5e f8 a8 f2 fe 63 ec d0    ..3.....^....c..
```

Search for a given byte pattern in a particular process:

```
$ python vol.py -f zeus.vmem malfind -D hidden_dumps --yara-rules="{eb 90 ff e4 88 32 0d}" --pid=624
```

Search for a regular expression in a particular process:

```
$ python vol.py -f zeus.vmem malfind -D hidden_dumps --yara-rules="/my(regular|expression{0,2})/" --pid=624
```

## svcscan ##

Volatility is the only memory forensics framework with the ability to list Windows services. To see which services are registered on your memory image, use the svcscan command. The output shows the process ID of each service (if its active and pertains to a usermode process), the service name, service display name, service type, and current status. It also shows the binary path for the registered service - which will be an EXE for usermode services and a driver name for services that run from kernel mode.

The lanmandrv entry displayed below is the name of the service that Laqma installs to load its malicious kernel driver.

```
$ python vol.py svcscan -f laqma.vmem
Volatile Systems Volatility Framework 2.0
Record       Order    Pid      Name             DisplayName                              Type                           State                Path

[snip]

0x6ea738     0xf5     1148     WebClient        WebClient                                SERVICE_WIN32_SHARE_PROCESS    SERVICE_RUNNING      C:\WINDOWS\system32\svchost.exe -k LocalService
0x6ea7c8     0xf6     1028     winmgmt          Windows Management Instrumentation       SERVICE_WIN32_SHARE_PROCESS    SERVICE_RUNNING      C:\WINDOWS\System32\svchost.exe -k netsvcs
0x6ea858     0xf7     -------- WmdmPmSN         Portable Media Serial Number Service     SERVICE_WIN32_SHARE_PROCESS    SERVICE_STOPPED      --------
0x6ea8e8     0xf8     -------- Wmi              Windows Management Instrumentation Driver Extensions SERVICE_WIN32_SHARE_PROCESS    SERVICE_STOPPED      --------
0x6ea970     0xf9     -------- WmiApSrv         WMI Performance Adapter                  SERVICE_WIN32_OWN_PROCESS      SERVICE_STOPPED      --------
0x6eaa00     0xfa     -------- WS2IFSL          Windows Socket 2.0 Non-IFS Service Provider Support Environment SERVICE_KERNEL_DRIVER          SERVICE_RUNNING      \Driver\WS2IFSL
0x6eaa90     0xfb     1028     wscsvc           Security Center                          SERVICE_WIN32_SHARE_PROCESS    SERVICE_RUNNING      C:\WINDOWS\System32\svchost.exe -k netsvcs
0x6eab20     0xfc     1028     wuauserv         Automatic Updates                        SERVICE_WIN32_SHARE_PROCESS    SERVICE_RUNNING      C:\WINDOWS\System32\svchost.exe -k netsvcs
0x6eabb0     0xfd     1028     WZCSVC           Wireless Zero Configuration              SERVICE_WIN32_SHARE_PROCESS    SERVICE_RUNNING      C:\WINDOWS\System32\svchost.exe -k netsvcs
0x6eac40     0xfe     -------- xmlprov          Network Provisioning Service             SERVICE_WIN32_SHARE_PROCESS    SERVICE_STOPPED      --------
0x6eacd0     0xff     -------- lanmandrv        lanmandrv                                SERVICE_KERNEL_DRIVER          SERVICE_RUNNING      \Driver\lanmandrv
```

## ldrmodules ##

There are many ways to hide a DLL. One of the ways involves unlinking the DLL from one (or all) of the linked lists in the PEB. However, when this is done, there is still information contained within the VAD (Virtual Address Descriptor) which identifies the base address of the DLL and its full path on disk. To cross-reference this information (known as memory mapped files) with the 3 PEB lists, use the ldrmodules command.

For each memory mapped PE file, the ldrmodules command prints a 0 or a 1 if the PE exists in the PEB lists.

```
$ python vol.py -f laqma.vmem ldrmodules 
Volatile Systems Volatility Framework 2.0
Pid      Process              Base     InLoad   InInit   InMem    Path
   608 csrss.exe            0x010E0000      0      0      0 \WINDOWS\Fonts\vgasys.fon
   608 csrss.exe            0x75B60000      0      0      0 \WINDOWS\system32\winsrv.dll
   608 csrss.exe            0x77D40000      0      0      0 \WINDOWS\system32\user32.dll
   632 winlogon.exe         0x01000000      1      0      1 \WINDOWS\system32\winlogon.exe
   632 winlogon.exe         0x77DD0000      1      1      1 \WINDOWS\system32\advapi32.dll
   632 winlogon.exe         0x77D40000      1      1      1 \WINDOWS\system32\user32.dll
   676 services.exe         0x01000000      1      0      1 \WINDOWS\system32\services.exe
   676 services.exe         0x758E0000      1      1      1 \WINDOWS\system32\scesrv.dll
   688 lsass.exe            0x01000000      1      0      1 \WINDOWS\system32\lsass.exe
   936 svchost.exe          0x01000000      1      0      1 \WINDOWS\system32\svchost.exe
  1028 svchost.exe          0x01000000      1      0      1 \WINDOWS\system32\svchost.exe
  1028 svchost.exe          0x20000000      1      1      1 \WINDOWS\system32\xpsp2res.dll
  1028 svchost.exe          0x76D30000      1      1      1 \WINDOWS\system32\wmi.dll
  1028 svchost.exe          0x77F60000      1      1      1 \WINDOWS\system32\shlwapi.dll
[snip]
```

Since the PEB and the DLL lists that it contains all exist in user mode, its also possible for malware to hide (or obscure) a DLL by simply overwriting the path. Tools that only look for unlinked entries may miss the fact that malware overwrite C:\bad.dll to show C:\windows\system32\kernel32.dll. So you can also pass -v or --verbose to ldrmodules to see the full path of all entries:

```
$ python vol.py -f laqma.vmem ldrmodules -v
Volatile Systems Volatility Framework 2.0
Pid      Process              Base     InLoad   InInit   InMem    Path

[snip]

  1028 svchost.exe          0x77C10000      1      1      1 \WINDOWS\system32\msvcrt.dll
  Load Path: C:\WINDOWS\system32\msvcrt.dll : msvcrt.dll
  Init Path: C:\WINDOWS\system32\msvcrt.dll : msvcrt.dll
  Mem Path:  C:\WINDOWS\system32\msvcrt.dll : msvcrt.dll
  1028 svchost.exe          0x76D10000      1      1      1 \WINDOWS\system32\clusapi.dll
  Load Path: C:\WINDOWS\System32\CLUSAPI.DLL : CLUSAPI.DLL
  Init Path: C:\WINDOWS\System32\CLUSAPI.DLL : CLUSAPI.DLL
  Mem Path:  C:\WINDOWS\System32\CLUSAPI.DLL : CLUSAPI.DLL
  1028 svchost.exe          0x76E80000      1      1      1 \WINDOWS\system32\rtutils.dll
  Load Path: c:\windows\system32\rtutils.dll : rtutils.dll
  Init Path: c:\windows\system32\rtutils.dll : rtutils.dll
  Mem Path:  c:\windows\system32\rtutils.dll : rtutils.dll
  1028 svchost.exe          0x71AA0000      1      1      1 \WINDOWS\system32\ws2help.dll
  Load Path: c:\windows\system32\WS2HELP.dll : WS2HELP.dll
  Init Path: c:\windows\system32\WS2HELP.dll : WS2HELP.dll
  Mem Path:  c:\windows\system32\WS2HELP.dll : WS2HELP.dll
[snip]
```

## impscan ##

In order to fully reverse engineer code that you find in memory dumps, its necessary to see which functions the code imports. In other words, which API functions it calls. When you dump binaries with dlldump, moddump, procexedump/procmemdump, it doesn't rebuild the IAT (Import Address Table) - many times the required memory pages are paged to disk. Thus, we created impscan. Impscan identifies calls to APIs without parsing a PE file's IAT. It even works if malware completely erases the PE header, and it works on kernel drivers.

If you have IDA Pro installed, make sure idag.exe (Windows) or idal (Linux/OS X) is in your $PATH variable. If so, then impscan will automatically create a labeled IDB from the code you want to analyze. You can then open up the extracted code in IDA and begin reversing...

Take Conficker for example. This malware deleted its PE header once it loaded in the target process. You can use malfind to detect the presence of Conficker based on the typical malfind criteria (page permissions, VAD tags, etc). Notice how the PE's base address doesn't contain the usual 'MZ' header:

```
$ python vol.py -f conficker.bin -p 3108 malfind -D out/
Volatile Systems Volatility Framework 2.0
Name                 Pid    Start      End        Tag    Hits Protect
notepad.exe            3108 0x00A10000 0x00A2BFFF VadS      0     24 (MM_EXECUTE_UNKNOWN)
Dumped to: out/services.exe.20c8558.00a10000-00a2bfff.dmp
0x00a10000   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
0x00a10010   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
0x00a10020   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
0x00a10030   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
0x00a10040   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
0x00a10050   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
0x00a10060   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
0x00a10070   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
```

Let's assume you want to extract the unpacked copy of Conficker and see its imported APIs. Use impscan by specifying the base address provided to you by malfind:

```
$ python vol.py -f conficker.bin -p 3108 impscan -a 0x00A10000 -D out
Volatile Systems Volatility Framework 2.0
a11204 RPCRT4.dll NdrClientCall2 77ef44d0
a11208 RPCRT4.dll RpcStringBindingComposeA 77e9a8e4
a110ac kernel32.dll Process32First 7c864f55
a1120c RPCRT4.dll RpcBindingFromStringBindingA 77e9a898
a11210 RPCRT4.dll RpcBindingFree 77e7b3d8
a11058 kernel32.dll FreeLibrary 7c80ac7e
a11220 VERSION.dll VerQueryValueA 77c018aa
a110b0 kernel32.dll Process32Next 7c8650c8
a11224 VERSION.dll GetFileVersionInfoA 77c01a40
a11228 VERSION.dll GetFileVersionInfoSizeA 77c019ef
a11230 WININET.dll InternetOpenA 771c5796
a11034 kernel32.dll WriteFile 7c810e27
a11238 WININET.dll InternetReadFile 771c82f2
a1123c WININET.dll InternetCloseHandle 771c4d94
a11240 WININET.dll InternetGetConnectedState 771d5c8e
a11260 WS2_32.dll sendto 71ab2f51
a11244 WININET.dll InternetOpenUrlA 771c5a62
[snip]
```

If you don't specify a base address with -a or --address, then you'll end up scanning the process's main module (i.e. services.exe) for imported functions. You can also specify the base address of a kernel driver to scan the driver for imported kernel-mode functions.

Laqma loads a kernel driver named lanmandrv.sys. If you extract it with moddump, the IAT will be corrupt. So use impscan to rebuild it:

```
$ python vol.py -f laqma.vmem modules | grep lanman
Volatile Systems Volatility Framework 2.0
\??\C:\WINDOWS\System32\lanmandrv.sys              0x00f8c52000 0x002000 lanmandrv.sys
```

Now that you know the base address:

```
$ python vol.py -f laqma.vmem impscan -a 0x00f8c52000 -D out/
Volatile Systems Volatility Framework 2.0
f8c53080 ntoskrnl.exe IofCompleteRequest 804ee07a
f8c530a0 ntoskrnl.exe ZwOpenKey 804fdd8c
f8c530a4 ntoskrnl.exe _except_handler3 80535230
f8c53084 ntoskrnl.exe IoDeleteDevice 804f0776
f8c53088 ntoskrnl.exe IoDeleteSymbolicLink 8056833a
f8c5309c ntoskrnl.exe wcscmp 80536fe3
f8c533ac ntoskrnl.exe NtQueryDirectoryFile 8056e1c2
f8c5308c ntoskrnl.exe IoCreateSymbolicLink 80567fc6
f8c53090 ntoskrnl.exe MmGetSystemRoutineAddress 805a23dc
f8c53094 ntoskrnl.exe IoCreateDevice 80569c5e
f8c53098 ntoskrnl.exe ExAllocatePoolWithTag 80544280
f8c533b4 ntoskrnl.exe NtQuerySystemInformation 806065e4
f8c533bc ntoskrnl.exe NtOpenProcess 805bfe1e
```

## apihooks ##

To find API hooks in user mode or kernel mode, use the apihooks plugin. This finds IAT, EAT, Inline style hooks, and several special types of hooks. For Inline hooks, it detects CALLs and JMPs to direct and indirect locations, and it detects PUSH/RET instruction sequences. The special types of hooks that it detects include syscall hooking in ntdll.dll and calls to unknown code pages in kernel memory.

Here is an example of detecting IAT hooks installed by Coreflood. The far right field contains UNKNOWN because there is no module associated with the memory in which the rootkit code exists. If you want to extract the code containing the hooks, you have a few options:

1. See if [malfind](http://code.google.com/p/volatility/wiki/CommandReference#malfind) can automatically find and extract it.

2. Use [volshell's](http://code.google.com/p/volatility/wiki/CommandReference#volshell) dd/db commands to scan backwards and look for an MZ header. Then pass that address to [dlldump](http://code.google.com/p/volatility/wiki/CommandReference#dlldump) as the --base value.

2. Use [vaddump](http://code.google.com/p/volatility/wiki/CommandReference#vaddump) to extract all code segments to individual files (named according to start and end address), then find the file that contains the 0x7ff82 ranges.

```
$ python vol.py -f coreflood.vmem -p 2044 apihooks 
Volatile Systems Volatility Framework 2.0
Name                             Type     Target                                   Value
IEXPLORE.EXE[2044]@winspool.drv  iat      KERNEL32.dll!GetProcAddress              0x0 0x7ff82360 (UNKNOWN)
IEXPLORE.EXE[2044]@winspool.drv  iat      KERNEL32.dll!LoadLibraryW                0x0 0x7ff82ac0 (UNKNOWN)
IEXPLORE.EXE[2044]@winspool.drv  iat      KERNEL32.dll!CreateFileW                 0x0 0x7ff82240 (UNKNOWN)
IEXPLORE.EXE[2044]@winspool.drv  iat      KERNEL32.dll!LoadLibraryA                0x0 0x7ff82a50 (UNKNOWN)
IEXPLORE.EXE[2044]@winspool.drv  iat      ADVAPI32.dll!RegSetValueExW              0x0 0x7ff82080 (UNKNOWN)
[snip]
```

Here is an example of detecting the Inline hooks installed by Silentbanker:

```
$ python vol.py -f silentbanker.vmem -p 1884 apihooks
Volatile Systems Volatility Framework 2.0
Name                             Type     Target                                   Value
IEXPLORE.EXE[1884]               inline   ws2_32.dll!connect                       0x71ab406a JMP 0xe90000 (UNKNOWN)
IEXPLORE.EXE[1884]               inline   ws2_32.dll!send                          0x71ab428a JMP 0xe70000 (UNKNOWN)
IEXPLORE.EXE[1884]               inline   user32.dll!DispatchMessageA              0x77d4bcbd JMP 0x10e0000 (UNKNOWN)
IEXPLORE.EXE[1884]               inline   user32.dll!DispatchMessageW              0x77d489d9 JMP 0x1100000 (UNKNOWN)
IEXPLORE.EXE[1884]               inline   user32.dll!GetClipboardData              0x77d6fcb2 JMP 0x10c0000 (UNKNOWN)
[snip]
```

Here is an example of detecting the 8-byte SHORT JMP + LONG JMP Inline hooks installed by SpyEye, the malware used in [The Honeynet Project's Forensic Challenge 8](http://www.honeynet.org/node/668).

```
$ python vol.py -f spyeye.vmem apihooks -p 700
Volatile Systems Volatility Framework 2.0
Name                             Type     Target                                   Value
explorer.exe[700]                inline   ws2_32.dll!send                          0x71ab4c27 JMP 0xbb6a9b8 (UNKNOWN)
explorer.exe[700]                inline   crypt32.dll!PFXImportCertStore           0x77aeff8f JMP 0xbb5e80d (UNKNOWN)
explorer.exe[700]                inline   wininet.dll!HttpSendRequestA             0x771c7519 JMP 0xbb6e13b (UNKNOWN)
explorer.exe[700]                inline   wininet.dll!HttpSendRequestW             0x771ddb8e JMP 0xbb6e299 (UNKNOWN)
explorer.exe[700]                inline   wininet.dll!InternetCloseHandle          0x771be85d JMP 0xbb68418 (UNKNOWN)
explorer.exe[700]                inline   wininet.dll!InternetWriteFile            0x771d27a3 JMP 0xbb6e3f7 (UNKNOWN)
explorer.exe[700]                inline   advapi32.dll!CryptEncrypt                0x77dee340 JMP 0xbb6a0e4 (UNKNOWN)
explorer.exe[700]                inline   ntdll.dll!NtEnumerateValueKey            0x7c90d2d0 JMP 0xbb5769e (UNKNOWN)
explorer.exe[700]                inline   ntdll.dll!NtQueryDirectoryFile           0x7c90d750 JMP 0xbb62dc5 (UNKNOWN)
explorer.exe[700]                inline   ntdll.dll!NtResumeThread                 0x7c90db20 JMP 0xbb7150a (UNKNOWN)
[snip]
```

If you look in memory (using the ws2\_32.dll!send hook as an example), the layout uses a JMP SHORT followed by a JMP. This is slightly more dangerous and more complex to install than your basic 5-byte detour patch, but it can hide from some anti-rootkit tools that only check the first instruction in a function for hooks.

```
Address   Hex dump          Command                               
71AB4C27   /EB 01           JMP SHORT 71AB4C2A
71AB4C29   |C3              RETN
71AB4C2A  -\E9 895D0B9A     JMP 0BB6A9B8
```

Here is an example of detecting the PUSH/RET Inline hooks installed by Laqma:

```
$ python vol.py -f laqma.vmem -p 1624 apihooks
Volatile Systems Volatility Framework 2.0
Name                             Type     Target                                   Value
explorer.exe[1624]               inline   user32.dll!MessageBoxA                   0x7e45058a PUSH 0xac10aa; RET (Dll.dll)
explorer.exe[1624]               inline   crypt32.dll!CertSerializeCRLStoreElement 0x77aa28df PUSH 0xac1104; RET (Dll.dll)
explorer.exe[1624]               inline   crypt32.dll!CertSerializeCTLStoreElement 0x77aa28df PUSH 0xac1104; RET (Dll.dll)
explorer.exe[1624]               inline   crypt32.dll!CertSerializeCertificateStoreElement 0x77aa28df PUSH 0xac1104; RET (Dll.dll)
explorer.exe[1624]               inline   crypt32.dll!PFXImportCertStore           0x77aef748 PUSH 0xac12a8; RET (Dll.dll)
explorer.exe[1624]               inline   wininet.dll!HttpOpenRequestA             0x771c36dd PUSH 0xac148c; RET (Dll.dll)
explorer.exe[1624]               inline   wininet.dll!HttpSendRequestA             0x771c6129 PUSH 0xac162c; RET (Dll.dll)
[snip]
```

Here is an example of using apihooks to detect the syscall patches in ntdll.dll (using a Carberp sample):

```
$ python vol.py -f carberp.vmem apihooks
Volatile Systems Volatility Framework 2.0
Name                             Type     Target                                   Value
explorer.exe[1004]               inline   ntdll.dll!NtCreateThread                 0x7c90d190 JMP 0x15a3fa7 (UNKNOWN)
explorer.exe[1004]               inline   ntdll.dll!ZwCreateThread                 0x7c90d190 JMP 0x15a3fa7 (UNKNOWN)
explorer.exe[1004]               syscall  ntdll.dll!NtQueryDirectoryFile           0x1dadd84 MOV EDX, 0x1dadd84 (UNKNOWN)
explorer.exe[1004]               syscall  ntdll.dll!NtResumeThread                 0x1dadd78 MOV EDX, 0x1dadd78 (UNKNOWN)
explorer.exe[1004]               syscall  ntdll.dll!ZwQueryDirectoryFile           0x1dadd84 MOV EDX, 0x1dadd84 (UNKNOWN)
explorer.exe[1004]               syscall  ntdll.dll!ZwResumeThread                 0x1dadd78 MOV EDX, 0x1dadd78 (UNKNOWN)
explorer.exe[1004]               inline   ws2_32.dll!WSASend                       0x71ab68fa JMP 0x15a97f7 (UNKNOWN)
explorer.exe[1004]               inline   ws2_32.dll!closesocket                   0x71ab3e2b JMP 0x15a979e (UNKNOWN)
[snip]
```

Here is an example of using apihooks to detect the Inline hook of a kernel mode function:

```
$ python vol.py apihooks -K -f rustock.vmem 

Name     Type     Function                        Value
-        inlinek  ntoskrnl.exe!IofCallDriver      0x804ee130 jmp [0x8054c280] =>> 0xb17a189d (\Driver\pe386)
```

Here is an example of using apihooks to detect the calls to an unknown code page from a kernel driver. In this case, malware has patched tcpip.sys with some malicious redirections.

```
$ python vol.py -f rustock-2.vmem apihooks -K
Volatile Systems Volatility Framework 2.0
Name                             Type     Target                                   Value
-                                ucpcall  tcpip.sys                                0xf7be2514 CALL [0x81ecd0c0]
-                                ucpcall  tcpip.sys                                0xf7be28ad CALL [0x81e9da60]
-                                ucpcall  tcpip.sys                                0xf7be2c61 CALL [0x81f8a058]
-                                ucpcall  tcpip.sys                                0xf7bfa0c0 CALL [0x82009dd0]
```

## idt ##

To print the system's IDT (Interrupt Descriptor Table), use the idt command. This displays the purpose of the interrupts, along with the current address and owning module. It also checks the IDT entries for Inline style API hooks. This is important because some rootkits hook the IDT entry for KiSystemService, but point it at a routine inside the NT module (where KiSystemService should point). However, at that address, there is an Inline hook!

```
$ python vol.py idt -f rustock.vmem 
Index    Selector Function                   Value        Details
[snip]
2A       8        KiGetTickCount             0x8053cbae   ntoskrnl.exe .text
2B       8        KiCallbackReturn           0x8053ccb0   ntoskrnl.exe .text
2C       8        KiSetLowWaitHighThread     0x8053ce50   ntoskrnl.exe .text
2D       8        KiDebugService             0x8053d790   ntoskrnl.exe .text
2E       8        KiSystemService            0x806b973c   ntoskrnl.exe .rsrc => JMP 0xf6ec0e45
[snip]
```

## gdt ##

To print the system's GDT (Global Descriptor Table), use the gdt command. This is useful for detecting rootkits like Alipop that install a call gate so that user mode programs can call directly into kernel mode (using a CALL FAR instruction).

In the output below, you can see that selector 0x3e0 has been infected and used for the purposes of a 32-bit call gate. The hook address is 0x8003f000, which as you can see in the disassembly, contains the instructions to further transfer control to 0xffdf0adb.

```
$ python vol.py -f alipop.vmem gdt 
Volatile Systems Volatility Framework 2.0
Sel    Base         Limit        Type           DPL    Gr     Pr    
0x0    0xffdf0a     0xdbbb       TSS16 Busy     2      By     P     
0x8    0x0          0xffffffff   Code RE Ac     0      Pg     P     
0x10   0x0          0xffffffff   Data RW Ac     0      Pg     P     
0x18   0x0          0xffffffff   Code RE Ac     3      Pg     P     
0x20   0x0          0xffffffff   Data RW Ac     3      Pg     P     
0x28   0x80042000   0x20ab       TSS32 Busy     0      By     P     
0x30   0xffdff000   0x1fff       Data RW Ac     0      Pg     P     
0x38   0x0          0xfff        Data RW Ac     3      By     P
[...]
0x3c8  0x8003       0xf3d0       <Reserved>     0      By     Np    
0x3d0  0x8003       0xf3d8       <Reserved>     0      By     Np    
0x3d8  0x8003       0xf3e0       <Reserved>     0      By     Np    
0x3e0  0x8003f000   -            CallGate32     3      -      P     

8003f000: bbdb0adfff                       MOV EBX, 0xffdf0adb
8003f005: c3                               RET

0x3e8  0x0          0xffffffff   Code RE Ac     0      Pg     P     
0x3f0  0x8003       0xf3f8       <Reserved>     0      By     Np    
0x3f8  0x0          0x0          <Reserved>     0      By     Np
```

If you want to further investigate the infection, you can break into a [volshell](http://code.google.com/p/volatility/wiki/CommandReference#volshell) as shown below:

```
$ python vol.py -f alipop.vmem volshell
Volatile Systems Volatility Framework 2.0
Current context: process System, pid=4, ppid=0 DTB=0x320000
Welcome to volshell! Current memory image is:
file:///Users/M/Desktop/alipop.vmem
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
Volatile Systems Volatility Framework 2.0
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
Volatile Systems Volatility Framework 2.0
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
Volatile Systems Volatility Framework 2.0
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
Volatile Systems Volatility Framework 2.0
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
Volatile Systems Volatility Framework 2.0
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
Volatile Systems Volatility Framework 2.0
DriverStart  Name             IRP                                  IrpAddr      IrpOwner         HookAddr     HookOwner
0xf9db8000   'vmscsi'         IRP_MJ_CREATE                        0xf9db9cbd   vmscsi.sys       -            -
0xf9db8000   'vmscsi'         IRP_MJ_CREATE_NAMED_PIPE             0xf9db9cbd   vmscsi.sys       -            -
0xf9db8000   'vmscsi'         IRP_MJ_CLOSE                         0xf9db9cbd   vmscsi.sys       -            -
0xf9db8000   'vmscsi'         IRP_MJ_READ                          0xf9db9cbd   vmscsi.sys       -            -
0xf9db8000   'vmscsi'         IRP_MJ_WRITE                         0xf9db9cbd   vmscsi.sys       -            -
0xf9db8000   'vmscsi'         IRP_MJ_QUERY_INFORMATION             0xf9db9cbd   vmscsi.sys       -            -
0xf9db8000   'vmscsi'         IRP_MJ_SET_INFORMATION               0xf9db9cbd   vmscsi.sys       -            -
0xf9db8000   'vmscsi'         IRP_MJ_QUERY_EA                      0xf9db9cbd   vmscsi.sys       -            -
0xf9db8000   'vmscsi'         IRP_MJ_SET_EA                        0xf9db9cbd   vmscsi.sys       -            -
[snip]
```

In the output, it is not apparent that the vmscsi.sys driver has been infected by the TDL3 rootkit. Although all IRPs point back into vmscsi.sys, they point at a stub staged in that region by TDL3 for the exact purpose of bypassing rootkit detection tools. To get extended information, use --verbose:

```
$ python vol.py -f tdl3.vmem driverirp -r vmscsi --verbose
Volatile Systems Volatility Framework 2.0
DriverStart  Name             IRP                                  IrpAddr      IrpOwner         HookAddr     HookOwner
0xf9db8000   'vmscsi'         IRP_MJ_CREATE                        0xf9db9cbd   vmscsi.sys       -            -
f9db9cbd: a10803dfff                       MOV EAX, [0xffdf0308]
f9db9cc2: ffa0fc000000                     JMP DWORD [EAX+0xfc]
f9db9cc8: 0000                             ADD [EAX], AL
f9db9cca: 0000                             ADD [EAX], AL
f9db9ccc: 0000                             ADD [EAX], AL

0xf9db8000   'vmscsi'         IRP_MJ_CREATE_NAMED_PIPE             0xf9db9cbd   vmscsi.sys       -            -
f9db9cbd: a10803dfff                       MOV EAX, [0xffdf0308]
f9db9cc2: ffa0fc000000                     JMP DWORD [EAX+0xfc]
f9db9cc8: 0000                             ADD [EAX], AL
f9db9cca: 0000                             ADD [EAX], AL
f9db9ccc: 0000                             ADD [EAX], AL
[snip]
```

Now you can see that TDL3 redirects all IRPs to its own stub in the vmscsi.sys driver. That code jumps to whichever address is pointed to by 0xffdf0308 - a location in the KUSER\_SHARED\_DATA region.

## devicetree ##

Windows uses a layered driver architecture, or driver chain so that multiple drivers can inspect or respond to an IRP. Rootkits often insert drivers (or devices) into this chain for filtering purposes (to hide files, hide network connections, steal keystrokes or mouse movements). The devicetree plugin shows the relationship of a driver object to its devices (by walking `_DRIVER_OBJECT.DeviceObject.NextDevice`) and any attached devices (`_DRIVER_OBJECT.DeviceObject.AttachedDevice`).

In the example below, Stuxnet has infected \FileSystem\Ntfs by attaching a malicious unnamed device. Although the device itself is unnamed, the device object identifies its driver (\Driver\MRxNet).

```
$ python vol.py -f stuxnet.vmem devicetree
Volatile Systems Volatility Framework 1.4_rc1
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

## psxview ##

This plugin helps you detect hidden processes by comparing what  PsActiveProcessHead contains with what is reported by various other sources of process listings. It compares the following:

  * PsActiveProcessHead linked list
  * EPROCESS pool scanning
  * ETHREAD pool scanning (then it references the owning EPROCESS)
  * PspCidTable
  * Csrss.exe handle table
  * Csrss.exe internal linked list

On Windows Vista and Windows 7 the internal list of processes in csrss.exe is not available. It also may not be available in some XP images where certain pages are not memory resident.

Here is an example of detecting the Prolaco malware with psxview. A zero in any column indicates that the respective process is missing. You can tell "1\_doc\_RCData\_61" is suspicious since it shows up in every column except pslist (PsActiveProcessHead).

```
$ python vol.py -f prolaco.vmem psxview
Offset       Name                 Pid      pslist     psscan     thrdproc   pspcid     csr_hnds   csr_list  
0xff1b8b28   vmtoolsd.exe         1668     1          1          1          1          1          0         
0x80ff88d8   svchost.exe          856      1          1          1          1          1          0         
0xff1d7da0   spoolsv.exe          1432     1          1          1          1          1          0         
0x810b1660   System               4        1          1          1          1          0          0         
0x80fbf910   svchost.exe          1028     1          1          1          1          1          0         
0xff2ab020   smss.exe             544      1          1          1          1          0          0         
0xff3667e8   VMwareTray.exe       432      1          1          1          1          1          0         
0xff247020   services.exe         676      1          1          1          1          1          0         
0xff217560   svchost.exe          936      1          1          1          1          1          0         
0xff143b28   TPAutoConnSvc.e      1968     1          1          1          1          1          0         
0x80fdc648   1_doc_RCData_61      1336     0          1          1          1          1          0         
0xff255020   lsass.exe            688      1          1          1          1          1          0         
0xff3865d0   explorer.exe         1724     1          1          1          1          1          0         
0xff22d558   svchost.exe          1088     1          1          1          1          1          0         
0xff374980   VMwareUser.exe       452      1          1          1          1          1          0         
0xff1fdc88   VMUpgradeHelper      1788     1          1          1          1          1          0         
0xff218230   vmacthlp.exe         844      1          1          1          1          1          0         
0xff364310   wscntfy.exe          888      1          1          1          1          1          0         
0x80f94588   wuauclt.exe          468      1          1          1          1          1          0         
0xff25a7e0   alg.exe              216      1          1          1          1          1          0         
0xff1ecda0   csrss.exe            608      1          1          1          1          0          0         
0xff38b5f8   TPAutoConnect.e      1084     1          1          1          1          1          0         
0xff37a4b0   ImmunityDebugge      1136     1          1          1          1          1          0         
0xff1ec978   winlogon.exe         632      1          1          1          1          1          0         
0xff203b80   svchost.exe          1148     1          1          1          1          1          0
```

## ssdt\_ex ##

If you want to explore SSDT hooks installed by rootkits, use the ssdt\_ex command. This will automatically detect which SSDT functions are hooked, extract the hooking kernel driver to disk, and generate an IDC file (IDA script) containing labels for the rootkit functions. Then, if you have idag.exe (Windows) or idal (Linux/OS X) in your $PATH, then it will create an IDB file from the extracted kernel driver and run the IDC script. The result is a pre-labeled IDB for you to explore and reverse engineer, after typing just one command in Volatility.

Here is an example:

```
$ python vol.py -f laqma.vmem ssdt_ex -D outdir/
Volatile Systems Volatility Framework 2.0
  Entry 0x0049: 0xf8c52884 (NtEnumerateValueKey) owned by lanmandrv.sys
  Entry 0x007a: 0xf8c5253e (NtOpenProcess) owned by lanmandrv.sys
  Entry 0x0091: 0xf8c52654 (NtQueryDirectoryFile) owned by lanmandrv.sys
  Entry 0x00ad: 0xf8c52544 (NtQuerySystemInformation) owned by lanmandrv.sys
Dumping IDC file to /Users/M/Desktop/Volatility-2.0/outdir/driver.f8c52000.sys.idc

[snip]
```

Now if you look in outdir, you'll find:

  * The extracted kernel driver (driver.f8c52000.sys)
  * The IDC script (driver.f8c52000.sys.idc)
  * The IDA database (driver.f8c52000.idb)

Inside the IDC script, you'll see something like this:

```
#include <idc.idc>
static main(void) {
   MakeFunction(0xF8C52A4C, BADADDR);
   MakeFunction(0xF8C52E7C, BADADDR);
   MakeName(0xF8C52544, "HookNtQuerySystemInformation");
   MakeFunction(0xF8C52544, BADADDR);
   MakeName(0xF8C52654, "HookNtQueryDirectoryFile");
   MakeFunction(0xF8C52654, BADADDR);
   MakeName(0xF8C52884, "HookNtEnumerateValueKey");
   MakeFunction(0xF8C52884, BADADDR);
   MakeName(0xF8C5253E, "HookNtOpenProcess");
   MakeFunction(0xF8C5253E, BADADDR);
Exit(0);
}
```

When you open the IDB, just navigate to any functions with a "Hook" prefix and you'll be staring at the rootkit's payload.

## timers ##

This command prints installed kernel timers (KTIMER) and any associated DPCs (Deferred Procedure Calls). Rootkits such as Zero Access, Rustock, and Stuxnet register timers with a DPC. Although the malware tries to be stealthy and hide in kernel space in a number of different ways, by finding the KTIMERs and looking at the address of the DPC, you can quickly find the malicious code ranges.

Here's an example. Notice how one of the timers has an UNKNOWN module (the DPC points to an unknown region of kernel memory). This is ultimately where the rootkit is hiding.

```
$ python vol.py timers -f rustock-c.vmem 
Offset       DueTime               Period(ms) Signaled   Routine      Module
0xf730a790   0x00000000:0x6db0f0b4 0          -          0xf72fb385   srv.sys
0x80558a40   0x00000000:0x68f10168 1000       Yes        0x80523026   ntoskrnl.exe
0x80559160   0x00000000:0x695c4b3a 0          -          0x80526bac   ntoskrnl.exe
0x820822e4   0x00000000:0xa2a56bb0 150000     Yes        0x81c1642f   UNKNOWN
0xf842f150   0x00000000:0xb5cb4e80 0          -          0xf841473e   Ntfs.sys
...
```

Please note: the timers are enumerated in different ways depending on the target operating system. Windows stores the timers in global variables for XP, 2003, 2008, and Vista. Since Windows 7, the timers are are in processor-specific regions off of KPCR (Kernel Processor Control Region). Thus, to enumerate all timers for multi-core Windows 7 systems, you should use the [kpcrscan](http://code.google.com/p/volatility/wiki/CommandReference#kpcrscan) command first and then pass each value to the timers plugin with the --kpcr=KPCRADDRESS parameter.

```
$ python vol.py -f mem.dmp --profile=Win7SP0x86 kpcrscan
Volatile Systems Volatility Framework 2.1_alpha
Potential KPCR structure virtual addresses:
 _KPCR: 0x807c3000
 _KPCR: 0x8296fc00
 _KPCR: 0x8cd00000
 _KPCR: 0x8cd36000

$ python vol.py -h
Volatile Systems Volatility Framework 2.1_alpha
Usage: Volatility - A memory forensics analysis platform.

Options:
[...]
-k KPCR, --kpcr=KPCR  Specify a specific KPCR address
[...]

$ python vol.py -f mem.dmp timers --profile=Win7SP0x86 --kpcr=0x807c3000
Volatile Systems Volatility Framework 2.1_alpha
Offset       DueTime              Period(ms) Signaled   Routine      Module
0x869ed930   0x0000217a:0x47a09f1a 0          -          0x99a78005 srv.sys
0x85f451d8   0x0000217a:0x5f8703b2 10         -          0x8b0a78b9 tcpip.sys
0x807c65a8   0x0000217a:0x47e7b336 15000      Yes        0x8287b4d3 ntoskrnl.exe

$ python vol.py -f mem.dmp timers --profile=Win7SP0x86 --kpcr=0x8296fc00
Volatile Systems Volatility Framework 2.1_alpha
Offset       DueTime              Period(ms) Signaled   Routine      Module
0x91593180   0x0000217a:0x4f4a5c00 0          -          0x9158e240 luafv.sys
0x829810a0   0x0000217a:0x4f4a5c00 5000       Yes        0x8290b2d0 ntoskrnl.exe
0x86135d70   0x0000217a:0x5b361e00 30000      Yes        0x8f6e0298 afd.sys
0x96243900   0x0000217a:0x4f5de140 0          -          0x9621b3b2 HTTP.sys
0x829ac4f0   0x0000217a:0x62940216 60000      Yes        0x82878d8f ntoskrnl.exe
0x862d9150   0x0000217a:0x5448bae0 0          -          0x8aedda4f ndis.sys
0x99a878c0   0x0000217a:0x51eb2594 0          -          0x99a780b6 srv.sys
0x8605dd20   0x0000217a:0x4dc62f22 0          -          0x82fbbba4 storport.sys
[...]
```

As you can see, depending on the KPCR used, you'll get a different list of timers. That's because each processor handles its own set of timers. For more information on timer objects, see [Ain't Nuthin But a K(Timer) Thing, Baby](http://mnin.blogspot.com/2011/10/aint-nuthin-but-ktimer-thing-baby.html).

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

## inspectcache ##
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

## testsuite ##