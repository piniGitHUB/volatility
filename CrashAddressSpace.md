# Introduction #

Crash dumps are a standard file format designed and used by Microsoft for debugging purposes. A system can be configured to create a crash dump when a BSOD occurs or you can create them manually using one of the acquisition techniques below. It is important to note that if you want your crash dump to be compatible with volatility, it must be a _complete_ memory dump, not just a _kernel_ memory dump. In other words, it must contain both kernel and process memory. The Microsoft KB articles below will explain how to ensure you pick the right format.

# Acquisition #

For detailed instructions creating crash dumps see Microsoft's [KB 969028](http://support.microsoft.com/kb/969028). Below you'll find a summary of the various techniques.

  * The SysInternals [NotMyFault](http://download.sysinternals.com/files/NotMyFault.zip) tool (NotMyFault.exe /crash)
  * CrashOnControlScroll from a PS/2 keyboard or CTRL, SCROLL, LOCK key sequences on a USB keyboard - see [KB 244139](http://support.microsoft.com/kb/244139)
  * NMI (Non-Maskable Interrupt) - see [KB 927069](http://support.microsoft.com/kb/927069)
  * Remote kernel debugger's .crash or .dump command
  * The SysInternals [LiveKD](http://download.sysinternals.com/files/LiveKD.zip) tool (LiveKd -o)
  * Some [forensic memory imaging tools](http://www.forensicswiki.org/wiki/Tools:Memory_Imaging) can create dumps in crash format
  * If you have a raw memory dump, you can convert it to a crash dump with volatility's [raw2dmp command](CommandReference22#raw2dmp.md)

Also see the technet article [Understanding Crash Dump Files](http://blogs.technet.com/b/askperf/archive/2008/01/08/understanding-crash-dump-files.aspx) which summarizes the difference between complete memory dumps, kernel memory dumps, and mini dumps.

# Notes #

Here are some things to keep in mind regarding crash dump files. Many items are from Matt Suiche's [Challenges of Windows Physical Memory Acquisition and Exploitation](http://shakacon.org/2009/talks/NFI-Shakacon-win32dd0.3.pdf)) and George Garner's [post on Vol-users](http://lists.volatilesystems.com/pipermail/vol-users/2012-July/000475.html). Some of the points are dependent on the tool being used to acquire the crash dump, not necessarily the crash format itself.

  * Does not include physical address space dedicated to hardware resources (i.e. PnP devices)
  * May skip certain physical pages, such as the first physical page containing the pre-boot authentication password in plain text
  * Possible to be subverted by malware using `KeRegisterBugCheckCallback` or by disabling access to the kernel debugger.
  * The methods involving debuggers are far from forensically sound. You may need special software to be installed on the target system, which is not always practical. Also, the values of `nt!KdDebuggerEnabled` and `nt!KdDebuggerNotPresent` will be altered. On x64 systems the `nt!KdDebuggerDataBlock` will be decoded and important operating system components (e.g. Patchguard) are disabled.

# File Format #

## 32-bit crash dumps ##

Crash dumps from 32-bit systems begin with a `_DMP_HEADER` structure. The Signature field must be "PAGEDUMP" for volatility to consider it valid.

```
>>> dt("_DMP_HEADER")
'_DMP_HEADER' (4096 bytes)
0x0   : Signature                      ['array', 4, ['unsigned char']]
0x4   : ValidDump                      ['array', 4, ['unsigned char']]
0x8   : MajorVersion                   ['unsigned long']
0xc   : MinorVersion                   ['unsigned long']
0x10  : DirectoryTableBase             ['unsigned long']
0x14  : PfnDataBase                    ['unsigned long']
0x18  : PsLoadedModuleList             ['unsigned long']
0x1c  : PsActiveProcessHead            ['unsigned long']
0x20  : MachineImageType               ['unsigned long']
0x24  : NumberProcessors               ['unsigned long']
0x28  : BugCheckCode                   ['unsigned long']
0x2c  : BugCheckCodeParameter          ['array', 4, ['unsigned long']]
0x3c  : VersionUser                    ['array', 32, ['unsigned char']]
0x5c  : PaeEnabled                     ['unsigned char']
0x5d  : KdSecondaryVersion             ['unsigned char']
0x5e  : VersionUser2                   ['array', 2, ['unsigned char']]
0x60  : KdDebuggerDataBlock            ['unsigned long']
0x64  : PhysicalMemoryBlockBuffer      ['_PHYSICAL_MEMORY_DESCRIPTOR']
0x320 : ContextRecord                  ['array', 1200, ['unsigned char']]
0x7d0 : Exception                      ['_EXCEPTION_RECORD32']
0x820 : Comment                        ['array', 128, ['unsigned char']]
0xf88 : DumpType                       ['unsigned long']
0xf8c : MiniDumpFields                 ['unsigned long']
0xf90 : SecondaryDataState             ['unsigned long']
0xf94 : ProductType                    ['unsigned long']
0xf98 : SuiteMask                      ['unsigned long']
0xf9c : WriterStatus                   ['unsigned long']
0xfa0 : RequiredDumpSpace              ['unsigned long long']
0xfb8 : SystemUpTime                   ['unsigned long long']
0xfc0 : SystemTime                     ['unsigned long long']
0xfc8 : reserved3                      ['array', 56, ['unsigned char']]
```

## 64-bit crash dumps ##

Crash dumps from 64-bit systems begin with a `_DMP_HEADER64` structure. The Signature field must be "PAGEDU64" for volatility to consider it valid.

```
>>> dt("_DMP_HEADER64")
'_DMP_HEADER64' (8192 bytes)
0x0   : Signature                      ['array', 4, ['unsigned char']]
0x4   : ValidDump                      ['array', 4, ['unsigned char']]
0x8   : MajorVersion                   ['unsigned long']
0xc   : MinorVersion                   ['unsigned long']
0x10  : DirectoryTableBase             ['unsigned long long']
0x18  : PfnDataBase                    ['unsigned long long']
0x20  : PsLoadedModuleList             ['unsigned long long']
0x28  : PsActiveProcessHead            ['unsigned long long']
0x30  : MachineImageType               ['unsigned long']
0x34  : NumberProcessors               ['unsigned long']
0x38  : BugCheckCode                   ['unsigned long']
0x40  : BugCheckCodeParameter          ['array', 4, ['unsigned long long']]
0x80  : KdDebuggerDataBlock            ['unsigned long long']
0x88  : PhysicalMemoryBlockBuffer      ['_PHYSICAL_MEMORY_DESCRIPTOR']
0x348 : ContextRecord                  ['array', 3000, ['unsigned char']]
0xf00 : Exception                      ['_EXCEPTION_RECORD64']
0xf98 : DumpType                       ['unsigned long']
0xfa0 : RequiredDumpSpace              ['unsigned long long']
0xfa8 : SystemTime                     ['unsigned long long']
0xfb0 : Comment                        ['array', 128, ['unsigned char']]
0x1030: SystemUpTime                   ['unsigned long long']
0x1038: MiniDumpFields                 ['unsigned long']
0x103c: SecondaryDataState             ['unsigned long']
0x1040: ProductType                    ['unsigned long']
0x1044: SuiteMask                      ['unsigned long']
0x1048: WriterStatus                   ['unsigned long']
0x104c: Unused1                        ['unsigned char']
0x104d: KdSecondaryVersion             ['unsigned char']
0x104e: Unused                         ['array', 2, ['unsigned char']]
0x1050: _reserved0                     ['array', 4016, ['unsigned char']]
```

# Meta Data #

You can use the crashinfo plugin to dump meta-data from the crash header:

```
$ python vol.py -f win7.dmp --profile=Win7SP1x86 crashinfo
Volatile Systems Volatility Framework 2.3_alpha
_DMP_HEADER:
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
 Comment               PAGEPAGEPAGEPAGEPAGEPAGE
 DumpType              Full Dump
 SystemTime            2010-06-17 16:36:17 
 SystemUpTime          

Physical Memory Description:
Number of runs: 3
FileOffset    Start Address    Length
00001000      00001000         0009e000
0009f000      00100000         3fdf0000
3fe8f000      3ff00000         00100000
3ff8e000      3ffff000
```