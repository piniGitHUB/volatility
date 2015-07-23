Although all Volatility commands can help you hunt malware in one way or another, there are a few designed specifically for hunting rootkits and malicious code. The most comprehensive documentation for these commands can be found in the [Malware Analyst's Cookbook and DVD: Tools and Techniques For Fighting Malicious Code](http://www.amazon.com/dp/0470613033).



# malfind #

The malfind command helps find hidden or injected code/DLLs in user mode memory, based on characteristics such as VAD tag and page permissions.

Note: malfind does not detect DLLs injected into a process using CreateRemoteThread->LoadLibrary. DLLs injected with this technique are not hidden and thus you can view them with [dlllist](CommandReference22#dlllist.md). The purpose of malfind is to locate DLLs that standard methods/tools do not see. For more information see [Issue #178](https://code.google.com/p/volatility/issues/detail?id=#178).

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

# yarascan #

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

# svcscan #

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

# ldrmodules #

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

# impscan #

In order to fully reverse engineer code that you find in memory dumps, its necessary to see which functions the code imports. In other words, which API functions it calls. When you dump binaries with [dlldump](CommandReference22#dlldump.md), [moddump](CommandReference22#moddump.md), or [procexedump](CommandReference22#procexedump.md), the IAT (Import Address Table) may not properly be reconstructed due to the high likelihood that one or more pages in the PE header or IAT are not memory resident (paged). Thus, we created impscan. Impscan identifies calls to APIs without parsing a PE's IAT. It even works if malware completely erases the PE header, and it works on kernel drivers.

Previous versions of impscan automatically created a labeled IDB for use with IDA Pro. This functionality has temporarily been disabled, but will return sometime in the future when other similar functionality is introduced.

Take Coreflood for example. This malware deleted its PE header once it loaded in the target process (by calling VirtualFree on the injected DLL's ImageBase). You can use [malfind](CommandReferenceMal22#malfind.md) to detect the presence of Coreflood based on the typical criteria (page permissions, VAD tags, etc). Notice how the PE's base address doesn't contain the usual 'MZ' header:

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

Laqma loads a kernel driver named lanmandrv.sys. If you extract it with [moddump](CommandReference22#moddump.md), the IAT will be corrupt. So use impscan to rebuild it:

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

# apihooks #

To find API hooks in user mode or kernel mode, use the apihooks plugin. This finds IAT, EAT, Inline style hooks, and several special types of hooks. For Inline hooks, it detects CALLs and JMPs to direct and indirect locations, and it detects PUSH/RET instruction sequences. The special types of hooks that it detects include syscall hooking in ntdll.dll and calls to unknown code pages in kernel memory.

As of Volatility 2.1, apihooks also detects hooked winsock procedure tables, includes an easier to read output format, supports multiple hop disassembly, and can optionally scan quicker through memory by ignoring non-critical processes and DLLs.

Here is an example of detecting IAT hooks installed by Coreflood. The hooking module is unknown because there is no module (DLL) associated with the memory in which the rootkit code exists. If you want to extract the code containing the hooks, you have a few options:

1. See if [malfind](CommandReferenceMal22#malfind.md) can automatically find and extract it.

2. Use [volshell](CommandReference22#volshell.md) dd/db commands to scan backwards and look for an MZ header. Then pass that address to [dlldump](CommandReference#dlldump.md) as the --base value.

3. Use [vaddump](CommandReference22#vaddump.md) to extract all code segments to individual files (named according to start and end address), then find the file that contains the 0x7ff82 ranges.

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

# idt #

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

# gdt #

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

If you want to further investigate the infection, you can break into a [volshell](CommandReference22#volshell.md) as shown below. Then disassemble code at the call gate address.

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

# threads #

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

# callbacks #

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

# driverirp #

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

# devicetree #

Windows uses a layered driver architecture, or driver chain so that multiple drivers can inspect or respond to an IRP. Rootkits often insert drivers (or devices) into this chain for filtering purposes (to hide files, hide network connections, steal keystrokes or mouse movements). The devicetree plugin shows the relationship of a driver object to its devices (by walking `_DRIVER_OBJECT.DeviceObject.NextDevice`) and any attached devices (`_DRIVER_OBJECT.DeviceObject.AttachedDevice`).

In the example below, Stuxnet has infected `\FileSystem\Ntfs` by attaching a malicious unnamed device. Although the device itself is unnamed, the device object identifies its driver (\Driver\MRxNet).

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

# psxview #

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

# timers #

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