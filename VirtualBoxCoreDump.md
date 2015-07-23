# Introduction #

Volatility can analyze memory dumps from [VirtualBox](https://www.virtualbox.org/) virtual machines. Philippe Teuwen wrote this Address Space and detailed much of the acquisition, file format, and other intricacies related to this exciting capability [on his personal wiki](http://wiki.yobi.be/wiki/RAM_analysis).

# Acquisition #

VirtualBox does not automatically save a full RAM dump to disk when you suspend or pause a virtual machine (as other virtualization products do). There are two ways to acquire a memory dump, both described by Philippe at the link above:

  * The vboxmanage debugvm commands (see [Chapter 8 of the manual](http://www.virtualbox.org/manual/ch08.html#vboxmanage-debugvm)). This creates a standard ELF64 with custom sections that represent the guest's physical memory.
  * Using the --dbg switch when starting a VM and the .pgmphystofile command (see [VirtualBox Ticket #10222](https://www.virtualbox.org/ticket/10222)). This outputs a raw dd-style physical memory dump that is natively compatible with Volatility. **Note**: a user also attached a Python script vboxdump.py (untested) which can be used to dump memory).

Of the two methods, the only one that needs special handling is the ELF64. However, this is also the method that can be scripted, so it can be very valuable, especially in a sandbox environment.

# Notes #

  * The VirtualBox AS was officially built and tested using core dumps from VirtualBox 4.1.23 (latest as of October 2012), but unless the specification (see file format below) is different in earlier (or future) versions, the AS should work on all core dumps.
  * You can convert a VirtualBox core dump into a raw dd-style memory dump that other tools can analyze by using the [imagecopy](CommandReference23#imagecopy.md) command.
  * The ELF64 core dumps also include VGA (video memory), and other MMIO device memory segments. See the meta-data section below.

# File Format #

The ELF64 file has several custom program header segments. One of them is a PT\_NOTE (elf64\_note) whose name is "VBCORE". This segment contains a DBGFCOREDESCRIPTOR structure, which is shown below:

```
>>> dt("DBGFCOREDESCRIPTOR")
'DBGFCOREDESCRIPTOR' (24 bytes)
0x0   : u32Magic                       ['unsigned int']
0x4   : u32FmtVersion                  ['unsigned int']
0x8   : cbSelf                         ['unsigned int']
0xc   : u32VBoxVersion                 ['unsigned int']
0x10  : u32VBoxRevision                ['unsigned int']
0x14  : cCpus                          ['unsigned int']
```

The structure contains the VirtualBox magic signature (0xc01ac0de), the version information, and number of CPUs for the target system. If you continue to iterate through the ELF64's program headers, you'll find various PT\_LOAD segments (elf64\_phdr). Each segment's p\_paddr member is a starting physical memory address. The p\_offset member tells you where in the ELF64 file you can find the chunk of physical memory. Finally, the p\_memsz tells you how big (in bytes) the chunk of memory is.

For more information on the format of core dump format, see the following links:

  * http://www.virtualbox.org/manual/ch12.html#guestcoreformat
  * http://www.virtualbox.org/svn/vbox/trunk/include/VBox/vmm/dbgfcorefmt.h
  * http://www.virtualbox.org/svn/vbox/trunk/src/VBox/VMM/VMMR3/DBGFCoreWrite.cpp

# Meta Data #

You can use the [vboxinfo](CommandReference23#vboxinfo.md) plugin to dump meta-data from the core dump header. Note the memory ranges: if a system has less than 3.5 GB of RAM, the entire main memory will be contained in the first run (0 - 0xe0000000). The VGA/video memory beings at 0xe0000000 on both x86 and x64 systems. Several MMIO device memory ranges ambiguously labeled "VirtualBox Device" (in Windows' Device Manager) exist after the VGA segment. If a system has more than 3.5 GB of RAM, the remainder of memory begins at 0x100000000.

The system below had about 5.5 GB RAM:

```
$ python vol.py -f ~/Desktop/win7sp1x64_vbox.elf --profile=Win7SP1x64 vboxinfo 
Volatile Systems Volatility Framework 2.3_alpha

Magic: 0xc01ac0de
Format: 0x10000
VirtualBox 4.1.23 (revision 80870)
CPUs: 1

File Offset        PhysMem Offset     Size              
------------------ ------------------ ------------------
0x0000000000000758 0x0000000000000000 0x00000000e0000000
0x00000000e0000758 0x00000000e0000000 0x0000000003000000
0x00000000e3000758 0x00000000f0400000 0x0000000000400000
0x00000000e3400758 0x00000000f0800000 0x0000000000004000
0x00000000e3404758 0x00000000ffff0000 0x0000000000010000
0x00000000e3414758 0x0000000100000000 0x000000006a600000
```

The system below had 8 GB RAM:

```
File Offset Memory Offset Size      
----------- ------------- ----------
0x000000808 0x00000000000 0xe0000000
0x0e0000808 0x000e0000000 0x01b00000
0x0e1b00808 0x000f0400000 0x00400000
0x0e1f00808 0x000f0800000 0x00004000
0x0e1f04808 0x000ffff0000 0x00010000
0x0e1f14808 0x00100000000 0xffdf0000
0x1e1d04808 0x001ffdf0000 0x20210000
```

The system below had 10 GB RAM:

```
File Offset Memory Offset Size      
----------- ------------- ----------
0x000000808 0x00000000000 0xe0000000
0x0e0000808 0x000e0000000 0x01b00000
0x0e1b00808 0x000f0400000 0x00400000
0x0e1f00808 0x000f0800000 0x00004000
0x0e1f04808 0x000ffff0000 0x00010000
0x0e1f14808 0x00100000000 0xffdf0000
0x1e1d04808 0x001ffdf0000 0x9de10000
```

The system below had 16 GB RAM:

```
File Offset Memory Offset Size      
----------- ------------- ----------
0x000000878 0x00000000000 0xe0000000
0x0e0000878 0x000e0000000 0x01b00000
0x0e1b00878 0x000f0400000 0x00400000
0x0e1f00878 0x000f0800000 0x00004000
0x0e1f04878 0x000ffff0000 0x00010000
0x0e1f14878 0x00100000000 0xffdf0000
0x1e1d04878 0x001ffdf0000 0xffdf0000
0x2e1af4878 0x002ffbe0000 0xffdf0000
0x3e18e4878 0x003ff9d0000 0x20630000
```

The system below had 24 GB RAM:

```
File Offset Memory Offset Size      
----------- ------------- ----------
0x0000008e8 0x00000000000 0xe0000000
0x0e00008e8 0x000e0000000 0x01b00000
0x0e1b008e8 0x000f0400000 0x00400000
0x0e1f008e8 0x000f0800000 0x00004000
0x0e1f048e8 0x000ffff0000 0x00010000
0x0e1f148e8 0x00100000000 0xffdf0000
0x1e1d048e8 0x001ffdf0000 0xffdf0000
0x2e1af48e8 0x002ffbe0000 0xffdf0000
0x3e18e48e8 0x003ff9d0000 0xffdf0000
0x4e16d48e8 0x004ff7c0000 0xffdf0000
0x5e14c48e8 0x005ff5b0000 0x05b50000
```