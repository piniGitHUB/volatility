# Introduction #

Volatility supports OSX memory dumps made with [ATC-NY CyberMarshall Mac Memory Reader](http://cybermarshal.com/index.php/cyber-marshal-utilities/mac-memory-reader).

# Acquisition #

By default, Mac Memory Reader uses a Mach-O file format for memory dumps. It can optionally save in raw/padded (-P) or raw/un-padded (-p) formats. The help information below is from version 3.0.2:

```
$ ./MacMemoryReader 
ATC-NY Mac Marshal Mac Memory Reader 3.0.2 ($Revision: 1.24 $)
Copyright (c) Architecture Technology Corporation.  All rights reserved.

Usage: ./MacMemoryReader [-g] [-d] [-H hashtype] [-r] [-p] [-P] [-k] <filename>

   -g print progress messages suitable for parsing by a GUI
   -d print verbose debugging information to stderr
   -H compute the given hash on the output data (where hashtype
      is one of MD5, SHA-1, SHA-256, or SHA-512); can be given
      multiple times; hash is printed on stderr
   -r also copy "reserved" areas of memory, such as that used
      by shared-memory graphics adapters; EXPERIMENTAL
   -p dump memory in plain raw DD format instead of Mach-O, then write
      a table of contents to stderr listing file offsets versus
      physical memory offsets
   -P dump memory in plain raw DD format, inserting zeros for un-mapped
      regions in the memory map; no table of contents is needed,
      because file offsets will correspond to physical memory
      offsets, but the resulting file may be much larger than RAM
   -k load the RAM dump kernel extension and set up /dev/mem and
      /dev/pmap, but do not dump memory; for EXPERTS ONLY

   dumps physical memory to <filename> in Mach-O (the default) or
   raw/DD format.  The resulting file may be slightly larger than
   physical memory due to the Mach-O header and alignment constraints.
   If the filename is '-', memory is dumped to stdout.
```

# Notes #

If you plan to do analysis with Volatility, you must either use the default Mach-O or raw/padded. We do not, and never will, support raw/un-padded.

# File Format #

The Mach-O file format is a standard documented by Apple - see [OS X ABI Mach-O File Format Reference](https://developer.apple.com/library/mac/#documentation/DeveloperTools/Conceptual/MachORuntime/Reference/reference.html) for more details.

The memory dump will begin with a mach\_header or mach\_header\_64 structure, as shown below. The magic is MH\_MAGIC (0xFEEDFACE) for mach\_header and MH\_MAGIC\_64 (0xFEEDFACF) for mach\_header\_64.

```
>>> dt("mach_header_64")
'mach_header_64' (32 bytes)
0x0   : magic                          ['unsigned int']
0x4   : cputype                        ['int']
0x8   : cpusubtype                     ['int']
0xc   : filetype                       ['unsigned int']
0x10  : ncmds                          ['unsigned int']
0x14  : sizeofcmds                     ['unsigned int']
0x18  : flags                          ['unsigned int']
0x1c  : reserved                       ['unsigned int']
```

Immediately following the header, one or more segment\_command or segment\_command\_64 structures can be found. These describe the memory runs, in particular the virtual address and size of the run and the offset within the file where the data can be found.

```
>>> dt("segment_command_64")
'segment_command_64' (72 bytes)
0x0   : cmd                            ['unsigned int']
0x4   : cmdsize                        ['unsigned int']
0x8   : segname                        ['array', 16, ['char']]
0x18  : vmaddr                         ['unsigned long long']
0x20  : vmsize                         ['unsigned long long']
0x28  : fileoff                        ['unsigned long long']
0x30  : filesize                       ['unsigned long long']
0x38  : maxprot                        ['int']
0x3c  : initprot                       ['int']
0x40  : nsects                         ['unsigned int']
0x44  : flags                          ['unsigned int']
```

# Meta Data #

You can use the machoinfo plugin to receive information on the Mach-O file.

```
$ python vol.py --profile=MacMountainLion_10_8_3_AMDx64 -f ~/Desktop/10.8.3/10.8.3.mmr.macho machoinfo
Volatile Systems Volatility Framework 2.3_alpha
Magic: 0xfeedfacf
Architecture: 64-bit
File Offset        Memory Offset      Size               Name
------------------ ------------------ ------------------ ----
0x0000000000004000 0x0000000000000000 0x000000000008e000 available
0x0000000000092000 0x0000000000090000 0x0000000000010000 available
0x00000000000a2000 0x0000000000100000 0x000000000f200000 available
0x000000000f2a2000 0x000000000f300000 0x0000000000013000 LoaderData
0x000000000f2b5000 0x000000000f313000 0x00000000000ed000 available
0x000000000f3a2000 0x000000000f400000 0x0000000000535000 LoaderData
0x000000000f8d7000 0x000000000f935000 0x00000000000cb000 available
0x000000000f9a2000 0x000000000fa00000 0x00000000021f2000 LoaderData
0x0000000011b94000 0x0000000011bf2000 0x0000000000053000 RT_data
0x0000000011be7000 0x0000000011c45000 0x0000000000028000 RT_code
......
```