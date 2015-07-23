# Introduction #

Volatility can analyze memory dumps in the "HPAK" archive format, which is proprietary to the Fast Dump (FDPro.exe) acquisition utility.

# Acquisition #

When acquiring memory with FDPro.exe, use the -hpak command-line option to create a memory dump in the HPAK format. By default, without this option, raw memory dumps will be created.

# Notes #

The target system's physical memory can be zlib-compressed if the "-compress" option is chosen during the acquisition. In this case, we advise that you use the [hpakextract](CommandReference23#hpakextract.md) plugin to convert the .hpak file into a raw memory dump.

# File Format #

A file with an .hpak extension has a 20-byte header. The first four bytes are "HPAK" which is the magic value.

```
>>> dt("HPAK_HEADER")
'HPAK_HEADER' (32 bytes)
0x0   : Magic                          ['String', {'length': 4}]
```

After the standard header, there is a variable number of HPAK\_SECTION structures:

```
>>> dt("HPAK_SECTION")
'HPAK_SECTION' (224 bytes)
0x0   : Header                         ['String', {'length': 32}]
0x8c  : Compressed                     ['unsigned int']
0x98  : Length                         ['unsigned long long']
0xa8  : Offset                         ['unsigned long long']
0xb0  : NextSection                    ['unsigned long long']
0xd4  : Name                           ['String', {'length': 12}]
```

The Header value (a string) will be "HPAKSECTHPAK\_SECTION\_PHYSDUMP" for the section containing physical memory. It will be "HPAKSECTHPAK\_SECTION\_PAGEDUMP" for the section containing the target system's pagefile. If Compressed is non-zero, then the section's data (located at offset Offset and of length Length) is compressed with zlib.

# Meta Data #

The [hpakinfo](CommandReference23#hpakinfo.md) plugin prints information found in the HPAK file headers.

```
$ python vol.py -f memdump.hpak hpakinfo
Header:     HPAKSECTHPAK_SECTION_PHYSDUMP
Length:     0x20000000
Offset:     0x4f8
NextOffset: 0x200004f8
Name:       memdump.bin
Compressed: 0

Header:     HPAKSECTHPAK_SECTION_PAGEDUMP
Length:     0x30000000
Offset:     0x200009d0
NextOffset: 0x500009d0
Name:       dumpfile.sys
Compressed: 0
```