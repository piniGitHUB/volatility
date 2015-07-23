# Introduction #

A hibernation file (hiberfil.sys) contains a complete copy of memory that is dumped to disk by the system during the hibernation process.

# Acquisition #

As explained by Microsoft [KB 920730](http://support.microsoft.com/kb/920730), to acquire a hibernation file, first enable hibernation in the kernel (`powercfg.exe /hibernate on`). Then issue a `shutdown /h` command to hibernate. Depending on your os version, you might also be able to do it by clicking from the Start menu (Start  -> Hibernate or Start -> Shutdown -> Hibernate). You'll have to copy off the C:\hiberfil.sys file by mounting the disk from an analysis machine (or by using a live CD/DVD).

# Notes #

Network connections may be unavailable or closed in hibernation files, due to DHCP releases and other routine actions a system performs before hibernation.

# File Format #

Hibernation files consist of a standard header (`PO_MEMORY_IMAGE`), a set of kernel contexts and registers such as CR3 (`_KPROCESSOR_STATE`) and several arrays of compressed/encoded Xpress data blocks (`_IMAGE_XPRESS_HEADER` and `_PO_MEMORY_RANGE_ARRAY`).

The standard header exists at offset 0 of the file and is shown below. Generally, the Signature member must be either "hibr" or "wake" to be considered valid, however in rare cases the entire `PO_MEMORY_IMAGE` header has been zeroed out, which can prevent analysis of the hibernation file in most tools. In those cases, volatility will use a brute force algorithm to locate the data it needs.

```
>>> dt("PO_MEMORY_IMAGE")
'PO_MEMORY_IMAGE' (168 bytes)
0x0   : Signature                      ['String', {'length': 4}]
0x4   : Version                        ['unsigned long']
0x8   : CheckSum                       ['unsigned long']
0xc   : LengthSelf                     ['unsigned long']
0x10  : PageSelf                       ['unsigned long']
0x14  : PageSize                       ['unsigned long']
0x18  : ImageType                      ['unsigned long']
0x20  : SystemTime                     ['WinTimeStamp', {}]
0x28  : InterruptTime                  ['unsigned long long']
0x30  : FeatureFlags                   ['unsigned long']
0x34  : HiberFlags                     ['unsigned char']
0x35  : spare                          ['array', 3, ['unsigned char']]
0x38  : NoHiberPtes                    ['unsigned long']
0x3c  : HiberVa                        ['unsigned long']
0x40  : HiberPte                       ['_LARGE_INTEGER']
0x48  : NoFreePages                    ['unsigned long']
0x4c  : FreeMapCheck                   ['unsigned long']
0x50  : WakeCheck                      ['unsigned long']
0x54  : TotalPages                     ['unsigned long']
0x58  : FirstTablePage                 ['unsigned long']
0x5c  : LastFilePage                   ['unsigned long']
0x60  : PerfInfo                       ['_PO_HIBER_PERF']
```

More details on the hibernation file format can be seen in [Windows Hibernation File For Fun N' Profit](http://www.blackhat.com/presentations/bh-usa-08/Suiche/BH_US_08_Suiche_Windows_hibernation.pdf).

# Meta Data #

Coming soon....