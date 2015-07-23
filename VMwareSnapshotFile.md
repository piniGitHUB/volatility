# Introduction #

Volatility can analyze VMware saved state (.vmss) and VMware snapshot (.vmsn) files. This capability was researched and introduced by Nir Izraeli and the AS is modeled after his [vmsnparser project](http://code.google.com/p/vmsnparser/). Saved state and snapshot files are not the same as typical .vmem files that most everyone is familiar with. Rather, these .vmss/.vmsn contain a fairly complex structure layout which contains the physical memory runs, the VM configuration data, CPU registers, and even PNG thumbnails of the VM's screen.

# Acquisition #

While some VMware products store guest memory in .vmem files, other products (such as ESX) create these .vmsn or .vmss files when you suspend or take snapshots of running virtual machines. Since ESX is typically used for larger virtualization environments (compared to VMware Fusion or VMware Desktop), the capability to analyze .vmss/.vmsn can be critical in corporate IR/forensics.

# Notes #

You can convert a .vmss/.vmsn to a raw dd-style memory dump by extracting the physical memory runs to a separate file. To do this, use the [imagecopy](http://code.google.com/p/volatility/wiki/CommandReference22#imagecopy) plugin.

# File Format #

At offset 0 of the .vmss/.vmsn file, there's a `_VMWARE_HEADER` structure, which looks like this:

```
>>> dt("_VMWARE_HEADER")
'_VMWARE_HEADER' (12 bytes)
0x0   : Magic                          ['unsigned int']
0x8   : GroupCount                     ['unsigned int']
0xc   : Groups                         ['array', <function <lambda> at 0x1046b7320>, ['_VMWARE_GROUP']]
```

As you can see, there's a magic value which must be 0xbed2bed0, 0xbad1bad1, 0xbed2bed2, or 0xbed3bed3 for the file to be considered valid. There is an array of `_VMWARE_GROUP` structures, which look like this:

```
>>> dt("_VMWARE_GROUP")
'_VMWARE_GROUP' (80 bytes)
0x0   : Name                           ['String', {'length': 64, 'encoding': 'utf8'}]
0x40  : TagsOffset                     ['unsigned long long']
```

Thus the groups have a name and a 64-bit offset to an array of `_VMWARE_TAG` structures:

```
>>> dt("_VMWARE_TAG")
'_VMWARE_TAG' (None bytes)
0x0   : Flags                          ['unsigned char']
0x1   : NameLength                     ['unsigned char']
0x2   : Name                           ['String', {'length': <function <lambda> at 0x1046b7398>, 'encoding': 'utf8'}]
```

The tag structures are a bit more complex than others. They have a name, a Flags field which devotes some bits to the length of the data associated with the tag, and a set of indices (not shown) which allow you to distinguish between multiple tags with the same name within a group.

The data for a tag follows the `_VMWARE_TAG` structure, however there are a few intricacies that Nir researched. If you need details, see the source code. If the system has less than 4 GB of RAM, there will be a single physical memory run stored in a group named "memory" and a tag named "Memory" using indices `[0][0]`. For systems with greater than 4 GB of RAM, there will be multiple runs, also in a group named "memory" but including tags named "Memory", "regionPPN", "regionPageNum", and "regionSize."

# Meta Data #

You can dump meta-data from .vmss/.vmsn files using the vmwareinfo plugin. If the data in a tag is 1, 2, 4, or 8 bytes, it's formatted as a number. If its more than 8 bytes and you supply --verbose to the plugin, you'll get a hexdump.

```
$ python vol.py -f ~/Desktop/Win7SP1x64-d8737a34.vmss vmwareinfo --verbose | less

Magic: 0xbad1bad1 (Version 1)
Group count: 0x5c

File Offset PhysMem Offset Size      
----------- -------------- ----------
0x000010000 0x000000000000 0xc0000000
0x0c0010000 0x000100000000 0xc0000000

DataOffset   DataSize Name                                               Value
---------- ---------- -------------------------------------------------- -----
0x00001cd9        0x4 Checkpoint/fileversion                             0xa
0x00001cfc      0x100 Checkpoint/ProductName                             
0x00001cfc  56 4d 77 61 72 65 20 45 53 58 00 00 00 00 00 00   VMware.ESX......
0x00001d0c  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
[snip]
0x00001e1d      0x100 Checkpoint/VersionNumber                           
0x00001e1d  34 2e 31 2e 30 00 00 00 00 00 00 00 00 00 00 00   4.1.0...........
0x00001e2d  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
[snip]
0x00002046        0x4 Checkpoint/Platform                                0x1
0x00002055        0x4 Checkpoint/usageMode                               0x1
0x00002062        0x4 Checkpoint/memSize                                 0x1800
0x00002071        0x4 Checkpoint/maxFBSize                               0x800000
0x00002085        0x4 cpu/cpu:numVCPUs                                   0x1
0x00002095        0x4 cpu/eflags[0]                                      0x86
0x000020a2        0x8 cpu/rip[0]                                         0xfffff80002c1c0ba
0x000020b3        0x4 cpu/eip[0]                                         0x2c1c0ba
0x000020c3        0x1 cpu/halted[0]                                      0
[snip]
0x00005eea        0x4 cpu/CR[0][0]                                       0x80050031
0x00005efa        0x4 cpu/CR[0][1]                                       0x0
0x00005f0a        0x4 cpu/CR[0][2]                                       0x865eb08
0x00005f1a        0x4 cpu/CR[0][3]                                       0x187000
0x00005f2a        0x4 cpu/CR[0][4]                                       0x6f8
0x00005f3c        0x8 cpu/DR64[0][0]                                     0x0
[snip]
0x00006020        0x8 cpu/DR64[0][6]                                     0xffff0ff0
0x00006034        0x4 cpu/DR[0][6]                                       0xffff0ff0
0x00006046        0x8 cpu/DR64[0][7]                                     0x400
0x0000605a        0x4 cpu/DR[0][7]                                       0x400
0x0000606c        0x2 cpu/GDTR[0][0]                                     127
0x0000607c        0x4 cpu/GDTR[0][1]                                     0x3cd5000
0x0000608e        0x4 cpu/GDTR[0][2]                                     0xfffff800
0x000060a0        0x2 cpu/IDTR[0][0]                                     4095
0x000060b0        0x4 cpu/IDTR[0][1]                                     0x3cd5080
0x000060c2        0x4 cpu/IDTR[0][2]                                     0xfffff800
[snip]
0x180011963    0x2c29 Snapshot/cfgFile                                   
0x180011953  2e 65 6e 63 6f 64 69 6e 67 20 3d 20 22 55 54 46   .encoding.=."UTF
0x180011963  2d 38 22 0a 63 6f 6e 66 69 67 2e 76 65 72 73 69   -8".config.versi
0x180011973  6f 6e 20 3d 20 22 38 22 0a 76 69 72 74 75 61 6c   on.=."8".virtual
0x180011983  48 57 2e 76 65 72 73 69 6f 6e 20 3d 20 22 37 22   HW.version.=."7"
0x180011993  0a 70 63 69 42 72 69 64 67 65 30 2e 70 72 65 73   .pciBridge0.pres
0x1800119a3  65 6e 74 20 3d 20 22 74 72 75 65 22 0a 70 63 69   ent.=."true".pci
0x1800119b3  42 72 69 64 67 65 34 2e 70 72 65 73 65 6e 74 20   Bridge4.present.
0x1800119c3  3d 20 22 74 72 75 65 22 0a 70 63 69 42 72 69 64   =."true".pciBrid
0x1800119d3  67 65 34 2e 76 69 72 74 75 61 6c 44 65 76 20 3d   ge4.virtualDev.=
0x1800119e3  20 22 70 63 69 65 52 6f 6f 74 50 6f 72 74 22 0a   ."pcieRootPort".
```