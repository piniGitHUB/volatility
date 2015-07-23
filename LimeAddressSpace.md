# Introduction #

LiME is a format created by Joe Sylve. From the tool's [website](http://code.google.com/p/lime-forensics/),  LiME (formerly DMD) is a Loadable Kernel Module (LKM), which allows the acquisition of volatile memory from Linux and Linux-based devices, such as those powered by Android. LiME...."minimizes its interaction between user and kernel space processes during acquisition, which allows it to produce memory captures that are more forensically sound than those of other tools designed for Linux memory acquisition."

# Acquisition #

For instructions on using LiME to capture memory, see the tool's [documentation (PDF)](http://lime-forensics.googlecode.com/files/LiME_Documentation_1.1.pdf), the LinuxMemoryForensics or AndroidMemoryForensics wiki pages. Although the LiME LKM can produce dumps in various formats (raw, padded, and lime), Volatility's LimeAddressSpace deals specifically with the lime format. Thus, if you want to analyze the memory in Volatility, you must specify format=lime when performing the acquisition.

# File Format #

A lime (v1) file begins with an array of `lime_header` structures as shown below. The `magic` member must be 0x4C694D45 (LiME) to be considered valid.

```
>>> dt("lime_header")
'lime_header' (32 bytes)
0x0   : magic                          ['unsigned int']
0x4   : version                        ['unsigned int']
0x8   : start                          ['unsigned long long']
0x10  : end                            ['unsigned long long']
0x18  : reversed                       ['unsigned long long']
```