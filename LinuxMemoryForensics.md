# Introduction #

This page describes how to use Volatility's Linux support.

# Prerequisites #

First check the [Release22](Release22.md) page for the supported Linux kernels, distributions, and architectures. Then ensure you have the following tools:

  * dwarfdump: apt-get install dwarfdump on Debian/Ubuntu or the libdwarf-tools package on OpenSuSE, Fedora, and other distributions. If you can't find it in your OS's package manager, build it from the latest [source package](http://reality.sgiweb.org/davea/dwarf.html). Make sure to build libdwarf first and then dwarfdump. Do not build dwarfdump2. Users building profiles on CentOS have also reported success using libdwarf from the [Fedora repository](http://pkgs.fedoraproject.org/repo/pkgs/libdwarf/) and getting the ELF utilities via "yum install elfutils-libelf-devel"
  * GCC/make: apt-get install build-essential on Debial/Ubuntu.
  * headers for building kernel modules: this is the kernel-devel or linux-headers-generic package. sometimes you may need to uname -a to find your kernel version and then be specific like apt-get install linux-headers-2.6.24-16.server

<font color='red'>By far, the most common mistake regarding Linux memory forensics is building a profile for a system other than the machine you want to analyze. For example, you cannot build a profile for a Debian 2.6.32 system to analyze a memory dump from Mandrake 2.6.32. Likewise you cannot build a profile for SuSE 2.5.35 system to analyze a memory dump from SuSE 2.6.42. You must ensure the profile you build matches the target system in 1) Linux distribution 2) exact kernel version 3) CPU architecture (32-bit, 64-bit, etc).</font>

# Getting the Volatility source #

Linux support is available as of [Release22](Release22.md). Please see the release page for direct download links.

# Creating a profile #

A Linux Profile is essentially a zip file with information on the kernel's data structures and debug symbols. This is what Volatility uses to locate critical information and how to parse it once found. In the near future, Volatility will include profiles for the most common Linux kernels. Until then, you'll need to create your own profile.

NOTE: There are known problems building profiles with the dwarfdump distributed with Fedora. If you must use Fedora to build profiles, please see the build procedures in this issue:

https://code.google.com/p/volatility/issues/detail?id=355

## Creating vtypes ##

The current method to create vtypes (kernel's data structures) is to check out the source code and compile 'module.c' against the kernel that you want to analyze. See below for an example of creating vtypes - just cd to 'tools/linux' in the Volatility source directory and type make. This will create a file named 'module.dwarf'.

```
$ cd volatility/tools/linux
$ make
$ head module.dwarf

.debug_info

<0><0+11><DW_TAG_compile_unit> DW_AT_producer<GNU C 4.6.3> DW_AT_language<DW_LANG_C89>.....

<1><45><DW_TAG_typedef> DW_AT_name<__s8> DW_AT_decl_file<1 include/asm-generic/int-ll64.h>.....
```

You can also compile against any kernel by simply pointing make to the directory with the kernel headers and .config file.

## Getting Symbols ##

The symbols are contained in the System.map file (i.e. System.map-3.5.2-3.fc17.x86\_64) for the kernel you want to analyze. This can almost always be found in the /boot directory of the installation or you can generate this file yourself by running "nm" on the vmlinux file of the kernel. If you have updated the kernel on your system in the past, the /boot directory may contain multiple System.map files - so make sure to choose the right one.

## Making the profile ##

To create the profile, place both the module.dwarf and the system.map file into a zip file. Then move this zip file under 'volatility/plugins/overlays/linux/'. Or to do it all in one step:

```
$ sudo zip volatility/volatility/plugins/overlays/linux/Ubuntu1204.zip volatility/tools/linux/module.dwarf /boot/System.map-3.2.0-23-generic 
  adding: volatility/tools/linux/module.dwarf (deflated 89%)
  adding: boot/System.map-3.2.0-23-generic (deflated 79%)
```

There are technically no naming rules for your zip file, but we recommend you choose a name that's descriptive of your Linux distribution and version.

If you _do not_ want to write to the core volatility directories (which may be overwritten during upgrades/uninstalls, or may not even exist if you're using the standalone windows executable), then just place your profiles in a directory on disk and use the --plugins=/path/to/profiles to get them loaded by volatility. Here is an example:

```
C:\Users\Jake\Desktop>volatility-2.2_rc1.standalone.exe --info | findstr Linux
Volatile Systems Volatility Framework 2.2_rc1

C:\Users\Jake\Desktop>dir profiles
 Volume in drive C has no label.
 Volume Serial Number is ACF0-0C63

 Directory of C:\Users\Jake\Desktop\profiles

09/12/2012  01:47 PM    <DIR>          .
09/12/2012  01:47 PM    <DIR>          ..
09/10/2012  10:24 PM           580,930 Mandriva2011.zip
09/10/2012  10:05 PM           681,770 OpenSuSE12.zip
09/10/2012  09:54 PM           765,454 Ubuntu1204.zip
               3 File(s)      2,028,154 bytes
               2 Dir(s)   8,360,775,680 bytes free

C:\Users\Jake\Desktop>volatility-2.2_rc1.standalone.exe --plugins=profiles --info | findstr Linux
Volatile Systems Volatility Framework 2.2_rc1
LinuxMandriva2011x64 - A Profile for Linux Mandriva2011 x64
LinuxOpenSuSE12x86   - A Profile for Linux OpenSuSE12 x86
LinuxUbuntu1204x64   - A Profile for Linux Ubuntu1204 x64
```

## Using the Profile ##

To find the name of your profile, run:

```
$ python vol.py --info | grep Linux
Volatile Systems Volatility Framework 2.2_alpha
LinuxDebian2632_zipx86 - A Profile for Linux Debian2632.zip x86
LinuxDebian2632x86     - A Profile for Linux Debian2632 x86
LinuxUbuntu1204x64    - A Profile for Linux Ubuntu1204 x64 <=== This is the one we just created
```

You can then use this name as the --profile option.

# Using the Plugins #

The basic form to run Volatility is:

```
$ python vol.py -f <path to mem image> --profile=<profile_name> plugin_name <plugin_options>
```

Soon, a wiki page will be created that details every plugin and its output. Until then, to find all the available plugins and get a quick description of their purpose, you can run:

```
$ python vol.py --info | grep -i linux_
Volatile Systems Volatility Framework 2.2_alpha
linux_arp           - Print the ARP table
linux_bash          - Recover bash history from bash process memory
linux_check_afinfo  - Verifies the operation function pointers of network protocols
linux_check_creds   - Checks if any processes are sharing credential structures
linux_check_fop     - Check file operation structures for rootkit modifications
linux_check_idt     - Checks if the IDT has been altered
linux_check_modules - Compares module list to sysfs info, if available
linux_check_syscall - Checks if the system call table has been altered
linux_cpuinfo       - Prints info about each active processor
linux_dentry_cache  - Gather files from the dentry cache
linux_dmesg         - Gather dmesg buffer
linux_dump_map      - Writes selected memory mappings to disk
linux_find_file     - Recovers tmpfs filesystems from memory
linux_ifconfig      - Gathers active interfaces
linux_iomem         - Provides output similar to /proc/iomem
linux_lsmod         - Gather loaded kernel modules
linux_lsof          - Lists open files
linux_memmap        - Dumps the memory map for linux tasks
linux_mount         - Gather mounted fs/devices
linux_mount_cache   - Gather mounted fs/devices from kmem_cache
linux_netstat       - Lists open sockets
linux_pidhashtable  - Enumerates processes through the PID hash table
linux_pkt_queues    - Writes per-process packet queues out to disk
linux_proc_maps     - Gathers process maps for linux
linux_psaux         - Gathers processes along with full command line and start time
linux_pslist        - Gather active tasks by walking the task_struct->task list
linux_pslist_cache  - Gather tasks from the kmem_cache
linux_pstree        - Shows the parent/child relationship between processes
linux_psxview       - Find hidden processes with various process listings
linux_route_cache   - Recovers the routing cache from memory
linux_sk_buff_cache - Recovers packets from the sk_buff kmem_cache
linux_slabinfo      - Mimics /proc/slabinfo on a running machine
linux_tmpfs         - Recovers tmpfs filesystems from memory
linux_vma_cache     - Gather VMAs from the vm_area_struct cache
```

# Acquiring memory #

Volatility does not provide the ability to acquire memory. We recommend using [Lime](http://code.google.com/p/lime-forensics/) for this purpose. It supports 32 and 64 bit captures from native Intel hardware as well as virtual machine guests. It also supports capture from Android devices. See below for example commands building and running LiME:

```
$ tar -xvzf lime-forensics-1.1-r14.tar.gz 
$ cd lime-forensics-1.1-r14/src
$ make
....
  CC [M]  /home/mhl/Downloads/src/tcp.o
  CC [M]  /home/mhl/Downloads/src/disk.o
....
$ sudo insmod lime-3.2.0-23-generic.ko "path=/home/mhl/ubuntu.lime format=lime"
$ ls -alh /home/mhl/ubuntu.lime 
-r--r--r-- 1 root root 2.0G Aug 17 19:37 /home/mhl/ubuntu.lime
```

NOTE: when you execute isnmod, if it tells you "-l Invalid parameter", then repeat the command without quotes around the options. Redhat distros, including CentOS may complain about the quotes, while other distros like Ubuntu require quotes.

# Enterprise Linux Memory Forensics #

The instructions in this document assume you're able to install tools, compile modules, and otherwise run commands on the system suspected to be compromised. Since this is not always the case, especially in forensic situations, or if you have tens or hundreds of Linux systems in a corporate environment, you may need to consider other options. For example, one of your IR planning steps should be to catalog all kernels and distributions that may need to be analyzed. Once you've done that, the possibilities include:

  * Build clones (can be VMs) of each unique distribution and kernel and use them to build a profile, which you can then use against memory dumps from the live systems
  * Build a base system of each distribution and with a gcc version similar to the one your target systems are running. Then build profiles for each target kernel on the single base system. Note: Instructions for doing this will be published here in the future.
  * Acquire a profile from someone else in the community who has built one that matches your criteria. In the future we'll also allow "sharing" or a searchable community repository of Linux profiles.