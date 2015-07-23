

# Introduction #

These are the instructions for using the Mac support in Volatility. A presentation on the initial set of features can be found [here](http://www.slideshare.net/AndrewDFIR/mac-memory-analysis-with-volatility).

# Determine your version #

Before you analyze a memory dump with Volatility, figure out what version of OSX you're dealing with. To do this, click the Apple icon in the top left corner of your Mac's screen and choose About This Mac. Look at the Version number, as shown below.

![https://lh3.googleusercontent.com/-J38DLJdf1F8/UVnPpKk2UqI/AAAAAAAADHo/eeqPo0eOyKk/s379/AppleVersion.png](https://lh3.googleusercontent.com/-J38DLJdf1F8/UVnPpKk2UqI/AAAAAAAADHo/eeqPo0eOyKk/s379/AppleVersion.png)

To verify your architecture, use the following command. If you see "RELEASE\_X86\_64 x86\_64" then choose the AMD 64-bit profile. If you see "RELEASE\_I386 i386" then choose the Intel 32-bit profile.

```
$ uname -a | cut -d/ -f2
RELEASE_X86_64 x86_64
```

Note: Some Macs ship with kernels capable of running in 32-bit or 64-bit mode. Even if you see "RELEASE\_I386 i386" it may be possible to boot your system into 64-bit mode. To check, run the file command on your /mach\_kernel. As you can see, the machine below can run as i386 (32-bit), x86\_64 (64-bit), or ppc.

```
$ file /mach_kernel 
/mach_kernel: Mach-O universal binary with 3 architectures
/mach_kernel (for architecture x86_64):	Mach-O 64-bit executable x86_64
/mach_kernel (for architecture i386):	Mach-O executable i386
/mach_kernel (for architecture ppc):	Mach-O executable ppc
```

Assuming you wanted to switch to a different mode, for testing purposes, you can do the following and then reboot. For more information see [Apple Support HT3773](https://support.apple.com/kb/HT3773).

```
$ sudo systemsetup -setkernelbootarchitecture x86_64
setting kernel architecture to: x86_64
changes to kernel architecture have been saved.
```

# Download pre-built profiles #

Click to download an [archive of 38 different Mac OSX profiles](https://code.google.com/p/volatility/downloads/detail?name=MacProfilesAll.zip). Extract the main zip and copy/move the individual profiles that you want to activate into your volatility/plugins/overlays/mac folder.

  * Leopard 10.5 (32-bit)
  * Leopard 10.5.3 (32-bit)
  * Leopard 10.5.4 (32-bit)
  * Leopard 10.5.5 (32-bit)
  * Leopard 10.5.6 (32-bit)
  * Leopard 10.5.7 (32-bit)
  * Leopard 10.5.8 (32-bit)
  * Snow Leopard 10.6 (32 and 64-bit)
  * Snow Leopard 10.6.1 (32 and 64-bit)
  * Snow Leopard 10.6.2 (32 and 64-bit)
  * Snow Leopard 10.6.4 (32 and 64-bit)
  * Snow Leopard 10.6.5 (32 and 64-bit)
  * Snow Leopard 10.6.6 (32 and 64-bit)
  * Lion 10.7 (32 and 64-bit)
  * Lion 10.7.1 (32 and 64-bit)
  * Lion 10.7.2 (32 and 64-bit)
  * Lion 10.7.3 (32 and 64-bit)
  * Lion 10.7.4 (32 and 64-bit)
  * Lion 10.7.5 (32 and 64-bit)
  * Mountain Lion 10.8.1 (64-bit)
  * Mountain Lion 10.8.2 (64-bit)
  * Mountain Lion 10.8.3 (64-bit)

# Building a Profile #

If you need to perform memory analysis on a version of Mac OSX that isn't in the list above, you will need to build your own profile.

## Getting the source ##

The source can be currently downloaded by checking out with SVN:

```
$ svn co http://volatility.googlecode.com/svn/trunk volatility-trunk
```

## Creating a profile ##

To create a profile, you first need to download the KernelDebugKit for the kernel you want to analyze. This can be downloaded from the [Apple Developer's website](http://developer.apple.com/hardwaredrivers) (click OS X Kernel Debug Kits on the right). This account is free and only requires a valid Email address.

After the DebugKit is downloaded, mount the dmg file. This will place the contents at "/Volumes/KernelDebugKit".

## Creating the vtypes ##

### Step 1 ###

The first step is to get the dwarf (debug) info from the kernel. The following shows how this can be done for the 32 bit debug information:

```
$ dwarfdump -arch i386 -i /Volumes/KernelDebugKit/mach_kernel.dSYM > 10.7.2.32bit.dwarfdump
```

You would use "-arch x86\_64" for the 64 bit information.

### Step 2 ###

The next step is to convert the Mac dwarfdump output to the Linux style output supported by Volatility:

```
$ python tools/mac/convert.py 10.7.2.32bit.dwarfdump converted-10.7.2.32bit.dwarfdump
```

### Step 3 ###

Create the vtypes file from the converted file. It is required that you give the output file a .vtypes extension.

```
$ python tools/mac/convert.py converted-10.7.2.32bit.dwarfdump > 10.7.2.32bit.vtypes
```

## Symbol information ##

Generate symbols in the following manner. It is required that you give the output file a .symbol.dsymutil extension.

```
$ dsymutil -s -arch i386 /Volumes/KernelDebugKit/mach_kernel > 10.7.2.32bit.symbol.dsymutil 
```

## Putting it all together ##

Create a zip archive of the .vtypes and .symbol.dysmutil files that you've created.

```
$ zip 10.7.2.32bit.zip 10.7.2.32-bit.symbol.dsymutil 10.7.2.32bit.vtypes 
```

The zip file is now what you use as the profile. Copy the profile into the "volatility/plugins/overlays/mac" directory and then run:

```
$ python vol.py --info | grep Mac
```

and find the name of your profile. This is what you will use to the --profile option.

# Acquiring memory #

Volatility does not provide the ability to acquire memory. We recommend using [Mac Memory Reader](http://www.cybermarshal.com/index.php/cyber-marshal-utilities/mac-memory-reader) from ATC-NY for this purpose. It supports 32 and 64 bit captures from native hardware, parallels, and virtual box. It currently does not support VMware fusion guests.

# Plugins #

To find all currently available plugins, use the following command. For more information on what these plugins do and how to use them correctly, see the [MacCommandReference23](MacCommandReference23.md) page.

```
$ python vol.py --info | grep mac_
mac_arp                 - Prints the arp table
mac_check_syscalls      - Checks to see if system call table entries are hooked
mac_check_sysctl        - Checks for unknown sysctl handlers
mac_check_trap_table    - Checks to see if system call table entries are hooked
mac_dead_procs          - Prints terminated/de-allocated processes
mac_dmesg               - Prints the kernel debug buffer
mac_dump_maps           - Dumps memory ranges of processes
mac_find_aslr_shift     - Find the ASLR shift value for 10.8+ images
mac_ifconfig            - Lists network interface information for all devices
mac_ip_filters          - Reports any hooked IP filters
mac_list_sessions       - Enumerates sessions
mac_list_zones          - Prints active zones
mac_ls_logins           - Lists login contexts
mac_lsmod               - Lists loaded kernel modules
mac_lsof                - Lists per-process opened files
mac_machine_info        - Prints machine information about the sample
mac_mount               - Prints mounted device information
mac_netstat             - Lists active per-process network connections
mac_notifiers           - Detects rootkits that add hooks into I/O Kit (e.g. LogKext)
mac_pgrp_hash_table     - Walks the process group hash table
mac_pid_hash_table      - Walks the pid hash table
mac_print_boot_cmdline  - Prints kernel boot arguments
mac_proc_maps           - Gets memory maps of processes
mac_psaux               - Prints processes with arguments in user land (**argv)
mac_pslist              - List Running Processes
mac_pstree              - Show parent/child relationship of processes
mac_psxview             - Find hidden processes with various process listings
mac_route               - Prints the routing table
mac_tasks               - List Active Tasks
mac_trustedbsd          - Lists malicious trustedbsd policies
mac_version             - Prints the Mac version
mac_vfs_events          - Lists Mac VFS Events
mac_volshell            - Shell in the memory image
mac_yarascan            - A shell in the mac memory image
```