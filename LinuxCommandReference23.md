

# Processes #

## linux\_pslist ##

This plugin prints the list of active processes starting from the `init_task` symbol and walking the `task_struct->tasks` linked list. It does not display the swapper process. If the DTB column is blank, the item is likely a kernel thread.

```
$ python vol.py -f ~/Desktop/Linux/ubuntu.lime --profile=LinuxUbuntu1204x64 linux_pslist
Volatile Systems Volatility Framework 2.2_rc2
Offset             Name                 Pid             Uid             Gid    DTB                Start Time
------------------ -------------------- --------------- --------------- ------ ------------------ ----------
0xffff88007b818000 init                 1               0               0      0x00000000366ec000 Fri, 17 Aug 2012 19:55:38 +0000
0xffff88007b8196f0 kthreadd             2               0               0      ------------------ Fri, 17 Aug 2012 19:55:38 +0000
0xffff88007b81ade0 ksoftirqd/0          3               0               0      ------------------ Fri, 17 Aug 2012 19:55:38 +0000
0xffff88007b81c4d0 kworker/0:0          4               0               0      ------------------ Fri, 17 Aug 2012 19:55:38 +0000
[snip]
0xffff8800790c5bc0 gnome-pty-helpe      11285           1000            1000   0x00000000308c1000 Fri, 17 Aug 2012 21:29:31 +0000
0xffff88007ad15bc0 bash                 11286           1000            1000   0x00000000309fa000 Fri, 17 Aug 2012 21:29:31 +0000
0xffff88005b8bdbc0 firefox              11370           1000            1000   0x00000000308a8000 Fri, 17 Aug 2012 21:31:22 +0000
0xffff880079f62de0 at-spi-bus-laun      11389           1000            1000   0x0000000030b8b000 Fri, 17 Aug 2012 21:31:22 +0000
0xffff880027d28000 notify-osd           18366           1000            1000   0x0000000027d10000 Fri, 17 Aug 2012 22:30:37 +0000
0xffff88005b8c16f0 kworker/0:1          18535           0               0      ------------------ Fri, 17 Aug 2012 22:31:13 +0000
0xffff880065ac44d0 kworker/0:2          18646           0               0      ------------------ Fri, 17 Aug 2012 22:36:14 +0000
0xffff880030b22de0 sudo                 18649           1000            1000   0x0000000027ed3000 Fri, 17 Aug 2012 22:36:42 +0000
0xffff880027efc4d0 insmod               18650           0               0      0x00000000309db000 Fri, 17 Aug 2012 22:36:42 +0000
```

## linux\_psaux ##

This plugin subclasses `linux_pslist` so it enumerates processes in the same way as described above. However, it mimics the `ps aux` command on a live system (specifically it can show the command-line arguments).

```
$ python vol.py -f ~/Desktop/Linux/ubuntu.lime --profile=LinuxUbuntu1204x64 linux_psaux
Volatile Systems Volatility Framework 2.2_rc2
Pid    Uid    Arguments                                                       
1      0      /sbin/init ro quiet splash                                       Fri, 17 Aug 2012 19:55:38 +0000    
2      0      [kthreadd]                                                       Fri, 17 Aug 2012 19:55:38 +0000    
3      0      [ksoftirqd/0]                                                    Fri, 17 Aug 2012 19:55:38 +0000    
4      0      [kworker/0:0]                                                    Fri, 17 Aug 2012 19:55:38 +0000
[snip]
11370  1000   /usr/lib/firefox/firefox                                         Fri, 17 Aug 2012 21:31:22 +0000    
11389  1000   /usr/lib/x86_64-linux-gnu/at-spi2-core/at-spi-bus-launcher       Fri, 17 Aug 2012 21:31:22 +0000    
18366  1000   /usr/lib/notify-osd/notify-osd                                   Fri, 17 Aug 2012 22:30:37 +0000    
18535  0      [kworker/0:1]                                                    Fri, 17 Aug 2012 22:31:13 +0000    
18646  0      [kworker/0:2]                                                    Fri, 17 Aug 2012 22:36:14 +0000    
18649  1000   sudo insmod lime-3.2.0-23-generic.ko path=/home/mhl/ubuntu.lime format=lime  Fri, 17 Aug 2012 22:36:42 +0000    
18650  0      insmod lime-3.2.0-23-generic.ko path=/home/mhl/ubuntu.lime format=lime  Fri, 17 Aug 2012 22:36:42 +0000
```

## linux\_pstree ##

This plugin prints a parent/child relationship tree by walking the `task_struct.children` and `task_struct.sibling` members.

```
$ python vol.py -f ~/Desktop/Linux/ubuntu.lime --profile=LinuxUbuntu1204x64 linux_pstree
Volatile Systems Volatility Framework 2.2_rc2
Name                 Pid             Uid            
init                 1               0              
.upstart-udev-br     375             0              
.udevd               412             0              
..udevd              9052            0              
..udevd              9053            0              
.upstart-socket-     707             0          
[snip]
.unity-2d-spread     11236           1000           
.gnome-control-c     11244           1000           
.gnome-terminal      11279           1000           
..gnome-pty-helpe    11285           1000           
..bash               11286           1000           
...sudo              18649           1000           
....insmod           18650           0              
.firefox             11370           1000 
[snip]
```

Here's an example showing how this plugin can associate child processes spawned by a malicious backdoor. In this case pid 2777 is related to the KBeast rootkit and a bash shell and the sleep command were executed by it.

```
# python vol.py --profile=LinuxDebianx86 -f kbeast.lime linux_pstree
Volatile Systems Volatility Framework 2.2_rc1
Name                 Pid             Uid
<snip>
._h4x_bd             2777            0
..bash               3053                0
...sleep             3077                0
<snip>
```

## linux\_pslist\_cache ##

This plugin enumerates processes from kmem\_cache. It currently only works on systems that use SLAB (i.e. SLUB is not  yet supported).

```
$ python vol.py -f ~/Desktop/Linux/centos.lime --profile=LinuxCentOS63x64 linux_pslist_cache
Volatile Systems Volatility Framework 2.2_rc2
Offset             Name                 Pid             Uid             Gid    DTB                Start Time
------------------ -------------------- --------------- --------------- ------ ------------------ ----------
0xffff88003d52c080 fcoemon              1436            0               0      0x000000003d41a000 Tue, 28 Aug 2012 11:06:24 +0000
0xffff88003d52cae0 bash                 3066            0               0      0x000000003c365000 Tue, 28 Aug 2012 11:31:47 +0000
0xffff88003d52d540 console-kit-dae      1927            0               0      0x000000003ceb1000 Tue, 28 Aug 2012 11:06:30 +0000
0xffff88003857c080 su                   3063            0               0      0x000000003d217000 Tue, 28 Aug 2012 11:31:47 +0000
0xffff88003857cae0 gnome-screensav      2209            500             501    0x000000003b066000 Tue, 28 Aug 2012 11:06:49 +0000
0xffff88003857d540 notification-ar      2223            500             501    0x000000003c7ba000 Tue, 28 Aug 2012 11:06:49 +0000
0xffff88003d6cc080 sudo                 3062            0               501    0x000000003c367000 Tue, 28 Aug 2012 11:31:47 +0000
0xffff88003d6ccae0 hald-runner          1619            0               0      0x000000003c52b000 Tue, 28 Aug 2012 11:06:26 +0000
0xffff88003d6cd540 Xorg                 1897            0               0      0x000000003c626000 Tue, 28 Aug 2012 11:06:30 +0000
0xffff88003c0d6040 nm-applet            2181            500             501    0x000000003bb4a000 Tue, 28 Aug 2012 11:06:49 +0000
[snip]
```

## linux\_pidhashtable ##

This plugin enumerates processes by walking the pid hash table. It can assist with detecting hidden processes. The output will appear similar to linux\_pslist, but in a different order.

```
$ python vol.py --profile=LinuxMandriva2011x64 -f mandriva.lime linux_pidhashtable
Offset             Name                 Pid             Uid             Gid    DTB                Start Time
------------------ -------------------- --------------- --------------- ------ ------------------ ----------
0xffff880010b6c410 console-kit-dae      1880            0               0      0x0000000011fa5000 2012-08-28 04:34:01 UTC+0000
0xffff88000f8016b0 mpt_poll_0           262             0               0      ------------------ 2012-08-28 04:33:46 UTC+0000
0xffff880014132d60 console-kit-dae      1914            0               0      0x0000000011fa5000 2012-08-28 04:34:01 UTC+0000
0xffff880001a496b0 kmix                 6315            500             500    0x000000001232b000 2012-08-28 17:17:57 UTC+0000
0xffff88000fac5ac0 rtkit-daemon         5794            492             491    0x0000000013931000 2012-08-28 17:17:20 UTC+0000
0xffff880012d1c410 hald                 1859            485             483    0x0000000012fe2000 2012-08-28 04:34:01 UTC+0000
....
```

## linux\_psxview ##

This plugin is similar in concept to the [Windows psxview command](CommandReference22#psxview.md) in that it gives you a cross-reference of processes based on multiple sources (the `task_struct->tasks` linked list, the pid hash table, and the kmem\_cache).

```
$ python vol.py -f ~/Desktop/Linux/centos.lime --profile=LinuxCentOS63x64 linux_psxview
Volatile Systems Volatility Framework 2.2_rc2
Offset(V)          Name                    PID pslist pid_hash kmem_cache
------------------ -------------------- ------ ------ -------- ----------
0xffff88003ef85500 init                      1 True   True     True      
0xffff88003ef84aa0 kthreadd                  2 True   True     True      
0xffff88003ef84040 migration/0               3 True   True     True      
0xffff88003ef91540 ksoftirqd/0               4 True   True     True      
0xffff88003ef90ae0 migration/0               5 True   True     True      
0xffff88003ef90080 watchdog/0                6 True   True     True      
0xffff88003efbb500 events/0                  7 True   True     True 
[snip]
```

## linux\_lsof ##

This plugin mimics the `lsof` command on a live system. It prints the list of open file descriptors and their paths for each running process. To print only the files for a specific process, use the -p PID option.

```
$ python vol.py -f ~/Desktop/Linux/ubuntu.lime --profile=LinuxUbuntu1204x64 linux_lsof
Volatile Systems Volatility Framework 2.2_rc2
Pid      FD       Path
-------- -------- ----
       1        0 /dev/null
       1        1 /dev/null
       1        2 /dev/null
       1        3 /
       1        4 /
       1        5 inotify
       1        6 inotify
       1        7 /
       1        8 /
       1        9 /
       1       10 /var/log/upstart/modemmanager.log
       1       11 /
       1       18 /dev/ptmx
       1       19 /dev/ptmx
[snip]
```

# Process Memory #

## linux\_memmap ##

This plugin prints the list of allocated and memory-resident (non-swapped) pages in a process. The virtual and physical addresses are shown. Choose specific processes with the -p option.

```
$ python vol.py --profile=LinuxMandriva2011x64 -f /Volumes/Storage/memory/Linux/mandriva.lime linux_memmap -p 7047
Task             Pid      Virtual            Physical                         Size
---------------- -------- ------------------ ------------------ ------------------
bash                 7047 0x0000000000400000 0x00000000118e5000             0x1000
bash                 7047 0x0000000000403000 0x000000000d8cc000             0x1000
bash                 7047 0x0000000000404000 0x0000000016dc2000             0x1000
bash                 7047 0x0000000000405000 0x0000000016dc3000             0x1000
bash                 7047 0x0000000000406000 0x0000000003e26000             0x1000
.....
```

## linux\_proc\_maps ##

This plugin prints details of process memory, including heaps, stacks, and shared libraries. In the example below from a KBeast infection, you can see the rootkit module in a hidden directory (with prefix `_h4x_`) starting at  0x8048000 in the memory of process with pid 2777.

```
$ python vol.py --profile=LinuxDebianx86 -f kbeast.lime linux_proc_maps -p 2777
Volatile Systems Volatility Framework 2.2_rc1
0x8048000-0x8049000 r-x          0  8: 1       301353 /usr/_h4x_/_h4x_bd
0x8049000-0x804a000 rw-       4096  8: 1       301353 /usr/_h4x_/_h4x_bd
0xb75d7000-0xb75d8000 rw-          0  0: 0            0
0xb75d8000-0xb772d000 r-x          0  8: 1       513087 /lib/i686/cmov/libc-2.7.so
0xb772d000-0xb772e000 r--    1396736  8: 1       513087 /lib/i686/cmov/libc-2.7.so
0xb772e000-0xb7730000 rw-    1400832  8: 1       513087 /lib/i686/cmov/libc-2.7.so
0xb7730000-0xb7733000 rw-          0  0: 0            0
0xb7739000-0xb773b000 rw-          0  0: 0            0
0xb773b000-0xb773c000 r-x          0  0: 0            0
0xb773c000-0xb7756000 r-x          0  8: 1       505267 /lib/ld-2.7.so
0xb7756000-0xb7758000 rw-     106496  8: 1       505267 /lib/ld-2.7.so
0xbf81b000-0xbf831000 rw-          0  0: 0            0 [stack]
```

You can then specify that base address as the -s/--vma option to `linux_dump_map` to acquire the data in that memory segment. Use it with the -O/--output-file parameter to save to disk.

```
$ python vol.py --profile=LinuxDebianx86 -f kbeast.lime linux_dump_map -p 2777 -s 0x8048000 -O h4x­bd
```

And you can verify what was extracted:

```
$ file h4xbd
bin22: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked (uses shared libs), stripped

$ readelf -s h4xbd
readelf: Error: Unable to read in 0x28 bytes of section headers
readelf: Error: Unable to read in 0x5a0 bytes of section headers
readelf: Error: Unable to read in 0xd0 bytes of dynamic section
```

Note that `readelf` is unable to process the file. To recover the file in-tact, we need to acquire it from the page cache using the `linux­_find_file` plugin. This is because the page cache holds all the physical pages backing a file in memory without any modifications.

## linux\_dump\_map ##

This plugin dumps a memory range specified by the -s/--vma parameter to disk. For a description, see the section in `linux_proc_maps` above.

## linux\_bash ##

This plugin recovers bash history from memory, even in the face of anti-forensics (for example if HISTSIZE is set to 0 or HISTFILE is pointed to /dev/null). For more information, see [MoVP 1.4 Average Coder Rootkit, Bash History, and Elevated Processes](http://volatility-labs.blogspot.com/2012/09/movp-14-average-coder-rootkit-bash.html).

The argument to the -H/--history\_list parameter can be gathered by using gdb on a live system. As shown below, the value you supply is 0x6ed4a0 (this was not calculated by us, its in a comment of the gdb output). For some systems, such as OpenSuSE, the history\_list symbol is in a shared library (readline.so) instead of /bin/bash and ASLR is enabled. In those cases, its not a static value, and the linux\_bash plugin will not work. The -P/--printunalloc argument tells the plugin to print unallocated/deleted commands (can sometimes yield invalid data).

```
mhl@ubuntu:~$ gdb /bin/bash 
GNU gdb (Ubuntu/Linaro 7.4-2012.02-0ubuntu2) 7.4-2012.02
Copyright (C) 2012 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
For bug reporting instructions, please see:
<http://bugs.launchpad.net/gdb-linaro/>...
Reading symbols from /bin/bash...(no debugging symbols found)...done.

(gdb) disassemble history_list
Dump of assembler code for function history_list:
   0x00000000004a5030 <+0>:﻿  mov    0x248469(%rip),%rax        # 0x6ed4a0
   0x00000000004a5037 <+7>:﻿  retq   
End of assembler dump.

(gdb) q
```

Here's an example of the output.

```
$ python vol.py -f avgcoder.mem --profile=LinuxCentOS63x64 linux_bash -H 0x6e0950 -P
Volatile Systems Volatility Framework 2.3_alpha
Pid      Name                 Command Time                   Command
-------- -------------------- ------------------------------ -------
    2738 bash                 2013-08-09 21:28:13 UTC+0000   dmesg | head -50
    2738 bash                 2013-08-09 21:51:28 UTC+0000   df
    2738 bash                 2013-08-09 21:51:50 UTC+0000   dmesg | tail -50
    2738 bash                 2013-08-09 21:51:58 UTC+0000   sudo mount /dev/sda1 /mnt
    2738 bash                 2013-08-09 21:52:02 UTC+0000   cd /mnt
    2738 bash                 2013-08-09 21:52:02 UTC+0000   ls
    2738 bash                 2013-08-09 21:52:08 UTC+0000   sudo insmod rootkit.ko
    2738 bash                 2013-08-09 21:52:56 UTC+0000   echo "hide" > /proc/buddyinfo 
    2738 bash                 2013-08-09 21:53:00 UTC+0000   lsmod | grep root
    2738 bash                 2013-08-09 21:53:14 UTC+0000   w
    2738 bash                 2013-08-09 21:53:38 UTC+0000   echo "huser centoslive" > /proc/buddyinfo 
    2738 bash                 2013-08-09 21:53:40 UTC+0000   w
    2738 bash                 2013-08-09 21:53:49 UTC+0000   sleep 900 &
    2738 bash                 2013-08-09 21:54:01 UTC+0000   echo "hpid 2872" > /proc/buddyinfo 
    2738 bash                 2013-08-09 21:54:13 UTC+0000   ps auwx | grep sleep
    2738 bash                 2013-08-09 21:54:01 UTC+0000   echo "hpid 2872" > /proc/buddyinfo 
    2738 bash                 2013-08-09 21:54:13 UTC+0000   ?
    2738 bash                 2013-08-09 21:52:08 UTC+0000   sudo insmod rootkit.ko
```

Note: The -H/--history\_list argument is now optional starting with Volatility 2.3. If you don't supply it, we now scan in a brute-force manner and automatically find the value. This is critical to being able to find bash history in memory when you don't have access to a live system on which to run gdb. By default, in the brute force mode, we only check processes named "bash" however if an attacker copies /bin/bash to /tmp/a then there may be fragments of attacker's commands in a process named "a" so use -A/--scan\_all to scan all processes regardless of their name.

# Kernel Memory and Objects #

## linux\_lsmod ##

This plugin prints the list of loaded kernel modules starting at the `modules` symbol and walking the `modules.list` linked list. It optionally can print the module section information (with the -S/--sections option) or the module load parameters (with the --P/--params option). In the example below, you can see the lime module is 18070 bytes and it was passed the parameters "format=lime path=/home/mhl/ubuntu.lime" when the user loaded it.

```
$ python vol.py -f ~/Desktop/Linux/ubuntu.lime --profile=LinuxUbuntu1204x64 linux_lsmod -P
Volatile Systems Volatility Framework 2.2_rc2
lime 18070
	format=lime                                                                                         
	dio=Y                                                                                               
	path=/home/mhl/ubuntu.lime                                                                          
vmwgfx 122198
	enable_fbdev=0                                                                                      
ttm 76949
drm 242038
	timestamp_precision_usec=20                                                                         
	vblankoffdelay=5000                                                                                 
	debug=0                                                                                             
vmhgfs 63371
	HOST_VSOCKET_PORT=0                                                                                 
	HOST_PORT=2000                                                                                      
	HOST_IP=(null)                                                                                      
	USE_VMCI=0                 
[snip]
```

## linux\_moddump ##

This plugin dumps linux kernel modules to disk for further inspection. The files are named according to their lkm name, their starting address in kernel memory, and with an .lkm extension. If you know the name of a module you want to dump, you can use the -r/--regex=REGEX parameter with -i/--ignore-case option.

```
$ python vol.py --profile=LinuxUbuntux64 -f ~/ubuntu.lime linux_moddump -D mods/
Volatile Systems Volatility Framework 2.3_alpha
Wrote 16794 bytes to lime.0xffffffffa01ef000.lkm
Wrote 122198 bytes to vmwgfx.0xffffffffa0296000.lkm
Wrote 76949 bytes to ttm.0xffffffffa0282000.lkm
Wrote 242038 bytes to drm.0xffffffffa022f000.lkm
Wrote 63371 bytes to vmhgfs.0xffffffffa021e000.lkm
Wrote 52475 bytes to vsock.0xffffffffa01f7000.lkm
Wrote 82479 bytes to vmci.0xffffffffa01d9000.lkm
[snip]
```

## linux\_tmpfs ##

This plugins lists and recovers tmpfs filesystems from memory. This is very useful in forensics investigations as these filesystems are never written to disk and attackers leverage this fact to hide their data in places like /dev/shm.

To use this plugin you must first list the tmpfs filesystems with the "L" option:

```
# python vol.py --profile=Linuxthisx86 -f after-blog-post.lime linux_tmpfs -L
Volatile Systems Volatility Framework 2.2
1 -> /dev/shm
2 -> /lib/init/rw
```

You then choose a filesystem to recover by number and give an output directory:

```
# python vol.py --profile=Linuxthisx86 -f after-blog-post.lime linux_tmpfs -S 1 -D tmpfs
Volatile Systems Volatility Framework 2.2
# ls -lR tmpfs
tmpfs:
total 0
-rw------- 1 root root 0 Oct  7  2012 XXXXXXXXXXX.injected
```

# Rootkit Detection #

## linux\_check\_afinfo ##

This plugin walks the `file_operations` and `sequence_operations` structures of all UDP and TCP protocol structures including, tcp6\_seq\_afinfo, tcp4\_seq\_afinfo, udplite6\_seq\_afinfo, udp6\_seq\_afinfo, udplite4\_seq\_afinfo, and udp4\_seq\_afinfo, and verifies each member. This effectively detects any tampering with the interesting members of these structures. The following output shows this plugin against the VM infected with KBeast:

```
# python vol.py -f  kbeast.lime --profile=LinuxDebianx86 linux_check_afinfo
Volatile Systems Volatility Framework 2.2_rc1
Symbol Name        Member          Address
-----------        ------          ----------
tcp4_seq_afinfo    show            0xe0fb9965
```

## linux\_check\_tty ##

This plugin detects one of the kernel level keylogging methods described in "Bridging the Semantic Gap to Mitigate Kernel-level
Keyloggers". It works by checking the receive\_buf function pointer for every active tty driver on the system. If the function pointer is not hooked then its symbol name is printed, otherwise "HOOKED" is printed.

```
# python vol.py -f centos.lime --profile=LinuxCentos63Newx64 linux_check_tty
Volatile Systems Volatility Framework 2.3_alpha
Name             Address            Symbol
---------------- ------------------ ------------------------------
tty1             0xffffffff8131a0b0 n_tty_receive_buf
tty2             0xffffffff8131a0b0 n_tty_receive_buf
tty3             0xffffffff8131a0b0 n_tty_receive_buf
tty4             0xffffffff8131a0b0 n_tty_receive_buf
tty5             0xffffffff8131a0b0 n_tty_receive_buf
tty6             0xffffffff8131a0b0 n_tty_receive_buf
```

## linux\_keyboard\_notifier ##

This plugin detects the second kernel level keylogging method described in "Bridging the Semantic Gap to Mitigate Kernel-level Keyloggers". It works by walking the kernel "keyboard\_notifier\_list" and checking if each notifier (callback) is within the kernel.  If the callback is malicious then its symbol name is printed, otherwise "HOOKED" is printed.

## linux\_check\_creds ##

This plugin detects rootkits that have elevated privileges to root using DKOM techniques.

On older 2.6 kernels, the user ID and group ID of a process were kept as simple integers in memory. For a rootkit to elevate the privileges of a process, it simply set these two values to zero.  This simplicity also made it very difficult to use only the information in the process structure itself to detect which processes had been elevated and which were simply spawned by root.

This changed in later versions of 2.6 as the kernel adopted a cred structure to hold all information related to the privileges of a process.  This structure is fairly complicated and forced rootkits to adapt their process elevation methods. Although the kernel provides the prepare\_creds and commit\_creds functions to allocate and store new credentials, a number of rootkits choose not to use this functionality. Instead, they simply find another process that has the privileges of root and that never exits, usually PID 1, and set the cred pointer of the target process to that of PID 1’s. This effectively gives the attacker’s process full control and the rootkit does not have to attempt the non-trivial task of allocating its own cred structure.

The borrowing of cred structures leads to an inconsistency that Volatility can leverage to find elevated processes. In the normal workings of the kernel, every process gets a unique cred structure and they are never shared or borrowed. The linux\_check\_creds plugin utilizes this by building a mapping of processes and their cred structures and then reports any processes that share them.

The following output shows the cred structure running on an infected VM and showing that PID 1 has the same cred structure as the elevated bash shell (PID 9673):

```
$ python vol.py -f avg.hidden-proc.lime --profile=Linuxthisx86 linux_check_creds
Volatile Systems Volatility Framework 2.2_rc1
PIDs
--------
1, 9673
```

For more information on this plugin, see [MoVP 1.4 Average Coder Rootkit, Bash History, and Elevated Processes](http://volatility-labs.blogspot.com/2012/09/movp-14-average-coder-rootkit-bash.html).

## linux\_check\_fop ##

This plugin enumerates the /proc filesystem and all opened files and verifies that each member of every file\_operations structure is valid (valid means the function pointer is either in the kernel or in a known (not hidden) loadable kernel module).

```
$ python vol.py -f avgcoder.mem --profile=LinuxCentOS63x64 linux_check_fop
Volatile Systems Volatility Framework 2.2_rc1
Symbol Name              Member           Address
------------------------ ---------------- ------------------
proc_mnt: root           readdir          0xffffa05ce0e0
buddyinfo                write            0xffffa05cf0f0
modules                  read             0xffffa05ce8a0
```

As we can see from the output, Volatility was able to report the three hooks placed by Average Coder (readdir from root of proc, write of buddyinfo, and read of modules), by enumerating all the files and directories under /proc and verifying their members. From here, the investigator knows the machine is compromised and can begin to investigate the rootkit.

This plugin, when given the –i/--inode option, reads the inode at the given address and verifies each member of its i\_fop pointer.

```
$ python vol.py -f avgcoder.mem --profile=LinuxCentOS63x64 linux_check_fop -i 0x88007a85acc0
Volatile Systems Volatility Framework 2.2_rc1
Symbol Name                   Member                 Address
----------------------------- ---------------------- ------------------
inode at 88007a85acc0         read                   0xffffa05ce4d0
```

As we can see, the plugin tells us that the read member is hooked and the address of the hooked function.

For more information on this plugin, see [MoVP 1.4 Average Coder Rootkit, Bash History, and Elevated Processes](http://volatility-labs.blogspot.com/2012/09/movp-14-average-coder-rootkit-bash.html)

## linux\_check\_idt ##

This plugin enumerates the interrupt descriptor table (IDT) addresses and symbols. If any entries are hooked by rootkits, you'll see "HOOKED" in the far right column instead of the symbol name.

```
$ python vol.py -f ~/Downloads/Metasploitable2-Linux/Metasploitable-555c9224.vmem --profile=LinuxMetasploitx86 linux_check_idt
Volatile Systems Volatility Framework 2.3_alpha
     Index Address    Symbol                        
---------- ---------- ------------------------------
       0x0 0xc0108fec divide_error                  
       0x1 0xc032ff80 debug                         
       0x2 0xc032ffcc nmi                           
       0x3 0xc03300f0 int3                          
       0x4 0xc0108f8c overflow                      
       0x5 0xc0108f98 bounds                        
       0x6 0xc0108fa4 invalid_op                    
       0x7 0xc0108f3c device_not_available          
       0x8 0x00000000 xen_save_fl_direct_reloc      
       0x9 0xc0108fb0 coprocessor_segment_overrun   
       0xa 0xc0108fbc invalid_TSS                   
       0xb 0xc0108fc8 segment_not_present           
       0xc 0xc0108fd4 stack_segment                 
       0xd 0xc033011c general_protection            
       0xe 0xc032ff00 page_fault                    
       0xf 0xc0108ff8 spurious_interrupt_bug        
      0x10 0xc0108f24 coprocessor_error             
      0x11 0xc0108fe0 alignment_check               
      0x12 0xc010035c ignore_int                    
      0x13 0xc0108f30 simd_coprocessor_error        
      0x80 0xc01083d0 system_call 
```

## linux\_check\_syscall ##

This plugin prints the system call tables and checks for hooked functions. For 64-bit systems, it prints both the 32-bit and 64-bit table. If a function is hooked, you'll see "HOOKED" displayed in the output, otherwise you'll see the name of the system call function.

```
$ python vol.py -f ~/Desktop/Linux/ubuntu.lime --profile=LinuxUbuntu1204x64 linux_check_syscall
Volatile Systems Volatility Framework 2.2_rc2
Table Name              Index Address            Symbol                        
---------- ------------------ ------------------ ------------------------------
64bit                     0x0 0xffffffff81177e80 sys_read                      
64bit                     0x1 0xffffffff81177f10 sys_write                     
64bit                     0x2 0xffffffff811770a0 sys_open                      
64bit                     0x3 0xffffffff81175dc0 sys_close                     
64bit                     0x4 0xffffffff8117ca70 sys_newstat                   
64bit                     0x5 0xffffffff8117cb30 sys_newfstat                  
64bit                     0x6 0xffffffff8117cab0 sys_newlstat                  
64bit                     0x7 0xffffffff8118bec0 sys_poll                      
64bit                     0x8 0xffffffff81177710 sys_lseek  
[snip]
```

Here's an example from [MoVP 1.5 KBeast Rootkit, Detecting Hidden Modules, and sysfs](http://volatility-labs.blogspot.com/2012/09/movp-15-kbeast-rootkit-detecting-hidden.html).

```
# python vol.py -f kbeast.lime --profile=LinuxDebianx86 linux_check_syscall > ksyscall

# head -10 ksyscall
Table Name      Index Address    Symbol
---------- ---------- ---------- ------------------------------
32bit             0x0 0xc103ba61 sys_restart_syscall
32bit             0x1 0xc103396b sys_exit
32bit             0x2 0xc100333c ptregs_fork
32bit             0x3 0xe0fb46b9 HOOKED
32bit             0x4 0xe0fb4c56 HOOKED
32bit             0x5 0xe0fb4fad HOOKED
32bit             0x6 0xc10b1b16 sys_close
32bit             0x7 0xc10331c0 sys_waitpid

# grep HOOKED ksyscall
32bit             0x3 0xe0fb46b9 HOOKED
32bit             0x4 0xe0fb4c56 HOOKED
32bit             0x5 0xe0fb4fad HOOKED
32bit             0xa 0xe0fb4d30 HOOKED
32bit            0x25 0xe0fb4412 HOOKED
32bit            0x26 0xe0fb4ebd HOOKED
32bit            0x28 0xe0fb4db1 HOOKED
32bit            0x81 0xe0fb5044 HOOKED
32bit            0xdc 0xe0fb4b9e HOOKED
32bit           0x12d 0xe0fb4e32 HOOKED
```

## linux\_check\_modules ##

This plugin finds rootkits that break themselves from the module list but not sysfs. We have never found a rootkit that actually removes itself from sysfs, so on a live system they are hidden from lsmod and /proc/modules, but can still be found under /sys/modules. We perform the same differnecing with the in-memory data structures. For more information, see [MoVP 1.5 KBeast Rootkit, Detecting Hidden Modules, and sysfs](http://volatility-labs.blogspot.com/2012/09/movp-15-kbeast-rootkit-detecting-hidden.html).

```
# python vol.py -f kbeast.this --profile=LinuxDebianx86 linux_check_modules
Volatile Systems Volatility Framework 2.2_rc1
Module Name
-----------
ipsecs_kbeast_v1
```

## linux\_check\_creds ##

The purpose of this plugin is to check if any processes are sharing 'cred' structures. In the beginning of the 2.6 kernel series, the user ID and group ID were just simple integers, so rootkits could elevate the privleges of userland processes by setting these to 0 (root). In later kernels, credentials are kept in a fairly complicated 'cred' structure. So now rootkits instead of allocating and setting their own 'cred' structure simply set a processes cred structure to be that of another root process that does not exit (usually init / pid 1).  This plugin checks for any processes sharing 'cred' structures and reports them as the kernel would normally never do this. It finds a wide range of rootkits and rootkit activity and you can focus your investigation on elevated process (i.e. bash)

# Networking #

## linux\_arp ##

This plugin prints the ARP table.

```
$ python vol.py --profile=LinuxUbuntux64 -f ~/ubuntu.lime linux_arp
Volatile Systems Volatility Framework 2.3_alpha
WARNING : volatility.obj      : Overlay structure tty_struct not present in vtypes
[?                                         ] at 00:00:00:00:00:00    on lo
[192.168.16.254                            ] at 00:50:56:f5:fd:73    on eth0
[0.0.0.0                                   ] at 00:00:00:00:00:00    on lo
[192.168.16.2                              ] at 00:50:56:fe:70:7d    on eth0
```

## linux\_ifconfig ##

This plugin prints the active interface information, including IPs, interface name, MAC address, and whether the NIC is in promiscuous mode or not (sniffing).

```
$ python vol.py --profile=LinuxUbuntux64 -f ~/ubuntu.lime linux_ifconfig
Volatile Systems Volatility Framework 2.3_alpha
Interface        IP Address           MAC Address        Promiscous Mode
---------------- -------------------- ------------------ ---------------
lo               127.0.0.1            00:00:00:00:00:00  False          
eth0             192.168.16.136       00:0c:29:8a:59:a3  False  
```

## linux\_route\_cache ##

This plugin enumerates the data in the routing table cache. It can show you which systems a machine communicated with in the past.

```
$ python vol.py --profile=LinuxUbuntux64 -f ~/ubuntu.lime linux_route_cache
Volatile Systems Volatility Framework 2.3_alpha
Interface        Destination          Gateway
---------------- -------------------- -------
eth0             173.194.43.41        192.168.16.2
eth0             173.194.43.38        192.168.16.2
eth0             173.194.43.39        192.168.16.2
eth0             173.194.43.46        192.168.16.2
eth0             173.194.73.82        192.168.16.2
eth0             173.194.73.103       192.168.16.2
eth0             91.189.94.25         192.168.16.2
eth0             173.194.43.41        192.168.16.2
eth0             199.7.59.72          192.168.16.2
eth0             173.194.43.37        192.168.16.2
eth0             173.194.73.147       192.168.16.2
[snip]
```

## linux\_netstat ##

This plugin mimics the `netstat` command on a live system. It leverages the `linux_lsof` functionality to list open files in each process. For every file, it checks if the `f_op` member is a `socket_file_ops` or the `dentry.d_op` is a `sockfs_dentry_operations` structure. It then translates those to the proper `inet_sock` structure. The -U/--ignore-unix option will ignore Unix sockets and only print TCP/IP entries.

Here's an example of the command revealing KBeast active network connections:

```
# python vol.py --profile=LinuxDebianx86 -f kbeast.lime linux_netstat -p 2777
Volatile Systems Volatility Framework 2.2_rc1
TCP      192.168.110.150:13377 192.168.110.140:41744 CLOSE_WAIT           _h4x_bd/2777
TCP      0.0.0.0:13377         0.0.0.0:0             LISTEN                       _h4x_bd/2777
TCP      192.168.110.150:13377 192.168.110.140:41745 ESTABLISHED           _h4x_bd/2777
[snip]
```

## linux\_pkt\_queues ##

When a socket is attempting to send packets out onto the network at rates that the network cannot handle, or when the kernel has processed received packets that the corresponding userland service has not yet picked up, these packets are placed on per-socket send and receive queues.

The linux\_pkt\_queues plugin enumerates these queues for each active socket in the kernel and writes the recovered packets to disk.

Running the Plugin:

```
# python vol.py --profile=LinuxDebianx86 -f network.lime linux_pkt_queues -D recovered_packets
Volatile Systems Volatility Framework 2.2_rc1
Wrote 32 bytes to receive.1466.3
Wrote 128 bytes to receive.2565.3
Wrote 32 bytes to receive.2839.3
```

As the plugin finds queued packets, it writes them out with a filename of <receive or send>.

&lt;PID&gt;

.<file descriptor number>.  The owning process can then be referenced by its PID in linux\_pslist / linux\_psaux  and the file descriptor can be matched with output from linux\_lsof on a per-process basis.


## linux\_sk\_buff\_cache ##

The linux\_sk\_buff\_cache plugin leverages the kmem\_cache to find network packets that are in kernel memory and writes them to disk.

Running the plugin:

```
# python vol.py --profile=LinuxDebianx86 -f network.lime linux_sk_buff_cache -D recovered_packets
Volatile Systems Volatility Framework 2.2_rc1
Wrote 20 bytes to de2c60c0
Wrote 1430 bytes to de2da900
Wrote 60 bytes to de21c680
Wrote 42 bytes to de2cc600
Wrote 1430 bytes to de284f00
Wrote 68 bytes to def720c0
Wrote 68 bytes to def72540
```

Sample recovered data:

```
# strings recovered_packets/*
<snip>

GET /safebrowsing/rd/<removed>
HTTP/1.1
Host: safebrowsing-cache.google.com
User-Agent: Mozilla/5.0 (X11; Linux i686; rv:7.0.1) Gecko/20100101 Firefox/7.0.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-us,en;q=0.5
Accept-Encoding: gzip, deflate
Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7
Connection: keep-alive
Cookie: PREF=ID=<removed>:LM=1346093776:S=_zT51pWTC5-mvK0t
Pragma: no-cache
Cache-Control: no-cache
<snip>
```

The plugin enumerates all of the packets from memory and writes them to a file named as the virtual address of where the owning structure was found.  As can be see in the strings output, this plugin is very effective at recovering packets still referenced by the kernel.

Note: This plugin can be run with the –u/--unallocated option to recover packet structures that were previously de-allocated and are no longer in use.


# System Information #

## linux\_cpuinfo ##

This plugin shows information on the target system's CPUs.

```
$ python vol.py --profile=LinuxUbuntux64 -f ~/ubuntu.lime linux_cpuinfo
Volatile Systems Volatility Framework 2.3_alpha
Processor    Vendor           Model
------------ ---------------- -----
0            GenuineIntel     Intel(R) Core(TM) i7 CPU         870  @ 2.93GHz
1            GenuineIntel     Intel(R) Core(TM) i7 CPU         870  @ 2.93GHz
```

## linux\_dmesg ##

This plugin dumps the kernel debug buffer.

```
$ python vol.py --profile=LinuxUbuntux64 -f ~/ubuntu.lime linux_dmesg
Volatile Systems Volatility Framework 2.3_alpha
WARNING : volatility.obj      : Overlay structure tty_struct not present in vtypes
[2314885531810281020.2314885531] ] Initializing cgroup subsys cpuset
<6>[    0.000000] Initializing cgroup subsys cpu
<5>[    0.000000] Linux version 3.2.0-23-generic (buildd@crested) (gcc version 4.6.3 (Ubuntu/Linaro 4.6.3-1ubuntu4) ) #36-Ubuntu SMP Tue Apr 10 20:39:51 UTC 2012 (Ubuntu 3.2.0-23.36-generic 3.2.14)
<6>[    0.000000] Command line: BOOT_IMAGE=/boot/vmlinuz-3.2.0-23-generic root=UUID=af23d300-0fe6-45f6-979b-3eb474727ae8 ro quiet splash
<6>[    0.000000] KERNEL supported cpus:
<6>[    0.000000]   Intel GenuineIntel
<6>[    0.000000]   AMD AuthenticAMD
<6>[    0.000000]   Centaur CentaurHauls
<6>[    0.000000] Disabled fast string operations
<6>[    0.000000] BIOS-provided physical RAM map:
<6>[    0.000000]  BIOS-e820: 0000000000000000 - 000000000009f400 (usable)
<6>[    0.000000]  BIOS-e820: 000000000009f400 - 00000000000a0000 (reserved)
<6>[    0.000000]  BIOS-e820: 00000000000ca000 - 00000000000cc000 (reserved)
[snip]
```

## linux\_iomem ##

This plugin shows the physical addresses currently reserved for IO devices like PCI and video card memory.

```
$ python vol.py --profile=LinuxUbuntux64 -f ~/ubuntu1204/ubuntu.lime linux_iomem
Volatile Systems Volatility Framework 2.3_alpha
WARNING : volatility.obj      : Overlay structure tty_struct not present in vtypes
PCI mem                            	0x0               	0xFFFFFFFFFF      
  reserved                         	0x0               	0xFFFF            
  System RAM                       	0x10000           	0x9F3FF           
  reserved                         	0x9F400           	0x9FFFF           
  PCI Bus 0000:00                  	0xA0000           	0xBFFFF           
  Video ROM                        	0xC0000           	0xC7FFF           
  reserved                         	0xCA000           	0xCBFFF           
    Adapter ROM                    	0xCA000           	0xCAFFF           
  PCI Bus 0000:00                  	0xCC000           	0xCFFFF           
  PCI Bus 0000:00                  	0xD0000           	0xD3FFF           
  PCI Bus 0000:00                  	0xD4000           	0xD7FFF           
  PCI Bus 0000:00                  	0xD8000           	0xDBFFF           
  reserved                         	0xDC000           	0xFFFFF    
[snip]
```

## linux\_slabinfo ##

This plugin mimics the output of reading /proc/slabinfo on a running Linux system. It is part of the infrastructure to allow plugins to read entries from the kmem\_cache.

```
# python vol.py -f centos.lime --profile=LinuxCentos63Newx64 linux_slabinfo
Volatile Systems Volatility Framework 2.3_alpha
<name>                         <active_objs> <num_objs> <objsize>  <objperslab> <pagesperslab>  <active_slabs> <num_slabs>
------------------------------ ------------- ---------- ---------- ------------ --------------- -------------- -----------
fuse_request                   0             0          632        6            1               0              0
fuse_inode                     0             0          768        5            1               0              0
bridge_fdb_cache               0             0          64         59           1               0              0
rpc_buffers                    8             8          2048       2            1               4              4
rpc_tasks                      8             15         256        15           1               1              1
rpc_inode_cache                8             8          832        4            1               2              2
libfc_em                       0             0          256        15           1               0              0
libfc_fcp_pkt                  0             0          256        15           1               0              0
```

## linux\_mount ##

This plugins mimics of the output of /proc/mouns on a running Linux system. For each mountpoint it prints the flags, mounted source (drive, network share, etc) and the director it is mounted on.

```
# python vol.py -f centos.lime --profile=LinuxCentos63Newx64 linux_mount
Volatile Systems Volatility Framework 2.3_alpha
sunrpc                    /var/lib/nfs/rpc_pipefs             rpc_pipefs   rw,relatime
/proc/bus/usb             /proc/bus/usb                       usbfs        rw,relatime
devtmpfs                  /                                   devtmpfs     rw,relatime,nosuid
tmpfs                     /dev/shm                            tmpfs        rw,relatime,nosuid,nodev
/dev/mapper/vg_livecd-lv_root /                                   ext4         rw,relatime
sysfs                     /sys                                sysfs        rw,relatime,nosuid,nodev,noexec
devtmpfs                  /dev                                devtmpfs     rw,relatime,nosuid
/dev/sr0                  /media/CentOS-6.3-x86_64-LiveCD     iso9660      ro,relatime,nosuid,nodev
none                      /proc/sys/fs/binfmt_misc            binfmt_misc  rw,relatime
-hosts                    /net                                autofs       rw,relatime
/etc/auto.misc            /misc                               autofs       rw,relatime
none                      /selinux                            selinuxfs    rw,relatime
devpts                    /dev/pts                            devpts       rw,relatime
proc                      /proc                               proc         rw,relatime,nosuid,nodev,noexec
/dev/sda1                 /boot                               ext4         rw,relatime
```

## linux\_mount\_cache ##

This plugins gathers information on currrently mounted filesystems from the kmem\_cache. You can use the -u option to potentially gather information on previously connected devices.

```
# python vol.py -f centos.lime --profile=LinuxCentos63Newx64 linux_mount_cache
Volatile Systems Volatility Framework 2.3_alpha
sunrpc                    /var/lib/nfs/rpc_pipefs             rpc_pipefs   rw,relatime
/etc/auto.misc            /misc                               autofs       rw,relatime
-hosts                    /net                                autofs       rw,relatime
none                      /proc/sys/fs/binfmt_misc            binfmt_misc  rw,relatime
/dev/sda1                 /boot                               ext4         rw,relatime
/proc/bus/usb             /proc/bus/usb                       usbfs        rw,relatime
devtmpfs                  /dev                                devtmpfs     rw,relatime,nosuid
none                      /selinux                            selinuxfs    rw,relatime
/dev/mapper/vg_livecd-lv_root /                                   ext4         rw,relatime
tmpfs                     /dev/shm                            tmpfs        rw,relatime,nosuid,nodev
devpts                    /dev/pts                            devpts       rw,relatime
devtmpfs                  /                                   devtmpfs     rw,relatime,nosuid
sysfs                     /sys                                sysfs        rw,relatime,nosuid,nodev,noexec
proc                      /proc                               proc         rw,relatime,nosuid,nodev,noexec
/dev/sr0                  /media/CentOS-6.3-x86_64-LiveCD     iso9660      ro,relatime,nosuid,nodev
```



## linux\_dentry\_cache ##

This plugin recovers the filesystem in memory for each active mount point and can also recover filenames of previously deleted files. It outputs pipe-delimited body-file format:

MD5|name|inode|mode\_as\_string|UID|GID|size|atime|mtime|ctime|crtime

```
$ python vol.py -f ~Desktop/Linux/centos.lime --profile=LinuxCentOS63x64 linux_dentry_cache
Volatile Systems Volatility Framework 2.3_alpha
0|home/mhl/Downloads/src/Module.symvers|0|0|0|0|0|0|0|0
0|home/mhl/Downloads/src/.3017.o|0|0|0|0|0|0|0|0
0|home/mhl/Downloads/src/.3017.tmp|0|0|0|0|0|0|0|0
0|tmp/ccN0ri78.o|0|0|0|0|0|0|0|0
0|tmp/cc88gIR4.c|0|0|0|0|0|0|0|0
0|tmp/ccaaUbDc.le|0|0|0|0|0|0|0|0
0|home/mhl/Downloads/src/modules.order|0|0|0|0|0|0|0|0
[snip]
```

If you encounter lines that are all 0's, they're indicative of uninitialized entries. If you see invalid or non-ascii characters in the full path name (as shown below), it means the containing directory was deleted, but the file name portion of the data structure was not wiped out.

```
0|^P?^S^P/???//IBM1026.gz|0|0|0|0|0|0|0|0
0|^P?^S^P/???//IBM037.gz|0|0|0|0|0|0|0|0
0|^P?^S^P/???//HP-TURKISH8.gz|0|0|0|0|0|0|0|0
```

## linux\_find\_file ##

This plugin is typically used in two steps. First you find the inode to a file in the following manner:

```
$ python vol.py -f avgcoder.mem --profile=LinuxCentOS63x64 linux_find_file -F "/var/run/utmp"
Volatile Systems Volatility Framework 2.2_rc1
Inode Number                  Inode
---------------- ------------------
          130564     0x88007a85acc0
```

Then the supply the Inode value (not the Inode Number) as the -i/--inode parameter in order to dump the cached file contents from memory. In the command below, the -O parameter specifies where to dump the resulting file.

```
$ python vol.py -f avgcoder.mem --profile=LinuxCentOS63x64 linux_find_file -i 0x88007a85acc0 -O utmp
```

Now we have a file named "utmp" which was extracted from the memory sample. You can run the `who` command on this file to determine who was logged in:

```
$ who utmp
centoslive tty1         2013-08-09 16:26 (:0)
centoslive pts/0        2013-08-09 16:28 (:0.0)
```

## linux\_vma\_cache ##

This plugins works by walking the kmem\_cache of vm\_area\_struct structures. These structures represent a memory mapping within a process and hold information such as the mapped file, starting and ending addresses, and permissions. Depending on how the kernel is compiled, these structures may also hold a pointer to the task\_struct (process) that opened or still has open the mapping. The "-u" flag can be passed to the plugin to find information on mappings that were closed or that were opened by processes that exited.

```
# python vol.py -f centos.lime --profile=LinuxCentos63Newx64 linux_vma_cache | head -20
Volatile Systems Volatility Framework 2.3_alpha
Process          PID    Start              End                Path
---------------- ------ ------------------ ------------------ ----
bash               3066 0x00000000008dc000 0x00000000008e5000 bin/bash
bash               3066 0x0000000000400000 0x00000000004d4000 bin/bash
packagekitd        2595 0x0000003639e04000 0x000000363a003000 lib64/libattr.so.1.1.0
automount          1712 0x00007f6460000000 0x00007f6460021000
udisks-daemon      2178 0x00007f697f09e000 0x00007f697f09f000 lib64/libnss_files-2.12.so
nm-applet          2181 0x00007f1cb06c9000 0x00007f1cb08c8000 usr/lib64/gtk-2.0/2.10.0/loaders/svg_loader.so
nm-applet          2181 0x00007f1cb08c8000 0x00007f1cb08c9000 usr/lib64/gtk-2.0/2.10.0/loaders/svg_loader.so
bash               3066 0x00000000006d3000 0x00000000006dd000 bin/bash
nm-applet          2181 0x000000363ce00000 0x000000363ce10000 lib64/libbz2.so.1.0.4
nm-applet          2181 0x000000363d00f000 0x000000363d011000 lib64/libbz2.so.1.0.4
nm-applet          2181 0x000000363ce10000 0x000000363d00f000 lib64/libbz2.so.1.0.4
nm-applet          2181 0x00007f1cb011d000 0x00007f1cb0121000 usr/lib64/libcroco-0.6.so.3.0.1
nm-applet          2181 0x00007f1cb0468000 0x00007f1cb0490000
nm-applet          2181 0x00007f1cafee4000 0x00007f1caff1d000 usr/lib64/libcroco-0.6.so.3.0.1
nm-applet          2181 0x00007f1cb06c5000 0x00007f1cb06c7000 usr/lib64/librsvg-2.so.2.26.0
clock-applet       2222 0x00007fce51b72000 0x00007fce51e44000 usr/share/icons/hicolor/icon-theme.cache
clock-applet       2222 0x00007fce5339c000 0x00007fce533b4000 usr/share/mime/mime.cache
clock-applet       2222 0x00007fce5361a000 0x00007fce53621000 usr/lib64/gconv/gconv-modules.cache
```

# Miscellaneous #

## linux\_volshell ##

This plugin presents an interactive shell in the linux memory image. You can use it to simply list processes:

```
$ python vol.py --profile=LinuxUbuntux64 -f ~/ubuntu.lime linux_volshell
Volatile Systems Volatility Framework 2.3_alpha
Current context: process init, pid=1 DTB=0x366ec000
Welcome to volshell! Current memory image is:
file:///Users/michaelligh/Desktop/ubuntu.lime
To get help, type 'hh()'
>>> ps()
Name             PID    Offset  
init             1      0xffff88007b818000
kthreadd         2      0xffff88007b8196f0
ksoftirqd/0      3      0xffff88007b81ade0
kworker/0:0      4      0xffff88007b81c4d0
kworker/u:0      5      0xffff88007b81dbc0
[snip]
```

You can print linux data structures and overlay them on a particular offset in an address space:

```
>>> dt("task_struct")
'task_struct' (5872 bytes)
0x0   : state                          ['long']
0x8   : stack                          ['pointer', ['void']]
0x10  : usage                          ['__unnamed_910']
0x14  : flags                          ['unsigned int']
0x18  : ptrace                         ['unsigned int']
0x20  : wake_entry                     ['llist_node']
0x28  : on_cpu                         ['int']
[snip]

>>> dt("task_struct", 0xffff88007b818000)
[task_struct task_struct] @ 0xFFFF88007B818000
0x0   : state                          1
0x8   : stack                          18446612134386278400
0x10  : usage                          18446612134386302992
0x14  : flags                          4202752
0x18  : ptrace                         0
0x20  : wake_entry                     18446612134386303008
0x28  : on_cpu                         0
[snip]
```

You can change into a specific process's context and then access the task\_struct object as self.proc:

```
>>> cc(pid = 11370)
Current context: process firefox, pid=11370 DTB=0x308a8000
>>> self.proc.comm
[String comm] @ 0xFFFF88005B8BE020
>>> str(self.proc.comm)
'firefox'
```

After doing so, any of the db/dd/dq commands will output data from the process's address space.

## linux\_yarascan ##

This plugin allows you to scan for Yara rules anywhere in process or kernel memory. The rules can be supplied on command-line (-Y) or in a file on disk (-y). In the example below, we limit our scan to one process (firefox pid 11370) and look for URLs:

```
$ python vol.py --profile=LinuxUbuntux64 -f ~/ubuntu.lime linux_yarascan -Y "http://" -p 11370
Volatile Systems Volatility Framework 2.3_alpha
Task: firefox pid 11370 rule r1 addr 0x7ff9fdde4945
0x7ff9fdde4945  68 74 74 70 3a 2f 2f 6c 69 6d 65 2d 66 6f 72 65   http://lime-fore
0x7ff9fdde4955  6e 73 69 63 73 2e 67 6f 6f 67 6c 65 63 6f 64 65   nsics.googlecode
0x7ff9fdde4965  2e 63 6f 6d 2f 66 69 6c 65 73 2f 6c 69 6d 65 2d   .com/files/lime-
0x7ff9fdde4975  66 6f 72 65 6e 73 69 63 73 2d 31 2e 31 2d 72 31   forensics-1.1-r1
Task: firefox pid 11370 rule r1 addr 0x7ff9fde3b388
0x7ff9fde3b388  68 74 74 70 3a 2f 2f 63 6f 64 65 2e 67 6f 6f 67   http://code.goog
0x7ff9fde3b398  6c 65 2e 63 6f 6d 2f 70 2f 76 6f 6c 61 74 69 6c   le.com/p/volatil
0x7ff9fde3b3a8  69 74 79 2f 73 6f 75 72 63 65 2f 6c 69 73 74 00   ity/source/list.
0x7ff9fde3b3b8  f8 e8 00 00 bc 07 00 00 30 c7 7b 25 fa 7f 00 00   ........0.{%....
Task: firefox pid 11370 rule r1 addr 0x7ff9fde48468
0x7ff9fde48468  68 74 74 70 3a 2f 2f 77 77 77 2e 67 73 74 61 74   http://www.gstat
0x7ff9fde48478  69 63 2e 63 6f 6d 2f 63 6f 64 65 73 69 74 65 2f   ic.com/codesite/
0x7ff9fde48488  70 68 22 2c 22 64 6f 6d 61 69 6e 4e 61 6d 65 22   ph","domainName"
0x7ff9fde48498  3a 6e 75 6c 6c 2c 22 61 73 73 65 74 56 65 72 73   :null,"assetVers
[snip]
```

To scan all processes, just leave off the -p parameter (or to scan multiple processes use -p 1,2,3 syntax). You can also scan kernel memory using the --kernel option.