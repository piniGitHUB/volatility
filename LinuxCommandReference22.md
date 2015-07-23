

# Processes #

## linux\_pslist ##

This plugin prints the list of active processes starting from the `init_task` symbol and walking the `task_struct->tasks` linked list. It does not display the swapper process.

```
$ python vol.py -f ~/Desktop/Linux/ubuntu.lime --profile=LinuxUbuntu1204x64 linux_pslist
Volatile Systems Volatility Framework 2.2_rc2
Offset             Name                 Pid             Uid             Start Time
------------------ -------------------- --------------- --------------- ----------
0x000088007b818000 init                 1               0               Fri, 17 Aug 2012 19:55:38 +0000
0x000088007b8196f0 kthreadd             2               0               Fri, 17 Aug 2012 19:55:38 +0000
0x000088007b81ade0 ksoftirqd/0          3               0               Fri, 17 Aug 2012 19:55:38 +0000
0x000088007b81c4d0 kworker/0:0          4               0               Fri, 17 Aug 2012 19:55:38 +0000
0x000088007b81dbc0 kworker/u:0          5               0               Fri, 17 Aug 2012 19:55:38 +0000
0x000088007b840000 migration/0          6               0               Fri, 17 Aug 2012 19:55:38 +0000
0x000088007b8416f0 watchdog/0           7               0               Fri, 17 Aug 2012 19:55:38 +0000
0x000088007b842de0 migration/1          8               0               Fri, 17 Aug 2012 19:55:38 +0000
0x000088007b8444d0 kworker/1:0          9               0               Fri, 17 Aug 2012 19:55:38 +0000
0x000088007b845bc0 ksoftirqd/1          10              0               Fri, 17 Aug 2012 19:55:38 +0000
0x000088007b85ade0 watchdog/1           12              0               Fri, 17 Aug 2012 19:55:38 +0000
0x000088007b85c4d0 cpuset               13              0               Fri, 17 Aug 2012 19:55:38 +0000
[snip]
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
Offset             Name                 Pid             Uid             Start Time
------------------ -------------------- --------------- --------------- ----------
0x000088003d52c080 fcoemon              1436            0               Tue, 28 Aug 2012 11:06:24 +0000
0x000088003d52cae0 bash                 3066            0               Tue, 28 Aug 2012 11:31:47 +0000
0x000088003d52d540 console-kit-dae      1927            0               Tue, 28 Aug 2012 11:06:30 +0000
0x000088003857c080 su                   3063            0               Tue, 28 Aug 2012 11:31:47 +0000
0x000088003857cae0 gnome-screensav      2209            500             Tue, 28 Aug 2012 11:06:49 +0000
0x000088003857d540 notification-ar      2223            500             Tue, 28 Aug 2012 11:06:49 +0000
0x000088003d6cc080 sudo                 3062            0               Tue, 28 Aug 2012 11:31:47 +0000
0x000088003d6ccae0 hald-runner          1619            0               Tue, 28 Aug 2012 11:06:26 +0000
0x000088003d6cd540 Xorg                 1897            0               Tue, 28 Aug 2012 11:06:30 +0000
[snip]
```

## linux\_psxview ##

This plugin is similar in concept to the [Windows psxview command](CommandReference22#psxview.md) in that it gives you a cross-reference of processes based on multiple sources (the `task_struct->tasks` linked list, the pid hash table, and the kmem\_cache).

```
$ python vol.py -f ~/Desktop/Linux/centos.lime --profile=LinuxCentOS63x64 linux_psxview
Volatile Systems Volatility Framework 2.2_rc2
Offset(V)          Name                    PID pslist pid_hash kmem_cache
------------------ -------------------- ------ ------ -------- ----------
0x000088003ef85500 init                      1 True   True     True      
0x000088003ef84aa0 kthreadd                  2 True   True     True      
0x000088003ef84040 migration/0               3 True   True     True      
0x000088003ef91540 ksoftirqd/0               4 True   True     True      
0x000088003ef90ae0 migration/0               5 True   True     True      
0x000088003ef90080 watchdog/0                6 True   True     True      
0x000088003efbb500 events/0                  7 True   True     True      
0x000088003efbaaa0 cgroup                    8 True   True     True      
0x000088003efba040 khelper                   9 True   True     True      
0x000088003effb540 netns                    10 True   True     True
[snip]
```

## linux\_lsof ##

This plugin mimics the `lsof` command on a live system. It prints the list of open file descriptors and their paths for each running process.

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

## linux\_pidhashtable ##

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

The argument to the -H/--history\_list parameter can be gathered by using gdb on a live system. As shown below, the value you supply is 0x6ed4a0 (this was not calculated by us, its in a comment of the gdb output). For some systems, such as OpenSuSE, the history\_list symbol is in a shared library (readline.so) instead of /bin/bash and ASLR is enabled. In those cases, its not a static value, and the linux\_bash plugin will not work. Please wait until Volatility 2.3 is released which will dynamically determine the history\_list address using disassembly.

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

Here's an example of the output. The command time is seconds since epoch.

```
$ python vol.py -f avgcoder.mem --profile=LinuxCentOS63x64 linux_bash -H 0x6e0950 -P
Volatile Systems Volatility Framework 2.2_rc1
Command Time         Command
-------------------- -------
#1376083693          dmesg | head -50
#1376085088          df
#1376085110          dmesg | tail -50
#1376085118          sudo mount /dev/sda1 /mnt
#1376085122          cd /mnt
#1376085122          ls
#1376085128          sudo insmod rootkit.ko
#1376085176          echo "hide" > /proc/buddyinfo
#1376085180          lsmod | grep root
#1376085194          w
#1376085218          echo "huser centoslive" > /proc/buddyinfo
#1376085220          w
#1376085229          sleep 900 &
#1376085241          echo "hpid 2872" > /proc/buddyinfo
#1376085253          ps auwx | grep sleep
#1376085241          echo "hpid 2872" > /proc/buddyinfo
#1376085128          sudo insmod rootkit.ko
```

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


## linux\_tmpfs ##

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

## linux\_check\_creds ##

## linux\_check\_fop ##

## linux\_check\_idt ##

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

## linux\_ifconfig ##

## linux\_route\_cache ##

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

## linux\_sk\_buff\_cache ##

# System Information #

## linux\_cpuinfo ##

## linux\_dmesg ##

## linux\_iomem ##

## linux\_mount ##

## linux\_mount\_cache ##

## linux\_slabinfo ##

## linux\_dentry\_cache ##

## linux\_find\_file ##

## linux\_vma\_cache ##