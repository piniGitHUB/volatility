

# Processes #
## mac\_pslist ##

This plugin walks the linked list of processes and displays their short name, pid, uid, gid, bits (32, 64, or 64 shared), the DTB address, and creation time. You can tweak the timestamp time zone by using --tz=TIMEZONE (see [Setting the Timezone](VolatilityUsage23#Setting_the_Timezone.md).

Note: in testing, we determined that oftentimes the list is corrupt, leading to semi-garbage output. This is likely due to smearing while acquiring the memory sample. In these cases, use the [mac\_tasks](MacCommandReference23#mac_tasks.md) plugin instead - it has been found to be a more reliable source of process listings.

```
$ python vol.py --profile=MacMountainLion_10_8_3_AMDx64 -f ~/10.8.3.mmr.macho mac_pslist
Volatile Systems Volatility Framework 2.3_alpha
Offset             Name                 Pid      Uid      Gid      PGID     Bits         DTB                Start Time
------------------ -------------------- -------- -------- -------- -------- ------------ ------------------ ----------
0xffffff8032be4ea0 image                4175     0        0        4167     64BIT        0x0000000317e7e000 2013-03-29 12:16:20 UTC+0000
0xffffff803dfdea40 coresymbolicatio     4173     0        0        4173     64BIT        0x00000004114c0000 2013-03-29 12:16:18 UTC+0000
0xffffff8032498d20 MacMemoryReader      4168     0        0        4167     64BIT        0x00000003f94a8000 2013-03-29 12:16:17 UTC+0000
0xffffff803dfe0020 sudo                 4167     0        20       4167     64BIT        0x0000000414a34000 2013-03-29 12:16:15 UTC+0000
0xffffff803dfe1a60 mdworker             4164     89       89       4164     64BIT        0x00000003f70cf000 2013-03-29 12:15:32 UTC+0000
0xffffff80370af760 DashboardClient      4160     501      20       275      64BIT        0x00000003e5bd9000 2013-03-29 12:14:36 UTC+0000
0xffffff803634ba60 CVMCompiler          4127     501      20       4127     64BIT        0x000000016692b000 2013-03-29 12:10:58 UTC+0000
0xffffff80370b11a0 cookied              4126     501      20       4126     64BIT        0x00000003137cc000 2013-03-29 12:10:58 UTC+0000
0xffffff803dfe1600 WebProcess           4124     501      20       4121     64BIT        0x00000003f235a000 2013-03-29 12:10:57 UTC+0000
0xffffff803249c600 taskgated            4122     0        0        4122     64BIT        0x00000003f3038000 2013-03-29 12:10:57 UTC+0000
0xffffff80314a9d40 Safari               4121     501      20       4121     64BIT        0x00000003f616c000 2013-03-29 12:10:57 UTC+0000
[snip]
```

## mac\_tasks ##

This plugin enumerates processes by first enumerating tasks and then following the task.bsd\_info pointer to find the process object.

```
$ python vol.py --profile=MacMountainLion_10_8_3_AMDx64 -f ~/10.8.3.mmr.macho mac_tasks
Volatile Systems Volatility Framework 2.3_alpha
Offset             Name                 Pid      Uid      Gid      PGID     Bits         DTB                Start Time
------------------ -------------------- -------- -------- -------- -------- ------------ ------------------ ----------
0xffffff800fada2d0 kernel_task          0        0        0        0        64BIT        0x0000000011e9f000 2013-03-29 01:08:47 UTC+0000
0xffffff80314aaa60 launchd              1        0        0        1        64BIT        0x0000000011234000 2013-03-29 01:08:47 UTC+0000
0xffffff80314a98e0 UserEventAgent       11       0        0        11       64BIT        0x000000000be18000 2013-03-29 01:08:49 UTC+0000
0xffffff80314aa1a0 kextd                12       0        0        12       64BIT        0x000000000becb000 2013-03-29 01:08:49 UTC+0000
0xffffff80314a9480 notifyd              14       0        0        14       64BIT        0x0000000023b9b000 2013-03-29 01:08:49 UTC+0000
0xffffff80314a9020 securityd            15       0        0        15       64BIT        0x000000001dd43000 2013-03-29 01:08:49 UTC+0000
[snip]
```

## mac\_pstree ##

This plugin shows the parent/child relationship between processes.

```
$ python vol.py --profile=MacMountainLion_10_8_3_AMDx64 -f ~/10.8.3.mmr.macho mac_pstree
Volatile Systems Volatility Framework 2.3_alpha
Name                 Pid             Uid            
kernel_task          0               0              
.launchd             1               0              
..coresymbolicatio   4173            0              
..taskgated          4122            0              
..ocspd              973             0              
..launchd            561             89             
...mdworker          4164            89             
...cfprefsd          566             89             
...distnoted         565             89             
..VDCAssistant       558             0              
..Dropbox            518             501            
...dbfseventsd       545             0              
....dbfseventsd      546             0              
.....dbfseventsd     552             501            
.....dbfseventsd     549             501            
..vmware-usbarbitr   461             0     
[snip]
```

## mac\_lsof ##

This plugin lists the open file handles. As you can see from the output, a user was viewing volatility source code files at the time of the memory dump.

```
$ python vol.py --profile=MacMountainLion_10_8_3_AMDx64 -f ~/10.8.3.mmr.macho mac_lsof
Volatile Systems Volatility Framework 2.3_alpha
0 -> /Macintosh HD/dev/null
1 -> /Macintosh HD/dev/null
2 -> /Macintosh HD/dev/null
4 -> /Macintosh HD/dev/console
81 -> /Macintosh HD/dev/autofs_nowait
0 -> /Macintosh HD/dev/null
1 -> /Macintosh HD/dev/null
2 -> /Macintosh HD/dev/null
[snip]
19 -> /Macintosh HD/Users/michaelligh/Desktop/volatility/volatility/plugins/mac/pstasks.py
20 -> /Macintosh HD/Users/michaelligh/Desktop/volatility/volatility/plugins/mac/pstree.py
21 -> /Macintosh HD/Users/michaelligh/Desktop/volatility/volatility/plugins/mac/pgrp_hash_table.py
22 -> /Macintosh HD/Users/michaelligh/Desktop/volatility/volatility/plugins/mac/pslist.py
23 -> /Macintosh HD/Users/michaelligh/Desktop/volatility/volatility/plugins/mac/psaux.py
24 -> /Macintosh HD/Users/michaelligh/Desktop/2.3.todo.txt
25 -> /Macintosh HD/Users/michaelligh/Desktop/mac_profile.sh
[snip]
```

## mac\_pgrp\_hash\_table ##

This plugin enumerates processes by walking the process group hash table.

```
$ python vol.py --profile=MacMountainLion_10_8_3_AMDx64 -f ~/10.8.3.mmr.macho mac_pgrp_hash_table
Volatile Systems Volatility Framework 2.3_alpha
Offset             Name                 Pid      Uid      Gid      PGID     Bits         DTB                Start Time
------------------ -------------------- -------- -------- -------- -------- ------------ ------------------ ----------
0xffffff800fada2d0 kernel_task          0        0        0        0        64BIT        0x0000000011e9f000 2013-03-29 01:08:47 UTC+0000
0xffffff8032c64600 apsd                 257      0        0        257      64BIT        0x000000005d70e000 2013-03-29 01:09:15 UTC+0000
0xffffff80314aaa60 launchd              1        0        0        1        64BIT        0x0000000011234000 2013-03-29 01:08:47 UTC+0000
0xffffff8032be6480 tccd                 258      501      20       258      64BIT        0x000000004bb09000 2013-03-29 01:09:15 UTC+0000
0xffffff803249b480 Terminal             259      501      20       259      64BIT        0x000000004b66d000 2013-03-29 01:09:15 UTC+0000
0xffffff803dfdf300 Dropbox              518      501      20       516      32BIT        0x0000000175f97000 2013-03-29 01:10:15 UTC+0000
0xffffff803dfe11a0 dbfseventsd          545      0        20       516      32BIT        0x000000014f98f000 2013-03-29 01:10:18 UTC+0000
[snip]
```

## mac\_pid\_hash\_table ##

This plugin enumerates processes by walking the pid hash table.

```
$ python vol.py --profile=MacMountainLion_10_8_3_AMDx64 -f ~/10.8.3.mmr.macho mac_pid_hash_table
Volatile Systems Volatility Framework 2.3_alpha
Offset             Name                 Pid      Uid      Gid      PGID     Bits         DTB                Start Time
------------------ -------------------- -------- -------- -------- -------- ------------ ------------------ ----------
0xffffff80314aa600 Google Chrome He     1025     501      20       261      32BIT        0x000000004c7a4000 2013-03-29 01:56:58 UTC+0000
0xffffff8032c64600 apsd                 257      0        0        257      64BIT        0x000000005d70e000 2013-03-29 01:09:15 UTC+0000
0xffffff80314aaa60 launchd              1        0        0        1        64BIT        0x0000000011234000 2013-03-29 01:08:47 UTC+0000
0xffffff8032be6480 tccd                 258      501      20       258      64BIT        0x000000004bb09000 2013-03-29 01:09:15 UTC+0000
0xffffff803dfdd460 Google Chrome He     1027     501      20       261      32BIT        0x000000014fd18000 2013-03-29 01:57:12 UTC+0000
0xffffff803249b480 Terminal             259      501      20       259      64BIT        0x000000004b66d000 2013-03-29 01:09:15 UTC+0000
0xffffff8032498000 Google Chrome        261      501      20       261      32BIT        0x000000006f56e000 2013-03-29 01:09:15 UTC+0000
[snip]
```

## mac\_psaux ##

This plugin accesses process memory to pull command-line arguments passed to the process at startup.

```
$ python vol.py --profile=MacMountainLion_10_8_3_AMDx64 -f ~/10.8.3.mmr.macho mac_psaux
Volatile Systems Volatility Framework 2.3_alpha
Pid      Name                 Bits             Stack              Length   Argc     Arguments
-------- -------------------- ---------------- ------------------ -------- -------- ---------
       0 kernel_task          64BIT            0x0000000000000000        0        0 
[snip]
      40 mDNSResponder        64BIT            0x00007fff54403000      384        2 /usr/sbin/mDNSResponder -launchd
      41 networkd             64BIT            0x00007fff50d3f000      360        1 /usr/libexec/networkd
      59 warmd                64BIT            0x00007fff51816000      232        1 /usr/libexec/warmd
      60 usbmuxd              64BIT            0x00007fff5fc00000      504        2 /System/Library/PrivateFrameworks/MobileDevice.framework/Versions/A/Resources/usbmuxd -launchd
      63 stackshot            64BIT            0x00007fff59a7a000      224        2 /usr/libexec/stackshot -t
      64 SleepServicesD       64BIT            0x00007fff582d5000      280        1 /System/Library/CoreServices/SleepServicesD
      66 revisiond            64BIT            0x00007fff50d1b000      376        1 /System/Library/PrivateFrameworks/GenerationalStorage.framework/Versions/A/Support/revisiond
      71 netbiosd             64BIT            0x00007fff577d3000      360        1 /usr/sbin/netbiosd
      72 mds                  64BIT            0x00007fff5713e000      376        1 /System/Library/Frameworks/CoreServices.framework/Frameworks/Metadata.framework/Support/mds
      75 loginwindow          64BIT            0x00007fff59635000      328        2 /System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow console
      77 KernelEventAgent     64BIT            0x00007fff5e5b7000      232        1 /usr/sbin/KernelEventAgent
      78 kdc                  64BIT            0x00007fff54a32000      304        1 /System/Library/PrivateFrameworks/Heimdal.framework/Helpers/kdc
      80 hidd                 64BIT            0x00007fff56819000      232        1 /usr/libexec/hidd
      82 dynamic_pager        64BIT            0x00007fff5dfdd000      248        3 /sbin/dynamic_pager -F /private/var/vm/swapfile
      84 dpd                  64BIT            0x00007fff5f995000      232        1 /usr/libexec/dpd
      85 corestoraged         64BIT            0x00007fff5dfed000      232        1 /usr/libexec/corestoraged
      86 appleeventsd         64BIT            0x00007fff5cc55000      408        2 /System/Library/CoreServices/appleeventsd --server
      89 blued                64BIT            0x00007fff5a65d000      224        1 /usr/sbin/blued
      91 autofsd              64BIT            0x00007fff577d9000      208        1 /usr/libexec/autofsd autofsd
      95 ntpd                 64BIT            0x00007fff5a494000      296        9 /usr/sbin/ntpd -c /private/etc/ntp-restrict.conf -n -g -p /var/run/ntpd.pid -f /var/db/ntp.drift
[snip]
```

## mac\_dead\_procs ##

This plugin prints terminated/dead processes. In most cases, the UID, GID, PGID, Bits, and DTB columns will show invalid data since we could be looking at partially overwritten data structures. Also please note in some rare cases, active processes are also found in this list. We are currently investigating conditions that lead to active processes showing up in the freed process object list.

```
$ python vol.py --profile=MacMountainLion_10_8_3_AMDx64 -f ~/10.8.3.mmr.macho mac_dead_procs
Volatile Systems Volatility Framework 2.3_alpha
Offset             Name                 Pid      Uid      Gid      PGID     Bits         DTB                Start Time
------------------ -------------------- -------- -------- -------- -------- ------------ ------------------ ----------
0xffffff8036349760 diskmanagementd      4158     -        -        -55...11              ------------------ 2013-03-29 12:14:31 UTC+0000
0xffffff8036349760 diskmanagementd      4158     -        -        -55...11              ------------------ 2013-03-29 12:14:31 UTC+0000
0xffffff8032c60d20 lssave               4161     -        -        -55...11              ------------------ 2013-03-29 12:14:43 UTC+0000
0xffffff803dfe08e0 com.apple.audio.     4146     -        -        -55...11              ------------------ 2013-03-29 12:12:59 UTC+0000
0xffffff803dfe0d40 com.apple.audio.     4145     -        -        -55...11              ------------------ 2013-03-29 12:12:59 UTC+0000
0xffffff8032c62300 com.apple.qtkits     4147     -        -        -55...11              ------------------ 2013-03-29 12:12:59 UTC+0000
[snip]
```

## mac\_psxview ##

This plugin enumerates processes in 6 different ways and cross-references the processes that appear in each list. Its a very effective way to identify processes hidden in only one or two ways.

For more information, see [MOVP II - 4.1 - Leveraging Process Cross-View Analysis for Mac Rootkit Detection](http://volatility-labs.blogspot.com/2013/06/movp-ii-41-leveraging-process-cross.html).

```
$ python vol.py --profile=MacMountainLion_10_8_3_AMDx64 -f ~/10.8.3.mmr.macho mac_psxview
Volatile Systems Volatility Framework 2.3_alpha
Offset(P)          Name                    PID pslist parents pid_hash pgrp_hash_table session leaders task processes
------------------ -------------------- ------ ------ ------- -------- --------------- --------------- --------------
0xffffff800fada2d0 kernel_task               0 True   True    False    True            True            True          
0xffffff80314aaa60 launchd                   1 True   True    True     True            True            True          
0xffffff80314a98e0 UserEventAgent           11 True   False   True     True            True            True          
0xffffff80314aa1a0 kextd                    12 True   False   True     True            True            True          
0xffffff80314a9480 notifyd                  14 True   False   True     True            True            True          
0xffffff80314a9020 securityd                15 True   False   True     True            True            True          
0xffffff80314a8bc0 diskarbitrationd         16 True   False   True     True            True            True          
0xffffff80314a8760 configd                  17 True   False   True     True            True            True          
0xffffff80314a8300 powerd                   18 True   False   True     True            True            True          
0xffffff80314a7ea0 syslogd                  19 True   False   True     True            True            True          
0xffffff80314a7a40 distnoted                20 True   False   True     True            True            True          
0xffffff80314a75e0 cfprefsd                 21 True   False   True     True            True            True        
[snip]
```

# Process Memory #

For more information on the complexities of Mac process memory, see [MoVP II - 4.2 - Dumping, Scanning, and Searching Mac OSX Process Memory](http://volatility-labs.blogspot.com/2013/06/movp-ii-42-dumping-scanning-and.html).

## mac\_proc\_maps ##

This plugin shows the allocated memory blocks in each process, along with their starting and ending addresses, permissions, and name of them mapped file if it applies. You can filter processes with the -p option.

```
$ python vol.py --profile=MacMountainLion_10_8_3_AMDx64 -f ~/10.8.3.mmr.macho mac_proc_maps -p 1 
Volatile Systems Volatility Framework 2.3_alpha
Pid      Name                 Start              End                Perms     Map Name
-------- -------------------- ------------------ ------------------ --------- --------
1        launchd              0x000000010630c000 0x0000000106333000 r-x       Macintosh HD/sbin/launchd
1        launchd              0x0000000106333000 0x0000000106335000 rw-       Macintosh HD/sbin/launchd
1        launchd              0x0000000106335000 0x000000010633b000 r--       Macintosh HD/sbin/launchd
1        launchd              0x000000010633b000 0x000000010633c000 r--       
1        launchd              0x000000010633c000 0x000000010633f000 r-x       Macintosh HD/usr/lib/libauditd.0.dylib
1        launchd              0x000000010633f000 0x0000000106340000 rw-       Macintosh HD/usr/lib/libauditd.0.dylib
1        launchd              0x0000000106340000 0x0000000106343000 r--       Macintosh HD/usr/lib/libauditd.0.dylib
1        launchd              0x0000000106343000 0x0000000106344000 r--       
1        launchd              0x0000000106344000 0x0000000106345000 rw-       Macintosh HD/private/var/db/dyld/dyld_shared_cache_x86_64
[snip]
```

## mac\_dump\_maps ##

This plugin dumps/extracts a memory block seen in the mac\_proc\_maps output. For example, if you wanted to recover the launchd binary which is reportedly located at 0x000000010630c000 in the launchd process memory, you can do the following:

```
$ python vol.py --profile=MacMountainLion_10_8_3_AMDx64 -f ~/10.8.3.mmr.macho mac_dump_maps -p 1 -s 0x000000010630c000 -O launchd.binary.dmp
Volatile Systems Volatility Framework 2.3_alpha
Wrote 159744 bytes

$ file launchd.binary.dmp 
launchd.binary.dmp: Mach-O 64-bit executable x86_64
```

# Kernel Memory and Objects #
## mac\_list\_sessions ##

This plugin enumerates sessions from the session hash table. You can use this information to link processes to user names.

```
$ python vol.py --profile=MacMountainLion_10_8_3_AMDx64 -f ~/10.8.3.mmr.macho mac_list_sessions
Volatile Systems Volatility Framework 2.3_alpha
Leader (Pid) Leader (Name)        Login Name               
------------ -------------------- -------------------------
           0 kernel_task                                   
         257 apsd                 _softwareupdate          
           1 launchd              _securityagent           
          -1 <INVALID LEADER>     michaelligh              
          11 UserEventAgent       root                     
          12 kextd                root                     
          14 notifyd              root                     
          15 securityd            root                     
          16 diskarbitrationd     root     
[snip]
```

## mac\_list\_zones ##

This plugin enumerates zones (in this context a zone is similar to a structure). You can use it to determine how many of a particular type of structure (i.e. a process object) are active and freed. For example, below you can see that 133 proc structures are active on the system. Other plugins can inherit from mac\_list\_zones and actually collect the addresses of each active object type, leading to a wealthy source of information regarding where to find allocated objects in memory dumps.

```
$ python vol.py --profile=MacMountainLion_10_8_3_AMDx64 -f ~/10.8.3.mmr.macho mac_list_zones
Volatile Systems Volatility Framework 2.3_alpha
Name                           Active Count Free Count Element Size
------------------------------ ------------ ---------- ------------
zones                                   182          0          592
vm.objects                           153401    8832498          224
vm.object.hash.entries               135206     882875           40
maps                                    149      34033          232
VM.map.entries                        26463   24372727           80
Reserved.VM.map.entries                  35      13164           80
VM.map.copies                             0     220097           80
pmap                                    139       7962          256
pagetable.anchors                       139       7962         4096
proc                                    133       4042         1120
[snip]
```

## mac\_lsmod ##

This plugin lists the loaded kernel extensions, their base addresses and size, reference count, and version number.

```
$ python vol.py --profile=MacMountainLion_10_8_3_AMDx64 -f ~/10.8.3.mmr.macho mac_lsmod
Volatile Systems Volatility Framework 2.3_alpha
Address                          Size   Refs   Version      Name
------------------ ------------------ -------- ------------ ----
0xffffff7f91847000             0x3000    0     3.0.2        com.atc-nycorp.devmem.kext
0xffffff7f91841000             0x6000    0     10.1.24      com.vmware.kext.vmioplug.10.1.24
0xffffff7f91834000             0xd000    0     0104.03.86   com.vmware.kext.vmx86
0xffffff7f9182a000             0xa000    0     0104.03.86   com.vmware.kext.vmnet
0xffffff7f9181a000            0x10000    0     90.4.23      com.vmware.kext.vsockets
0xffffff7f91808000            0x12000    1     90.4.18      com.vmware.kext.vmci
0xffffff7f916d2000             0xe000    0     75.19        com.apple.driver.AppleBluetoothMultitouch
[snip]
```

## mac\_mount ##

This plugin shows the mounted file systems.

```
$ python vol.py --profile=MacMountainLion_10_8_3_AMDx64 -f ~/10.8.3.mmr.macho mac_mount
Volatile Systems Volatility Framework 2.3_alpha
Device                         Mount Point                                                  Type
------------------------------ ------------------------------------------------------------ ----
/                              /dev/disk3                                                   hfs
/dev                           devfs                                                        devfs
/net                           map -hosts                                                   autofs
/home                          map auto_home                                                autofs
/Volumes/LaCie                 /dev/disk2s2                                                 hfs
```

# Networking #
## mac\_arp ##

This plugin prints the ARP table, including sent/recv statistics, time the entry was created, and its expiration.

```
$ python vol.py --profile=MacMountainLion_10_8_3_AMDx64 -f ~/10.8.3.mmr.macho mac_arp
Volatile Systems Volatility Framework 2.3_alpha
Source IP                Dest. IP                    Name           Sent               Recv                     Time                 Exp.    Delta
------------------------ ------------------------ ---------- ------------------ ------------------ ------------------------------ ---------- -----
192.168.228.255          ff:ff:ff:ff:ff:ff          vmnet8           10                 0           2013-03-29 12:13:59 UTC+0000    39913    0
172.16.244.255           ff:ff:ff:ff:ff:ff          vmnet1           10                 0           2013-03-29 12:13:59 UTC+0000    39913    0
10.0.1.255               ff:ff:ff:ff:ff:ff           en1             12                 0           2013-03-29 12:13:59 UTC+0000    39913    0
10.0.1.8                 e8:8d:28:cb:67:07           en1             19                924          2013-03-29 11:56:30 UTC+0000    40065    1201
10.0.1.2                 ac:16:2d:32:fc:d7           en1             1                  47          2013-03-29 11:56:02 UTC+0000    40037    1201
10.0.1.1                 00:26:bb:6c:8e:64           en1            4551               4517         2013-03-29 01:08:53 UTC+0000    40318    40310
```

## mac\_ifconfig ##

This plugin prints the IPv4, IPv6, and Ethernet addresses for interfaces (both physical and virtual) on the system.

```
$ python vol.py --profile=MacMountainLion_10_8_3_AMDx64 -f ~/10.8.3.mmr.macho mac_ifconfig
Volatile Systems Volatility Framework 2.3_alpha
Interface  Address
---------- -------
lo0        fe80:1::1
lo0        127.0.0.1
lo0        ::1
gif0       
stf0       
en1        8c:2d:aa:41:1e:3b
en1        fe80:4::8e2d:aaff:fe41:1e3b
en1        10.0.1.3
en0        10:dd:b1:9f:d5:ce
p2p0       0e:2d:aa:41:1e:3b
fw0        00:0a:27:02:00:4b:19:5c
vmnet1     00:50:56:c0:00:01
vmnet1     172.16.244.1
vmnet8     00:50:56:c0:00:08
vmnet8     192.168.228.1
```

## mac\_netstat ##

This plugin shows active UNIX sockets and TCP/UDP endpoints (along with the TCP state and local/remote IPs and ports).

```
$ python vol.py --profile=MacMountainLion_10_8_3_AMDx64 -f ~/10.8.3.mmr.macho mac_netstat
Volatile Systems Volatility Framework 2.3_alpha
UNIX -
UNIX /var/tmp/launchd/sock
UNIX -
UNIX /var/tmp/com.barebones.authd.socket
UNIX /var/run/com.apple.ActivityMonitor.socket
TCP :::548 :::0 TIME_WAIT
TCP 0.0.0.0:548 0.0.0.0:0 TIME_WAIT
UDP 127.0.0.1:60762 0.0.0.0:0 
UNIX /var/run/mDNSResponder
UNIX /var/rpc/ncacn_np/lsarpc
UNIX /var/rpc/ncalrpc/lsarpc
TCP 10.0.1.3:49179 173.194.76.125:5222 TIME_WAIT
TCP 10.0.1.3:49188 205.188.248.150:443 TIME_WAIT
TCP 10.0.1.3:49189 205.188.254.208:443 TIME_WAIT
TCP 10.0.1.3:50614 205.188.13.76:443 TIME_WAIT
UDP 0.0.0.0:137 0.0.0.0:0 
UDP 0.0.0.0:138 0.0.0.0:0 
UNIX /var/run/vpncontrol.sock
UNIX /var/run/portmap.socket
TCP :::5900 :::0 TIME_WAIT
[snip]
```

## mac\_route ##

This plugin dumps the routing table. It shows the Source and Destination IPs, name of the interface, and for versions that support it - the sent/recv statistics and expiration/delta times. Only 10.7.x and 10.8.x OSX versions include the extra details.

```
$ python vol.py --profile=MacMountainLion_10_8_3_AMDx64 -f ~/10.8.3.mmr.macho mac_route
Volatile Systems Volatility Framework 2.3_alpha
Source IP                Dest. IP                    Name           Sent               Recv                     Time                 Exp.    Delta
------------------------ ------------------------ ---------- ------------------ ------------------ ------------------------------ ---------- -----
0.0.0.0                  10.0.1.1                    en1            4342              50431         2013-03-29 01:08:55 UTC+0000      0      0
10.0.1.0                                             en1            8331              31691         2013-03-29 01:08:56 UTC+0000      8      0
10.0.1.1                 00:26:bb:6c:8e:64           en1            4551               4517         2013-03-29 01:08:53 UTC+0000    40318    40310
10.0.1.2                 ac:16:2d:32:fc:d7           en1             1                  47          2013-03-29 11:56:02 UTC+0000    40037    1201
10.0.1.3                 127.0.0.1                   lo0             0                 6168         2013-03-29 01:08:55 UTC+0000      0      0
10.0.1.8                 e8:8d:28:cb:67:07           en1             19                924          2013-03-29 11:56:30 UTC+0000    40065    1201
10.0.1.255               ff:ff:ff:ff:ff:ff           en1             12                 0           2013-03-29 12:13:59 UTC+0000    39913    0
17.171.4.15              10.0.1.1                    en1             39                 39          2013-03-29 01:08:55 UTC+0000      0      0
17.172.232.105           10.0.1.1                    en1             2                  60          2013-03-29 01:09:16 UTC+0000      0      0
17.172.238.203           10.0.1.1                    en1             0                  58          2013-03-29 01:09:46 UTC+0000      0      0
[snip]
```

# Malware/Rootkits #
## mac\_check\_sysctl ##

This plugin checks for unknown sysctl handlers. You'll see the name of the sysctl, associated permissions, the handler address, and any available details (may be a string or a number, depending on the purpose of the sysctl. The "Status" column will contain "OK" if the sysctl is known/safe or "UNKNOWN" if its been hooked.

```
$ python vol.py --profile=MacMountainLion_10_8_3_AMDx64 -f ~/10.8.3.mmr.macho mac_check_sysctl
Volatile Systems Volatility Framework 2.3_alpha
Name                           Number   Perms  Handler            Status     Value
------------------------------ -------- ------ ------------------ ---------- -----
ostype                                1 R-L    0xffffff800f76cee0 OK         Darwin
osrelease                             2 R-L    0xffffff800f76cee0 OK         12.3.0
osrevision                            3 R-L    0xffffff800f76cdd0 OK         
version                               4 R-L    0xffffff800f76cee0 OK         Darwin Kernel Version 12.3.0: Sun Jan  6 22:37:10 PST 2013; root:xnu-2050.22.13~1/RELEASE_X86_64
maxvnodes                             5 RWL    0xffffff800f76ad60 OK         
maxproc                               6 RWL    0xffffff800f76adc0 OK         
maxfiles                              7 RWL    0xffffff800f76cdd0 OK         4638564691968
argmax                                8 R-L    0xffffff800f76cdd0 OK         
securelevel                           9 RWL    0xffffff800f76af80 OK         
hostname                             10 RWL    0xffffff800f76b040 OK         
[snip]
```

## mac\_check\_syscalls ##

This plugin prints the syscall table entries and resolves the function address to the appropriate kernel symbol. If any functions are hooked by rootkits, you'll see a "HOOKED" in the far right column. We define "HOOKED" as any entries whose address is not found in the dysmutil output (system.map equivalent for mac) which is built into your profile.

There are some exceptions, however, where a function can be hooked and you won't see the HOOKED indicator...for example when you hook with D-Trace as described in [Hunting D-Trace Rootkits with The Volatility Framework](http://siliconblade.blogspot.com/2013/04/hunting-d-trace-rootkits-with.html). The dtrace infrastructure is compiled inside the kernel (not a kernel module) so the dysmutil output knows the symbol name.

```
$ python vol.py --profile=MacMountainLion_10_8_3_AMDx64 -f ~/10.8.3.mmr.macho mac_check_syscalls
Volatile Systems Volatility Framework 2.3_alpha
Table Name      Index  Address            Symbol                        
--------------- ------ ------------------ ------------------------------
SyscallTable         0 0xffffff800f7755f0 _nosys                        
SyscallTable         1 0xffffff800f755430 _exit                         
SyscallTable         2 0xffffff800f759730 _fork                         
SyscallTable         3 0xffffff800f775630 _read                         
SyscallTable         4 0xffffff800f775d00 _write                        
SyscallTable         5 0xffffff800f4fb210 _open                         
SyscallTable         6 0xffffff800f749f30 _close                        
SyscallTable         7 0xffffff800f756660 _wait4                        
SyscallTable         8 0xffffff800f7755f0 _nosys                        
SyscallTable         9 0xffffff800f4fbc20 _link                         
SyscallTable        10 0xffffff800f4fc8c0 _unlink                       
SyscallTable        11 0xffffff800f7755f0 _nosys                        
SyscallTable        12 0xffffff800f4fa650 _chdir         
[snip]
```

## mac\_check\_trap\_table ##

This plugin checks the status of the mach trap table function pointers to determine if they've been hooked. The Symbol column displays "HOOKED" if any appear to be maliciously altered. The "kern\_invalid" entries are safe, they're just default/un-used handlers (similar to how un-used IRPs on Windows point to nt!IopInvalidDeviceRequest).

```
$ python vol.py --profile=MacMountainLion_10_8_3_AMDx64 -f ~/10.8.3.mmr.macho mac_check_trap_table
Volatile Systems Volatility Framework 2.3_alpha
Table Name      Index  Address            Symbol                                            
--------------- ------ ------------------ --------------------------------------------------
TrapTable            0 0xffffff800f434ec0 _kern_invalid                                     
TrapTable            1 0xffffff800f434ec0 _kern_invalid                                     
TrapTable            2 0xffffff800f434ec0 _kern_invalid                                     
TrapTable            3 0xffffff800f434ec0 _kern_invalid                                     
TrapTable            4 0xffffff800f434ec0 _kern_invalid                                     
TrapTable            5 0xffffff800f434ec0 _kern_invalid                                     
TrapTable            6 0xffffff800f434ec0 _kern_invalid                                     
TrapTable            7 0xffffff800f434ec0 _kern_invalid                                     
TrapTable            8 0xffffff800f434ec0 _kern_invalid                                     
TrapTable            9 0xffffff800f434ec0 _kern_invalid                                     
TrapTable           10 0xffffff800f418a20 __kernelrpc_mach_vm_allocate_trap                 
TrapTable           11 0xffffff800f434ec0 _kern_invalid                                     
TrapTable           12 0xffffff800f418ab0 __kernelrpc_mach_vm_deallocate_trap  
[snip]
```

## mac\_ip\_filters ##
## mac\_notifiers ##

This plugin detects rootkits that add hooks into I/O Kit (e.g. LogKext). If any entries are suspicious, you'll see "UNKNOWN" in the Status column.

```
$ python vol.py --profile=MacMountainLion_10_8_3_AMDx64 -f ~/10.8.3.mmr.macho mac_notifiers
Volatile Systems Volatility Framework 2.3_alpha
Status     Key                            Handler            Matches
---------- ------------------------------ ------------------ -------
OK         IOServicePublish               0xffffff7f8fa878e8 IODisplayConnect
OK         IOServicePublish               0xffffff7f91206ab6 IOResources,AppleClamshellState
OK         IOServicePublish               0xffffff7f8fa94188 IOResources,AppleClamshellState
OK         IOServicePublish               0xffffff800f872d50 IODisplayWrangler
OK         IOServicePublish               0xffffff7f902ff732 IOHIDevice
OK         IOServicePublish               0xffffff7f902ff732 IOHIDEventService
OK         IOServicePublish               0xffffff7f902ff732 IODisplayWrangler
OK         IOServicePublish               0xffffff7f902ffe74 AppleKeyswitch
[snip]
```

## mac\_trustedbsd ##
# System Information #
## mac\_dmesg ##

This plugin recovers the kernel debug buffer.

```
$ python vol.py --profile=MacMountainLion_10_8_3_AMDx64 -f ~/10.8.3.mmr.macho mac_dmesg
Volatile Systems Volatility Framework 2.3_alpha
deny mach-lookup com.apple.coresymbolicationd
MacAuthEvent en1   Auth result for: 00:26:bb:77:d2:a7  MAC AUTH succeeded
wlEvent: en1 en1 Link UP virtIf = 0
AirPort: RSN handshake complete on en1
wl0: Roamed or switched channel, reason #8, bssid 00:26:bb:77:d2:a7
en1: BSSID changed to 00:26:bb:77:d2:a7
en1::IO80211Interface::postMessage bssid changed
MacAuthEvent en1   Auth result for: 00:26:bb:77:d2:a7  MAC AUTH succeeded
wlEvent: en1 en1 Link UP virtIf = 0
AirPort: RSN handshake complete on en1
[snip]
```

## mac\_find\_aslr\_shift ##

This plugin only applies to Mountain Lion (10.8.x) versions using Address Space Layout Randomization. The symbol addresses that Volatility pulls from the mach\_kernel need to be adjusted using a special "shift" value that we first must find by scanning the physical memory dump. Any plugin for 10.8.x that utilizes symbols will do this scan in the background unless you supply the value as the --shift=SHIFT parameter.

```
$ python vol.py --profile=MacMountainLion_10_8_3_AMDx64 -f ~/10.8.3.mmr.macho mac_find_aslr_shift
Volatile Systems Volatility Framework 2.3_alpha
Shift Value       
------------------
0x000000000f200000
```

For example, if you run the mac\_pslist plugin (which uses symbols) and it will scan for the shift value automatically:

```
$ time python vol.py --profile=MacMountainLion_10_8_3_AMDx64 -f ~/10.8.3.mmr.macho mac_pslist
Volatile Systems Volatility Framework 2.3_alpha
Offset             Name                 Pid      Uid      Gid      PGID     Bits         DTB                Start Time
------------------ -------------------- -------- -------- -------- -------- ------------ ------------------ ----------
0xffffff8032be4ea0 image                4175     0        0        4167     64BIT        0x0000000317e7e000 2013-03-29 12:16:20 UTC+0000
0xffffff803dfdea40 coresymbolicatio     4173     0        0        4173     64BIT        0x00000004114c0000 2013-03-29 12:16:18 UTC+0000
0xffffff8032498d20 MacMemoryReader      4168     0        0        4167     64BIT        0x00000003f94a8000 2013-03-29 12:16:17 UTC+0000
[snip]
real	0m12.642s
user	0m11.117s
sys	0m0.743s
```

If you supply the shift value when running mac\_pslist, the plugin will complete about 1.5 seconds quicker. This isn't a significant speed enhancement, but if you were running several plugins sequentially, the total time saved can end up being significant.

```
$ time python vol.py --profile=MacMountainLion_10_8_3_AMDx64 -f ~/10.8.3.mmr.macho mac_pslist --shift=0x000000000f200000
Volatile Systems Volatility Framework 2.3_alpha
Offset             Name                 Pid      Uid      Gid      PGID     Bits         DTB                Start Time
------------------ -------------------- -------- -------- -------- -------- ------------ ------------------ ----------
0xffffff8032be4ea0 image                4175     0        0        4167     64BIT        0x0000000317e7e000 2013-03-29 12:16:20 UTC+0000
0xffffff803dfdea40 coresymbolicatio     4173     0        0        4173     64BIT        0x00000004114c0000 2013-03-29 12:16:18 UTC+0000
0xffffff8032498d20 MacMemoryReader      4168     0        0        4167     64BIT        0x00000003f94a8000 2013-03-29 12:16:17 UTC+0000
[snip]
real	0m10.998s
user	0m10.544s
sys	0m0.444s
```

## mac\_machine\_info ##

This plugin prints the machine's kernel major/minor versions, RAM size, and CPU details.

```
$ python vol.py --profile=MacMountainLion_10_8_3_AMDx64 -f ~/10.8.3.mmr.macho mac_machine_info
Volatile Systems Volatility Framework 2.3_alpha
Major Version:  12
Minor Version:  3
Memory Size:    17179869184
Max CPUs:       4
Physical CPUs:  4
Logical CPUs:   4
```

## mac\_version ##

This plugin shows the version string you'd see from "uname -a" on a live system.

```
$ python vol.py --profile=MacMountainLion_10_8_3_AMDx64 -f ~/10.8.3.mmr.macho mac_version
Volatile Systems Volatility Framework 2.3_alpha
Darwin Kernel Version 12.3.0: Sun Jan  6 22:37:10 PST 2013; root:xnu-2050.22.13~1/RELEASE_X86_64
```

## mac\_print\_boot\_cmdline ##

This plugin prints the boot arguments passed to the kernel upon system start

```
$ python vol.py --profile=MacSnowLeopard_10_6_AMDx64  -f /root/mac-images-profiles/s10.6.0x64.vmem mac_print_boot_cmdline
Volatile Systems Volatility Framework 2.3_alpha
Command Line
------------
srv=1
```


# Miscellaneous #
## mac\_volshell ##

This plugin presents an interactive shell in the mac memory image. You can list processes, switch contexts for printing process-specific addresses, display mac kernel structure types, etc.

To list processes:

```
$ python vol.py --profile=MacMountainLion_10_8_3_AMDx64 -f ~/Desktop/10.8.3/10.8.3.mmr.macho mac_volshell
Volatile Systems Volatility Framework 2.3_alpha
Current context: process kernel_task, pid=0 DTB=0x11e9f000
Welcome to volshell! Current memory image is:
file:///Users/michaelligh/Desktop/10.8.3.mmr.macho
To get help, type 'hh()'
>>> ps()
Name             PID    Offset  
kernel_task      0      0xffffff800fada2d0
launchd          1      0xffffff80314aaa60
UserEventAgent   11     0xffffff80314a98e0
kextd            12     0xffffff80314aa1a0
notifyd          14     0xffffff80314a9480
securityd        15     0xffffff80314a9020
[snip]
```

To display a data structure:

```
>>> dt("proc")
'proc' (1120 bytes)
0x0   : p_list                         ['__unnamed_14910873']
0x10  : p_pid                          ['int']
0x18  : task                           ['pointer', ['task']]
0x20  : p_pptr                         ['pointer', ['proc']]
0x28  : p_ppid                         ['int']
0x2c  : p_pgrpid                       ['int']
0x30  : p_uid                          ['unsigned int']
0x34  : p_gid                          ['unsigned int']
[snip]
```

To overlay a data structure to an offset in an address space:

```
>>> dt("proc", 0xffffff800fada2d0)
[proc proc] @ 0xFFFFFF800FADA2D0
0x0   : p_list                         18446743524216775376
0x10  : p_pid                          0
0x18  : task                           18446743524770536480
0x20  : p_pptr                         18446743524216775376
0x28  : p_ppid                         0
0x2c  : p_pgrpid                       0
0x30  : p_uid                          0
0x34  : p_gid                          0
[snip]
```

To switch into a specific process's context and read from a user mode address:

Note after you switch contexts with cc(), the current process's proc object can be found at self.proc.

```
>>> cc(pid = 261)
Current context: process Google Chrome, pid=261 DTB=0x6f56e000
>>> hex(self.proc.user_stack)
'0xbffe8000L'
>>> db(self.proc.user_stack - self.proc.p_argslen)
0xbffe7d44  2f 41 70 70 6c 69 63 61 74 69 6f 6e 73 2f 47 6f   /Applications/Go
0xbffe7d54  6f 67 6c 65 20 43 68 72 6f 6d 65 2e 61 70 70 2f   ogle.Chrome.app/
0xbffe7d64  43 6f 6e 74 65 6e 74 73 2f 4d 61 63 4f 53 2f 47   Contents/MacOS/G
0xbffe7d74  6f 6f 67 6c 65 20 43 68 72 6f 6d 65 00 00 00 00   oogle.Chrome....
0xbffe7d84  2f 41 70 70 6c 69 63 61 74 69 6f 6e 73 2f 47 6f   /Applications/Go
0xbffe7d94  6f 67 6c 65 20 43 68 72 6f 6d 65 2e 61 70 70 2f   ogle.Chrome.app/
0xbffe7da4  43 6f 6e 74 65 6e 74 73 2f 4d 61 63 4f 53 2f 47   Contents/MacOS/G
0xbffe7db4  6f 6f 67 6c 65 20 43 68 72 6f 6d 65 00 2d 70 73   oogle.Chrome.-ps
```

## mac\_yarascan ##