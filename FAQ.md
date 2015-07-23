

# General #

## What is the latest stable version of Volatility ##

The latest stable version is 2.0. You can grab the source code, Python installer, or Windows standalone executable from the [Downloads page](http://code.google.com/p/volatility/downloads/list).

## What is the latest development version of Volatility ##

The latest development version is 2.1 alpha which you can get by checking out the main branch using SVN (see instructions in the [Source page](http://code.google.com/p/volatility/source/checkout)). There are also several branches available for specific needs (descriptions forthcoming).

## What version of Volatility is right for me ##

Please consider the following points when deciding which version of Volatility is best for your needs:

  * If you're using anything less than 2.0 (for example 1.3 or 1.4) you should upgrade and [port your plugins](ConvertingPluginsFromVol13toVol20.md)
  * If you need Linux support, use the ([linux-trunk](http://code.google.com/p/volatility/source/browse/#svn%2Fbranches%2Flinux-trunk)) branch
  * If you're looking for something stable to analyze x86 (32-bit) Windows memory dumps, see the [Downloads page](http://code.google.com/p/volatility/downloads/list).
    * Windows users who just want to be up and running in a matter of seconds (i.e. not install any dependencies) and who don't plan on viewing or modifying any source code, select the [Standalone executable](http://volatility.googlecode.com/files/volatility-2.0.standalone.zip).
    * Windows users who want to install Volatility as a Python package, select the [Windows Module Installer](http://volatility.googlecode.com/files/volatility-2.0.win32.exe).
    * Users of any platform (Windows, Linux, OSX) who want the greatest amount of flexibility, and who potentially are interested in developing new plugins or investigating how Volatility works, select the [zip](http://volatility.googlecode.com/files/volatility-2.0.zip) or [tar](http://volatility.googlecode.com/files/volatility-2.0.tar.gz) archive.
  * If you need x64 (64-bit) Windows support and don't mind working through possible bugs or experimental aspects, you should check out the latest [development version in svn](http://code.google.com/p/volatility/source/checkout).

Also please note that its possible to have multiple versions of Volatility "installed" at the same time. Just store the source files in separate directories (i.e. C:\Users\Joe\volatility\_trunk and C:\Users\Joe\volatility\_linux). You can just "cd" into the proper directory depending on which branch you want to use for a particular task.

## What's new in 2.0 ##

Highlights of this release include:

  * Restructured and depolluted namespace
  * Usage and Development Documentation
  * New Configuration Subsystem
  * New Caching Subsystem
  * New Pluggable address spaces with automated election
  * New Address Spaces (i.e. EWF, [Firewire](Vol20AddressSpacesFirewire.md))
  * Updated Object Model and Profile Subsystems ([VolatilityMagic](Vol20VolatilityMagic.md))
  * Support for Windows Server 2003, Windows Vista, Windows Server 2008, Windows 7
  * Updated Scanning Framework
  * Volshell integration
  * Over 40 new plugins!

## Are Volatility 1.3 plugins compatible with 2.0 ##

No.  A lot has changed since Volatility 1.3 making older plugins incompatible with the current code base.  The good news is most public plugins have been ported to 2.0 already.  You can check the [CommandReference](CommandReference.md) wiki to see if the plugin you are looking for is there.  If not you will need to convert the plugin to work with the current code base.  See [ConvertingPluginsFromVol13toVol20](ConvertingPluginsFromVol13toVol20.md) for details on how to do this.

## What operating systems does Volatility support ##

The stable release of Volatility 2.0 currently only supports 32bit Windows operating systems, however the bleeding edge version of Volatility (trunk in SVN) supports 32bit and 64bit Windows operating systems.

Microsoft Windows:
  * 32bit Windows XP Service Pack 2 and 3
  * 32bit Windows 2003 Server Service Pack 0, 1, 2
  * 32bit Windows Vista Service Pack 0, 1, 2
  * 32bit Windows 2008 Server Service Pack 1, 2 ([there is no SP0](http://blogs.msdn.com/b/iainmcdonald/archive/2008/02/15/windows-server-2008-is-called-sp1-adventures-in-doing-things-right.aspx))
  * 32bit Windows 7 Service Pack 0, 1

_Bleeding Edge Volatility Only_:
  * 64bit Windows XP Service Pack 1 and 2 (There is no SP0)
  * 64bit Windows 2003 Server Service Pack 1 and 2 (there is no SP0)
  * 64bit Windows Vista Service Pack 0, 1, 2
  * 64bit Windows 2008 Server Service Pack 1 and 2 (there is no SP0)
  * 64bit Windows 2008 `R2` Server Service Pack 0 and 1
  * 64bit Windows 7 Service Pack 0 and 1

Linux:
  * Support for Linux memory dumps is growing rapidly. We have two branches ([linux-trunk](http://code.google.com/p/volatility/source/browse/#svn%2Fbranches%2Flinux-trunk) and [scudette](http://code.google.com/p/volatility/source/browse/#svn%2Fbranches%2Fscudette)) whose functionality will be merged into the main trunk in one of the next major releases of Volatility. For information on analyzing Linux memory dumps, see [Linux Support](DocFiles20#Linux_Support.md) and [Linux Memory Forensics](LinuxMemoryForensics.md)

## What about reading crash dumps and hibernation files ##

Volatility should automatically determine whether you've asked it to analyze a crash dump file or a hiberation file, and allow you to run plugins against them just like normal.

If you'd like to save these files as raw dd files, you can use the [imagecopy](http://code.google.com/p/volatility/wiki/CommandReference#imagecopy) plugin to convert them to raw memory images. The raw memory images can also be analyzed using the normal Volatility commands.

## Can Volatility acquire physical memory ##

Short answer: No.
Long Answer: The [imagecopy](http://code.google.com/p/volatility/wiki/CommandReference#imagecopy) plugin can be used to copy one address space to a file (allowing acquisition from address spaces such as IEEE 1394), but in general no, to acquire memory, you must use another tool. For a list of possibilities, see: [The Forensics Wiki](http://www.forensicswiki.org/wiki/Tools:Memory_Imaging)

## What's the largest memory dump Volatility can read ##

There is technically no limit. We've heard reports of Volatility handling 30-40 GB images on both Windows and Linux host operating systems. If you routinely analyze large memory dumps and would like to supply some performance benchmarks for the FAQ, please let us know.

## Are there any public memory samples available that I can use for testing ##

Yes, see the list below.

Images from The [Malware Analyst's Cookbook](http://www.malwarecookbook.com)

| **Description**    | **url** | **OS** |
|:-------------------|:--------|:-------|
| be2.vmem.zip       | [be2.vmem.zip](http://malwarecookbook.googlecode.com/svn-history/r26/trunk/17/6/be2.vmem.zip)| XP SP2 |
| coreflood.vmem.zip | [coreflood.vmem.zip](http://malwarecookbook.googlecode.com/svn-history/r26/trunk/16/6/coreflood.vmem.zip) | XP SP2 |
| laqma.vmem.zip     | [laqma.vmem.zip](http://malwarecookbook.googlecode.com/svn-history/r26/trunk/16/7/laqma.vmem.zip) | XP SP2 |
| prolaco.vmem.zip   | [prolaco.vmem.zip](http://malwarecookbook.googlecode.com/svn-history/r26/trunk/15/6/prolaco.vmem.zip)| XP SP2 |
| sality.vmem.zip    | [sality.vmem.zip](http://malwarecookbook.googlecode.com/svn-history/r26/trunk/17/11/sality.vmem.zip)| XP SP2 |
|  silentbanker.vmem.zip | [silentbanker.vmem.zip](http://malwarecookbook.googlecode.com/svn-history/r26/trunk/16/6/silentbanker.vmem.zip)| XP SP2 |
| tigger.vmem.zip    | [tigger.vmem.zip](http://malwarecookbook.googlecode.com/svn-history/r26/trunk/17/8/tigger.vmem.zip)| XP SP2 |
| zeus.vmem.zip      | [zeus.vmem.zip](http://malwarecookbook.googlecode.com/svn-history/r26/trunk/17/1/zeus.vmem.zip)| XP SP2 |
| spyeye.vmem.zip    |[spyeye.vmem.zip](http://code.google.com/p/malwarecookbook/source/browse/trunk/spyeye.vmem.zip)| XP SP2 |

Other Images

| **Description**    | **url** | **OS** |
|:-------------------|:--------|:-------|
| Stuxnet image      | [stuxnet.vmem.zip](http://malwarecookbook.googlecode.com/svn/trunk/stuxnet.vmem.zip)| XP SP3 |
| NIST               | [http://www.cfreds.nist.gov/mem/memory-images.rar](http://www.cfreds.nist.gov/mem/memory-images.rar)| XP SP2 |
|Hogfly's malware memory samples | [http://cid-5694a755c9c6a175.skydrive.live.com/browse.aspx/Public](http://cid-5694a755c9c6a175.skydrive.live.com/browse.aspx/Public)| ?      |
|Moyix's Fuzzy Hidden Process Sample | [http://amnesia.gtisc.gatech.edu/~moyix/ds\_fuzz\_hidden\_proc.img.bz2](http://amnesia.gtisc.gatech.edu/~moyix/ds_fuzz_hidden_proc.img.bz2)| XP SP3 |
|Honeynet Banking Troubles Image | [https://www.honeynet.org/challenges/2010\_3\_banking\_troubles](https://www.honeynet.org/challenges/2010_3_banking_troubles)| XP SP2 |
|NPS 2009-M57        | [https://domex.nps.edu/corp/nps/scenarios/2009-m57-patents/ram/](https://domex.nps.edu/corp/nps/scenarios/2009-m57-patents/ram/) |  Various XP / Vista |
| [Dougee's comparison samples](http://dougee652.blogspot.com/2011/04/malware-memory-images.html) | [before](http://dl.dropbox.com/u/21148428/xp-clean.tgz) and [after infection](http://dl.dropbox.com/u/21148428/xp-infected.tgz) | XP     |
| Shylock Sample     | [Shylock vmem](http://various-things.googlecode.com/files/vmem2.zip) | XP     |
| R2D2 Sample        | [0zapftis.rar](http://www.mediafire.com/file/yxqodp1p2aca91x/0zapftis.rar) (pw: infected) | XP SP2 |
| Honeynet Compromised Server Challenge | http://www.honeynet.org/challenges/2011_7_compromised_server | Linux - Debian 2.6.26-26 |
| Pikeworks Linux Samples | http://secondlookforensics.com/images.html | Misc Linux |

<br>

<h1>Installation</h1>

<h2>What are the dependencies for running Volatility</h2>

Note: once the installers are released, update this section since some installers come pre-packaged with python and the dependencies.<br>
<br>
Here is what you need for the core functionality:<br>
<br>
<ul><li>A Windows, Linux, or Mac OS X machine<br>
</li><li>Python version 2.6 or greater (but not 3.x)</li></ul>

Some plugins require third party libraries which you can get here:<br>
<br>
<ul><li><a href='http://code.google.com/p/distorm/'>Distorm3</a> (Malware Plugins, Volshell)<br>
</li><li><a href='http://code.google.com/p/yara-project/'>Yara</a> (Malware Plugins)<br>
</li><li><a href='http://gitweb.pycrypto.org/?p=crypto/pycrypto-2.0.x.git;a=summary'>PyCrypto</a> (Core)<br>
</li><li><a href='http://docs.python.org/library/sqlite3.html'>Sqlite3</a></li></ul>

If you are still using the 1.3 branch of Volatility, then you may need:<br>
<br>
<ul><li><a href='http://libdasm.googlecode.com'>pydasm</a>
</li><li><a href='http://pefile.googlecode.com'>pefile</a></li></ul>

<h2>Where do I find the "malware" plugins</h2>

The most recent version can be downloaded from <a href='http://malwarecookbook.googlecode.com/svn/trunk/malware.py'>here</a>.<br>
<br>
<h1>Usage</h1>

<h2>How do I run Volatility</h2>

See <a href='BasicUsage.md'>BasicUsage</a> and <a href='CommandReference.md'>CommandReference</a> for information on how to use Volatility.<br>
<br>
<h2>How can I run external plugins with the standalone executable</h2>

With the standalone executable you have to specify the location of external plugins directory or zipfile using the "--plugins" switch.  In general you can specify the path of the item "--plugins=<path to directory/zipfile>".  An example using a directory called "plugins" can be seen below:<br>
<br>
<pre><code>C:\vol&gt;volatility.exe --plugins=..\plugins malfind -f c:\memory_images\win7.dd --profile=Win7SP0x86 -D output<br>
Volatile Systems Volatility Framework 2.0 <br>
Name                 Pid    Start      End        Tag      Hits   Protect<br>
svchost.exe          740    0x005b0000 0x5f0fff00 Vad      0      PAGE_EXECUTE_WRITECOPY<br>
Dumped to: output\svchost.exe.3e3949d0.005b0000-005f0fff.dmp<br>
0x005b0000   4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00    MZ..............<br>
0x005b0010   b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00    ........@.......<br>
0x005b0020   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................<br>
0x005b0030   00 00 00 00 00 00 00 00 00 00 00 00 d8 00 00 00    ................<br>
0x005b0040   0e 1f ba 0e 00 b4 09 cd 21 b8 01 4c cd 21 54 68    ........!..L.!Th<br>
0x005b0050   69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f    is program canno<br>
0x005b0060   74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20    t be run in DOS<br>
0x005b0070   6d 6f 64 65 2e 0d 0d 0a 24 00 00 00 00 00 00 00    mode....$.......<br>
[snip]<br>
</code></pre>

You can also give Volatility a zipfile containing plugins:<br>
<br>
<pre><code>C:\vol&gt;volatility.exe --plugins=malfind.zip malfind -f c:\memory_images\win7.dd --profile=Win7SP0x86 -D output<br>
Volatile Systems Volatility Framework 2.0 <br>
Name                 Pid    Start      End        Tag      Hits   Protect<br>
svchost.exe          740    0x005b0000 0x5f0fff00 Vad      0      PAGE_EXECUTE_WRITECOPY<br>
Dumped to: output\svchost.exe.3e3949d0.005b0000-005f0fff.dmp<br>
0x005b0000   4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00    MZ..............<br>
0x005b0010   b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00    ........@.......<br>
0x005b0020   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................<br>
0x005b0030   00 00 00 00 00 00 00 00 00 00 00 00 d8 00 00 00    ................<br>
0x005b0040   0e 1f ba 0e 00 b4 09 cd 21 b8 01 4c cd 21 54 68    ........!..L.!Th<br>
0x005b0050   69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f    is program canno<br>
0x005b0060   74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20    t be run in DOS<br>
0x005b0070   6d 6f 64 65 2e 0d 0d 0a 24 00 00 00 00 00 00 00    mode....$.......<br>
[snip]<br>
</code></pre>

<b>Note:</b> Due to the way plugins are loaded, the external plugins directory or zipfile must be specified before any plugin-specific arguments (including the name of the plugin).<br>
<br>
<h2>Where can I find additional documentation on Volatility</h2>

See the following resources:<br>
<br>
<ul><li>There are a few installation guides and how-to's provided by the community which you can find on the <a href='http://code.google.com/p/volatility/downloads/list'>Downloads Page</a>
</li><li>The <a href='http://code.google.com/p/volatility/wiki/DocFiles20'>Volatility Documentation Project Wiki</a> contains links to external web sites.<br>
</li><li><a href='http://www.malwarecookbook.com'>Malware Analyst's Cookbook</a> devotes 4 chapters to using Volatility for malware analysis.</li></ul>

<h1>Troubleshooting</h1>

<h2>I'm getting an error: "<code>[..]</code> (ImportError: No module named Crypto.Hash)"</h2>

This error occurs when <a href='http://code.google.com/p/volatility/wiki/FullInstallation#Installation_Prerequisites'>PyCrypto is not installed</a>.  This is a library that is used by some of the registry plugins like <a href='http://code.google.com/p/volatility/wiki/CommandReference#lsadump'>lsadump</a>.  You will see this error message when using any of the plugins, however.  If you are not using lsadump, hashdump or any other registry plugin that uses PyCrypto, then you can safely ignore the error message.  Otherwise, install PyCrypto and the message will disappear.  See <a href='FullInstallation.md'>FullInstallation</a> for more details on how to install supporting libraries.<br>
<br>
<h2>Volatility thinks my image is invalid</h2>

If you run into the message "Could not list tasks, please verify the --profile option and whether this image is valid" there are a few things you should know. First, the --profile parameter should be set to the name of a Volatility profile that matches the OS and architecture of the memory dump. If you don't know which OS your memory dump came from, try using the <a href='CommandReference#imageinfo.md'>imageinfo</a> plugin for suggestions. If you use those suggestions and still see the error message, the most likely cause is multiple KDBG signatures. Volatility finds and uses the first KDBG signature it finds, which in the case of multiple KDBG signatures - the first one may not be the correct one. In this case, you should use the <a href='CommandReference#kdbgscan.md'>kdgbscan</a> plugin and select an alternate KDBG address. When you run commands, also supply the --kdbg parameter. Here's an example walk-through:<br>
<br>
<pre><code>$ python vol.py -f mem.dmp --profile=Win2003SP2x64 pslist <br>
Volatile Systems Volatility Framework 2.1_alpha<br>
 Offset(V)  Name                 PID    PPID   Thds   Hnds   Time <br>
---------- -------------------- ------ ------ ------ ------ -------------------<br>
Could not list tasks, please verify the --profile option and whether this image is valid<br>
</code></pre>

Now let's confirm the profile we're using is one that Volatility suggests:<br>
<br>
<pre><code>$ python vol.py -f mem.dmp imageinfo <br>
Volatile Systems Volatility Framework 2.1_alpha<br>
Determining profile based on KDBG search...<br>
<br>
          Suggested Profile(s) : Win2003SP2x64, WinXPSP1x64<br>
                     AS Layer1 : AMD64PagedMemory (Kernel AS)<br>
                     AS Layer2 : FileAddressSpace (/Users/Michael/mem.dmp)<br>
                      PAE type : PAE<br>
                           DTB : 0x529000<br>
                          KDBG : 0xf80001172cb0<br>
                          KPCR : 0xffdff000<br>
             KUSER_SHARED_DATA : 0xfffff78000000000L<br>
           Image date and time : 2012-01-30 18:55:54 <br>
     Image local date and time : 2012-01-30 18:55:54 <br>
Could not list tasks, please verify the --profile option and whether this image is valid<br>
</code></pre>

Volatility suggested two profiles, the first and thus most likely profile is Win2003SP2x64 (which is the one we originally used). The KDBG signature was found at 0xf80001172cb0. Now let's double check if there are multiple KDBG signatures.<br>
<br>
<pre><code>$ python vol.py -f mem.dmp kdbgscan --profile=Win2003SP2x64<br>
Volatile Systems Volatility Framework 2.1_alpha<br>
Potential KDBG structure addresses (P = Physical, V = Virtual):<br>
 _KDBG: V 0xf80001172cb0  (Win2003SP2x64)<br>
 _KDBG: P 0x01172cb0  (Win2003SP2x64)<br>
 _KDBG: V 0xf80001175cf0  (Win2003SP2x64)<br>
 _KDBG: P 0x01175cf0  (Win2003SP2x64)<br>
</code></pre>

Near the end you can see there's an alternate KDBG signature found at 0xf80001175cf0. Supply this one to --kdbg with using pslist and see if that solves the problem:<br>
<br>
<pre><code>$ python vol.py -f mem.dmp --profile=Win2003SP2x64 --kdbg=0xf80001175cf0<br>
Volatile Systems Volatility Framework 2.1_alpha<br>
 Offset(V)  Name                 PID    PPID   Thds   Hnds   Time <br>
---------- -------------------- ------ ------ ------ ------ ------------------- <br>
0xfffffadfe7a7dc20 System                    4      0     60    341 1970-01-01 00:00:00       <br>
0xfffffadfe736b040 smss.exe                300      4      3     19 2012-01-23 18:19:44       <br>
0xfffffadfe6fe0c20 csrss.exe               348    300     13    449 2012-01-23 18:19:46       <br>
0xfffffadfe7054c20 winlogon.exe            372    300     23    618 2012-01-23 18:19:47       <br>
0xfffffadfe7115c20 services.exe            420    372     16    277 2012-01-23 18:19:50     <br>
....<br>
</code></pre>

<h2>No address space mapping, No valid DTB found</h2>

If you see the message "No suitable address space mapping found" and/or "No valid DTB found" most likely you've selected an invalid profile for the memory image you're analyzing. For example:<br>
<br>
<pre><code>$ python vol.py -f win2k3sp0.vmem psscan<br>
Volatile Systems Volatility Framework 2.1_alpha<br>
 Offset(P)  Name             PID    PPID   PDB        Time created             Time exited             <br>
---------- ---------------- ------ ------ ---------- ------------------------ ------------------------ <br>
No suitable address space mapping found<br>
Tried to open image as:<br>
 WindowsHiberFileSpace32: No base Address Space<br>
 EWFAddressSpace: No libEWF implementation found<br>
 WindowsCrashDumpSpace32: No base Address Space<br>
 AMD64PagedMemory: No base Address Space<br>
 JKIA32PagedMemory: No base Address Space<br>
 JKIA32PagedMemoryPae: No base Address Space<br>
 IA32PagedMemoryPae: Module disabled<br>
 IA32PagedMemory: Module disabled<br>
 WindowsHiberFileSpace32: No xpress signature found<br>
 EWFAddressSpace: No libEWF implementation found<br>
 WindowsCrashDumpSpace32: Header signature invalid<br>
 AMD64PagedMemory: Incompatible profile WinXPSP2x86 selected<br>
 JKIA32PagedMemory: No valid DTB found<br>
 JKIA32PagedMemoryPae: No valid DTB found<br>
 IA32PagedMemoryPae: Module disabled<br>
 IA32PagedMemory: Module disabled<br>
 FileAddressSpace: Must be first Address Space<br>
</code></pre>

You should check with the <a href='CommandReference#imageinfo.md'>imageinfo</a> plugin for profile suggestions (also see the previous FAQ entry). In this case, simply supplying the correct profile will fix the issue:<br>
<br>
<pre><code>$ python vol.py -f win2k3sp0.vmem --profile=Win2003SP0x86 psscan<br>
Volatile Systems Volatility Framework 2.1_alpha<br>
 Offset(P)  Name             PID    PPID   PDB        Time created             Time exited             <br>
---------- ---------------- ------ ------ ---------- ------------------------ ------------------------ <br>
0x01fc6550 vmtoolsd.exe       2816    508 0x0e717000 2010-09-26 20:15:24      2010-09-26 20:15:46     <br>
0x01fca2f0 VMwareTray.exe     2788    152 0x098bc000 2010-09-26 20:15:24      2010-09-26 20:15:44     <br>
0x01ff0d00 wpabaln.exe        3352    464 0x0d716000 2010-09-26 20:15:32      2010-09-26 20:15:44     <br>
0x01ffed88 rundll32.exe       2704   2696 0x16c38000 2010-09-26 20:15:20      2010-09-26 20:15:44     <br>
0x01fff348 spoolsv.exe        2096    508 0x1168f000 2010-09-26 20:14:55      2010-09-26 20:15:46     <br>
0x02023ca0 msiexec.exe        1748   1920 0x079d4000 2010-09-26 20:14:51      2010-09-26 20:15:39<br>
....<br>
</code></pre>

<h2>Scanning commands report false positives</h2>

Commands like <a href='CommandReference#psscan.md'>psscan</a>, <a href='CommandReference#modscan.md'>modscan</a>, <a href='CommandReference#connscan.md'>connscan</a>, etc. use pool tag scanning to find objects (either active or residual) in physical memory. Thus Volatility scans over your entire memory dump looking for 4 byte pool tag signatures and then applies a serious of sanity checks (specific per object type). If you believe one of the scanners has found a false positive, you can investigate the reason using <a href='CommandReference#volshell.md'>volshell</a> (look for the section that describes how to use the dt() command with a physical address space). You also may want to view the source code for the plugin you're running and examine the sanity checks Volatility uses. In particular, look for classes that subclass scan.ScannerCheck and view the list of checks in classes that subclass scan.PoolScanner. For more information on the scanning framework, see <a href='Scanners.md'>Scanners</a>.<br>
<br>
<h2>How can I report a bug or feature request</h2>

See the contact section below.<br>
<br>
<h1>Contact</h1>

<h2>Who wrote/is writing Volatility</h2>

See the AUTHORS.txt and CREDITS.txt files provided with the Volatility source code.<br>
<br>
<h2>How can I contribute to Volatility</h2>

If you have documentation, code or ideas to contribute, use one of the following methods:<br>
<br>
<ul><li>Through the <a href='http://code.google.com/p/volatility/issues/list'>Google Code web interface</a>
</li><li>Through IRC: #volatility on freenode<br>
</li><li>Through the <a href='http://lists.volatilesystems.com/mailman/listinfo'>Volatility Mailing List</a>