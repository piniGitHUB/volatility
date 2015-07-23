

The win32k.sys suite of plugins analyzes GUI memory. Most of these plugins are more thoroughly described (including details on underlying data structures, example use cases, etc) on the [Volatility Labs Blog](http://volatility-labs.blogspot.com), so the content here is just a quick summary.

# sessions #

This command analyzes the unique `_MM_SESSION_SPACE` objects and prints details related to the processes running in each logon session, mapped drivers, paged/non-paged pools etc. The alternate process lists output by this plugin are leveraged by the `psxview` plugin for rootkit detection. For more information, see [MoVP 1.1 Logon Sessions, Processes, and Images](http://volatility-labs.blogspot.com/2012/09/movp-11-logon-sessions-processes-and.html).

```
$ python vol.py -f win7x64.dd --profile=Win7SP1x64 sessions
Volatile Systems Volatility Framework 2.1_alpha
**************************************************
Session(V): fffff88002ec7000 ID: 0 Processes: 20
PagedPoolStart: fffff900c0000000 PagedPoolEnd fffff920bfffffff
 Process: 316 csrss.exe 2011-12-30 08:25:45 
 Process: 352 wininit.exe 2011-12-30 08:25:54 
 Process: 448 services.exe 2011-12-30 08:25:57 
 Process: 464 lsass.exe 2011-12-30 08:25:57 
 Process: 472 lsm.exe 2011-12-30 08:25:57 
 Process: 564 svchost.exe 2011-12-30 08:26:00 
 Process: 632 svchost.exe 2011-12-30 08:26:01 
 Process: 824 sppsvc.exe 2011-12-30 08:26:14 
 Process: 868 svchost.exe 2011-12-30 08:26:15 
 Process: 892 svchost.exe 2011-12-30 08:26:15 
 Process: 928 svchost.exe 2011-12-30 08:26:15 
 Process: 268 svchost.exe 2011-12-30 08:27:04 
 Process: 296 svchost.exe 2011-12-30 08:27:04 
 Process: 1144 spoolsv.exe 2011-12-30 08:27:08 
 Process: 1176 svchost.exe 2011-12-30 08:27:08 
 Process: 1868 svchost.exe 2011-12-30 07:29:10 
 Process: 2016 svchost.exe 2011-12-30 07:29:13 
 Process: 1240 SearchIndexer. 2011-12-30 07:29:13 
 Process: 1904 svchost.exe 2012-01-19 14:27:08 
 Process: 2284 f-response-ent 2012-03-14 16:45:57 
 Image: 0xfffffa800284b860, Address fffff96000080000, Name: win32k.sys
 Image: 0xfffffa800234d200, Address fffff960004e0000, Name: dxg.sys
 Image: 0xfffffa80028178a0, Address fffff960007d0000, Name: TSDDD.dll
```

# wndscan #

This command scans for `tagWINDOWSTATION` objects and prints details on the window station, its global atom table, available clipboard formats, and processes or threads currently interacting with the clipboard. For more information see [MoVP 1.2 Window Stations and Clipboard Malware](http://volatility-labs.blogspot.com/2012/09/movp-12-window-stations-and-clipboard.html).

```
$ python vol.py -f rdp.mem --profile=Win2003SP2x86 wndscan
Volatile Systems Volatility Framework 2.1_alpha
**************************************************
WindowStation: 0x8581e40, Name: WinSta0, Next: 0x0
SessionId: 2, AtomTable: 0xe7981648, Interactive: True
Desktops: Default, Disconnect, Winlogon
ptiDrawingClipboard: pid - tid -
spwndClipOpen: 0x0, spwndClipViewer: 0xbc6f2ca8 6772 rdpclip.exe
cNumClipFormats: 4, iClipSerialNumber: 9
pClipBase: 0xe6fe8ec8, Formats: CF_UNICODETEXT,CF_LOCALE,CF_TEXT,CF_OEMTEXT 
[snip] 
```

# deskscan #

This command subclasses the `wndscan` plugin and for each window station found, it walks the list of desktops. It can be used for the following purposes:

  * Find rogue desktops used to hide applications from logged-on users
  * Detect desktops created by ransomware
  * Link threads to their desktops
  * Analyze the desktop heap for memory corruptions
  * Profile dekstop heap allocations to locate USER objects

Here's an example of the output. For more information see [MoVP 1.3 Desktops, Heaps, and Ransomware](http://volatility-labs.blogspot.com/2012/09/movp-13-desktops-heaps-and-ransomware.html).

```
$ python vol.py -f rdp.mem --profile=Win2003SP2x86 deskscan
Volatile Systems Volatility Framework 2.1_alpha
**************************************************
Desktop: 0x8001038, Name: WinSta0\Default, Next: 0x8737bc10
SessionId: 2, DesktopInfo: 0xbc6f0650, fsHooks: 2128
spwnd: 0xbc6f06e8, Windows: 238
Heap: 0xbc6f0000, Size: 0x300000, Base: 0xbc6f0000, Limit: 0xbc9f0000
 7808 (notepad.exe 6236 parent 5544)
 7760 (csrss.exe 7888 parent 432)
 5116 (csrss.exe 7888 parent 432)
 8168 (PccNTMon.exe 5812 parent 5132)
 3040 (cmd.exe 5544 parent 5132)
 6600 (csrss.exe 7888 parent 432)
 7392 (explorer.exe 5132 parent 8120)
 5472 (explorer.exe 5132 parent 8120)
 548 (PccNTMon.exe 5812 parent 5132)
 6804 (mbamgui.exe 5220 parent 5132)
 2008 (ctfmon.exe 4576 parent 5132)
 3680 (PccNTMon.exe 5812 parent 5132)
 2988 (VMwareTray.exe 3552 parent 5132)
 1120 (explorer.exe 5132 parent 8120)
 4500 (explorer.exe 5132 parent 8120)
 7732 (explorer.exe 5132 parent 8120)
 6836 (explorer.exe 5132 parent 8120)
 7680 (winlogon.exe 3272 parent 432)
 7128 (rdpclip.exe 6772 parent 3272)
 5308 (rdpclip.exe 6772 parent 3272)
**************************************************
Desktop: 0x737bc10, Name: WinSta0\Disconnect, Next: 0x8a2f2068
SessionId: 2, DesktopInfo: 0xbc6e0650, fsHooks: 0
spwnd: 0xbc6e06e8, Windows: 25
Heap: 0xbc6e0000, Size: 0x10000, Base: 0xbc6e0000, Limit: 0xbc6f0000
**************************************************
Desktop: 0xa2f2068, Name: WinSta0\Winlogon, Next: 0x0
SessionId: 2, DesktopInfo: 0xbc6c0650, fsHooks: 0
spwnd: 0xbc6c06e8, Windows: 6
Heap: 0xbc6c0000, Size: 0x20000, Base: 0xbc6c0000, Limit: 0xbc6e0000
 6912 (winlogon.exe 3272 parent 432)
 1188 (winlogon.exe 3272 parent 432)
 8172 (winlogon.exe 3272 parent 432)
**************************************************
[snip]
```

# atomscan #

This command scans physical memory for atom tables. For each table found, it enumerates the bucket of atoms - including session global atoms and window station global atoms. It does not include process local atoms. Atoms are reported the order in which they were found, unless you specify --sort-by=atom (sorts by atom ID) or --sort-by=refcount (sorts by number of references to the atom). Using this plugin you can find registered window messages, rogue injected DLL paths, window class names, etc. For more information see [MoVP 2.1 Atoms (The New Mutex), Classes, and DLL Injection](http://volatility-labs.blogspot.com/2012/09/movp-21-atoms-new-mutex-classes-and-dll.html).

```
$ python vol.py -f mutihack.vmem atomscan
AtomOfs(V)       Atom Refs   Pinned Name
---------- ---------- ------ ------ ----
[snip]
0xe179d850     0xc038      1      1 OleMainThreadWndClass
0xe17a7e40     0xc094      2      0 Shell_TrayWnd
0xe17c34b8     0xc0c4      2      0 UnityAppbarWindowClass
0xe17c7678     0xc006      1      1 FileName
0xe17d40a0     0xc0ff      2      0 
0xe17d4128     0xc027      1      1 SysCH
0xe17e78f0     0xc01c      1      1 ComboBox
0xe17e9070     0xc065     26      0 6.0.2600.6028!Combobox
0xe17ec350     0xc13e      1      0 Xaml
0xe18119c0     0xc08c      5      0 OM_POST_WM_COMMAND
[snip]
```

# atoms #

This command is similar to `atomscan` above, but it allows us to associate atom tables with their owning window station. We need this command in conjunction with `atomscan` because there are many reasons an atom must be tied to its session or window station (for example when resolving `ihmod` values from windows message hooks or event hooks.

# clipboard #

This command recovers data from users' clipboards. It walks the array of `tagCLIP` objects pointed to by `tagWINDOWSTATION.pClipBase` and takes the format (i.e. unicode, ansi, ole, bmp) and the handle value. Then it walks the USER handle table (also see the [userhandles](CommandReferenceGui22#userhandles.md) plugin) and filters for TYPE\_CLIPDATA objects. It matches the handle value of those objects with the handles from `tagCLIP` so that a format can be associated with the raw data. For more information, see [MoVP 3.4: Recovering tagCLIPDATA What's In Your Clipboard?](http://volatility-labs.blogspot.com/2012/09/movp-34-recovering-tagclipdata-whats-in.html).

The output below shows an extracted unicode command that a user had copied to the clipboard:

```
$ python vol.py -f dfrws2008-rodeo-memory.img clipboard
Volatile Systems Volatility Framework 2.1_alpha
Session  WindowStation Format               Handle Object     Data                                             
-------- ------------- ---------------- ---------- ---------- ------------
    0    WinSta0       CF_UNICODETEXT     0x4900c3 0xe12a7c98 pp -B -p -o out.pl file                           
    0    WinSta0       CF_LOCALE           0x80043 0xe12362d0                                                   
    0    WinSta0       CF_TEXT                 0x1 ----------                                                   
    0    WinSta0       CF_OEMTEXT              0x1 ----------
```

The next example is a format type CF\_HDROP which is a copy & paste operating of a file from windows explorer. Notice the entire file's content isn't copied to the clipboard, just the full path.

```
$ python vol.py -f xpsp3.vmem clipboard -v
Volatile Systems Volatility Framework 2.1_rc3
[snip]

   0    WinSta0       CF_HDROP           0x10230131 0xe1fa6590

0xe1fa659c  14 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
0xe1fa65ac  01 00 00 00 43 00 3a 00 5c 00 44 00 6f 00 63 00 ....C.:.\.D.o.c.
0xe1fa65bc  75 00 6d 00 65 00 6e 00 74 00 73 00 20 00 61 00 u.m.e.n.t.s...a.
0xe1fa65cc  6e 00 64 00 20 00 53 00 65 00 74 00 74 00 69 00 n.d...S.e.t.t.i.
0xe1fa65dc  6e 00 67 00 73 00 5c 00 41 00 64 00 6d 00 69 00 n.g.s.\.A.d.m.i.
0xe1fa65ec  6e 00 69 00 73 00 74 00 72 00 61 00 74 00 6f 00 n.i.s.t.r.a.t.o.
0xe1fa65fc  72 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 r.\.D.e.s.k.t.o.
0xe1fa660c  70 00 5c 00 6e 00 6f 00 74 00 65 00 2e 00 74 00 p.\.n.o.t.e...t.
0xe1fa661c  78 00 74 00 00 00 00 00                         x.t.....
```

# eventhooks #

This command enumerates event hooks installed via the `SetWinEventHook` API. It prints the minimum and maximum event IDs to which the hook applies, the targeted threads, owning processes, and offset to the hook procedure. For more information, see [MoVP 3.1 Detecting Malware Hooks in the Windows GUI Subsystem](http://volatility-labs.blogspot.com/2012/09/movp-31-detecting-malware-hooks-in.html).

```
$ python vol.py -f  win7x64.dd --profile=Win7SP1x64 eventhooks
Volatile Systems Volatility Framework 2.1_alpha

Handle: 0x300cb, Object: 0xfffff900c01eda10, Session: 1
Type: TYPE_WINEVENTHOOK, Flags: 0, Thread: 1516, Process: 880
eventMin: 0x4 EVENT_SYSTEM_MENUSTART
eventMax: 0x7 EVENT_SYSTEM_MENUPOPUPEND
Flags: none, offPfn: 0xff567cc4, idProcess: 0, idThread: 0
ihmod: -1
```

# gahti #

This command uses an algorithmic approach to finding the `win32k!gahti` symbol which is an array of `tagHANDLETYPEINFO` structures - one for each type of USER object for the system. Windows XP has typically 20 objects and Windows 7 has 22, including TYPE\_FREE. The plugin shows you the 4-byte tag associated with allocations, where the objects are allocated from (desktop heap, shared heap, session pool), and how the objects are owned (thread owned, process owned, or anonymous). For more information, see [MoVP 3.3 Analyzing USER Handles and the Win32k Gahti](http://volatility-labs.blogspot.com/2012/09/movp-33-analyzing-user-handles-and.html).

```
$ python vol.py -f win7x64cmd.dd --profile=Win7SP1x64 gahti
Volatile Systems Volatility Framework 2.1_alpha
Session  Type                 Tag      fnDestroy          Flags
-------- -------------------- -------- ------------------ -----
       0 TYPE_FREE                     0x0000000000000000 
       0 TYPE_WINDOW          Uswd     0xfffff9600014f660 OCF_DESKTOPHEAP, OCF_THREADOWNED, OCF_USEPOOLIFNODESKTOP, OCF_USEPOOLQUOTA
       0 TYPE_MENU                     0xfffff960001515ac OCF_DESKTOPHEAP, OCF_PROCESSOWNED
       0 TYPE_CURSOR          Uscu     0xfffff960001541a0 OCF_MARKPROCESS, OCF_PROCESSOWNED, OCF_USEPOOLQUOTA
       0 TYPE_SETWINDOWPOS    Ussw     0xfffff960001192b4 OCF_THREADOWNED, OCF_USEPOOLQUOTA
       0 TYPE_HOOK                     0xfffff9600018e5c8 OCF_DESKTOPHEAP, OCF_THREADOWNED
       0 TYPE_CLIPDATA        Uscb     0xfffff9600017c5ac 
       0 TYPE_CALLPROC                 0xfffff9600017c5cc OCF_DESKTOPHEAP, OCF_PROCESSOWNED
       0 TYPE_ACCELTABLE      Usac     0xfffff9600017c5cc OCF_PROCESSOWNED, OCF_USEPOOLQUOTA
       0 TYPE_DDEACCESS       Usd9     0xfffff9600017c5ac OCF_THREADOWNED, OCF_USEPOOLQUOTA
       0 TYPE_DDECONV         UsdA     0xfffff960001ba1fc OCF_THREADOWNED, OCF_USEPOOLQUOTA
       0 TYPE_DDEXACT         UsdB     0xfffff960001ba22c OCF_THREADOWNED, OCF_USEPOOLQUOTA
       0 TYPE_MONITOR         Usdi     0xfffff960001ca76c OCF_SHAREDHEAP
       0 TYPE_KBDLAYOUT       Uskb     0xfffff960001b7c28 
       0 TYPE_KBDFILE         Uskf     0xfffff960001b77c8 
       0 TYPE_WINEVENTHOOK    Uswe     0xfffff9600018f148 OCF_THREADOWNED
       0 TYPE_TIMER           Ustm     0xfffff960001046dc OCF_PROCESSOWNED
       0 TYPE_INPUTCONTEXT    Usim     0xfffff9600014c660 OCF_DESKTOPHEAP, OCF_THREADOWNED
       0 TYPE_HIDDATA         Usha     0xfffff960001d2a34 OCF_THREADOWNED
       0 TYPE_DEVICEINFO      UsDI     0xfffff960000d8cd4 
       0 TYPE_TOUCH           Ustz     0xfffff9600017c5cc OCF_THREADOWNED
       0 TYPE_GESTURE         Usgi     0xfffff9600017c5cc OCF_THREADOWNED
```

# messagehooks #

This command prints both local and global message hooks, installed via `SetWindowsHookEx` APIs. This is a common trick used by malware to inject code into other processes and log keystrokes, record mouse movements, etc. For more information, see [MoVP 3.1 Detecting Malware Hooks in the Windows GUI Subsystem](http://volatility-labs.blogspot.com/2012/09/movp-31-detecting-malware-hooks-in.html).

```
$ python vol.py -f laqma.vmem messagehooks --output=block
Volatile Systems Volatility Framework 2.1_alpha
Offset(V)  : 0xbc693988
Session    : 0
Desktop    : WinSta0\Default
Thread     : <any>
Filter     : WH_GETMESSAGE
Flags      : HF_ANSI, HF_GLOBAL
Procedure  : 0x1fd9
ihmod      : 1
Module     : C:\WINDOWS\system32\Dll.dll

Offset(V)  : 0xbc693988
Session    : 0
Desktop    : WinSta0\Default
Thread     : 1584 (explorer.exe 1624)
Filter     : WH_GETMESSAGE
Flags      : HF_ANSI, HF_GLOBAL
Procedure  : 0x1fd9
ihmod      : 1
Module     : C:\WINDOWS\system32\Dll.dll

Offset(V)  : 0xbc693988
Session    : 0
Desktop    : WinSta0\Default
Thread     : 252 (VMwareUser.exe 1768)
Filter     : WH_GETMESSAGE
Flags      : HF_ANSI, HF_GLOBAL
Procedure  : 0x1fd9
ihmod      : 1
Module     : C:\WINDOWS\system32\Dll.dll
[snip]
```

# screenshot #

This command takes a screenshot from each desktop on the system. The screenshot is a wire-frame diagram, with labeled window titles, according to the Z-Order (i.e. front to back) arrangement of the windows and their coordinates at the time of the memory dump. For more information, see [MoVP 4.3 Taking Screenshots From Memory Dumps](http://volatility-labs.blogspot.com/2012/10/movp-43-taking-screenshots-from-memory.html).

```
$ python vol.py -f users.vmem --profile=Win7SP1x86 screenshot -D shots/
Volatile Systems Volatility Framework 2.1_alpha
Wrote shots/session_0.Service-0x0-3e4$.Default.png
Wrote shots/session_0.Service-0x0-3e5$.Default.png
Wrote shots/session_0.msswindowstation.mssrestricteddesk.png
Wrote shots/session_0.Service-0x0-3e7$.Default.png
Wrote shots/session_1.WinSta0.Default.png
Wrote shots/session_1.WinSta0.Disconnect.png
Wrote shots/session_1.WinSta0.Winlogon.png
Wrote shots/session_0.WinSta0.Default.png
Wrote shots/session_0.WinSta0.Disconnect.png
Wrote shots/session_0.WinSta0.Winlogon.png
Wrote shots/session_2.WinSta0.Default.png
Wrote shots/session_2.WinSta0.Disconnect.png
Wrote shots/session_2.WinSta0.Winlogon.png
```

Here's an example of one of the desktops:

![http://4.bp.blogspot.com/-qH4Qt7QP37w/UGqEM7oHbLI/AAAAAAAACx4/LY8Ekvqi47s/s1600/session_0.WinSta0.Default.png](http://4.bp.blogspot.com/-qH4Qt7QP37w/UGqEM7oHbLI/AAAAAAAACx4/LY8Ekvqi47s/s1600/session_0.WinSta0.Default.png)

# userhandles #

This command locates the session-specific `tagSHAREDINFO` structure, walks the `aheList` member (an array of `_HANDLEENTRY`) structures. It determines if each handle entry is thread or process owned, shows the object type, and its offset in session space. This plugin is not very verbose, its just meant to show an overview of the USER objects currently in use by each thread or process; and it serves as an API for other plugins that do want verbose details on an object type. For example the gditimers and eventhooks plugins leverage the APIs from this plugin. For more information, see [MoVP 3.3 Analyzing USER Handles and the Win32k Gahti](http://volatility-labs.blogspot.com/2012/09/movp-33-analyzing-user-handles-and.html).

```
$ python vol.py -f win7x64.dd --profile=Win7SP1x64 userhandles
Volatile Systems Volatility Framework 2.1_alpha
**************************************************
SharedInfo: 0xfffff9600035d300, SessionId: 0 
aheList: 0xfffff900c0400000, Table size: 0x2000, Entry size: 0x18

Object(V)                Handle bType          Flags    Thread  Process
------------------ ------------ --------------- -------- -------- -------
0xfffff900c05824b0      0x10001 TYPE_MONITOR     0     -------- -
0xfffff900c01bad20      0x10002 TYPE_WINDOW      64      432    316
0xfffff900c00b6730      0x10003 TYPE_CURSOR      0     -------- 316
0xfffff900c0390b90      0x10004 TYPE_WINDOW      0       432    316
0xfffff900c00d7ab0      0x10005 TYPE_CURSOR      0     -------- 316
0xfffff900c0390e60      0x10006 TYPE_WINDOW      0       432    316
0xfffff900c00d7640      0x10007 TYPE_CURSOR      0     -------- 316
[snip]
0xfffff900c0630bf0   0x467c054b TYPE_HOOK        0       2368   2348
0xfffff900c0616d60     0x72055f TYPE_MENU        0     -------- 880
0xfffff900c0654610   0x494c0581 TYPE_MENU        0     -------- 880
0xfffff900c1a14b10   0x539f0583 TYPE_CURSOR      0     -------- 880
[snip]
```

# gditimers #

This command leverages the USER handle table API as described above and for each TYPE\_TIMER, it dereferences the object as a `tagTIMER` and prints details on the fields. Malware uses timers often to schedule routine functions, such as contacting a C2 server or making sure a hidden process remains hidden. For more information, see [MoVP 4.1 Detecting Malware with GDI Timers](http://volatility-labs.blogspot.com/2012/10/movp-41-detecting-malware-with-gdi.html).

```
$ python vol.py -f laqma.vmem gditimers
Volatile Systems Volatility Framework 2.1_alpha
Thread   Process                     nID Rate(ms)   Countdown(ms) Func      
-------- -------------------- ---------- ---------- ------------- ----------
     696 csrss.exe:660            0x7ffe       1000           734 0xbf8012b8
    1648 explorer.exe:1624          0x15      60000         45109 0x00000000
    1480 svchost.exe:1064         0x7476      60000         16234 0x74f51070
     696 csrss.exe:660            0x7ffd      35000         25625 0xbf8f4d9a
    1648 explorer.exe:1624          0x19   86400000      70004672 0x00000000
    1764 VMwareTray.exe:1760         0x0       5000          4859 0x00000000
    1648 explorer.exe:1624           0xe   43200000      26805359 0x00000000
    1764 VMwareTray.exe:1760        0x11      60000         45859 0x00000000
     700 csrss.exe:660            0xfff5        100           100 0xbf807d00
     356 svchost.exe:1064            0x0     300000        131234 0x77532ebb
    2024 lanmanwrk.exe:920         0x2eb     600000        589578 0x00401fc8
    2024 lanmanwrk.exe:920         0x161       3000          1578 0x004010aa
    1648 explorer.exe:1624           0x0      60000         11922 0x00000000
     384 KernelDrv.exe:352          0x8b     600000        595359 0x00404c2b
     384 KernelDrv.exe:352          0x8c       3000          1359 0x004010aa
     384 KernelDrv.exe:352           0xd       2000          1359 0x00410850
```

# windows #

This command enumerates all windows (visible or not) in all desktops of the system. It walks windows in their Z-Order (i.e. front to back focus) starting at the desktops `spwnd` value (the foreground window). For each window it shows details on the window's title, class atoms, the owning thread and process, the visibility properties, the left/right/top/bottom coordinates, the flags and ex-flags, and the window procedure address. For more information on windows, see [MoVP 2.2 Malware In Your Windows](http://volatility-labs.blogspot.com/2012/09/movp-22-malware-in-your-windows.html).

```
$ python vol.py -f win7x64.dd --profile=Win7SP1x64 windows
Volatile Systems Volatility Framework 2.1_alpha
**************************************************
Window context: 1\WinSta0\Default

Window Handle: #40170 at 0xfffff900c06258a0, Name: Download: Microsoft Windows SDK 7.1 - Microsoft Download Center - Confirmation - Windows Internet Explorer
ClassAtom: 0xc193, Class: IEFrame
SuperClassAtom: 0xc193, SuperClass: IEFrame
pti: 0xfffff900c24c4c30, Tid: 680 at 0xfffffa8002007060
ppi: 0xfffff900c28c2320, Process: iexplore.exe, Pid: 2328
Visible: Yes
Left: -32000, Top: -32000, Bottom: -32000, Right: -32000
Style Flags: WS_MINIMIZE,WS_MINIMIZEBOX,WS_TABSTOP,WS_DLGFRAME,WS_BORDER,WS_THICKFRAME,WS_CAPTION,WS_CLIPCHILDREN,WS_SYSMENU,WS_MAXIMIZEBOX,WS_GROUP,WS_OVERLAPPED,WS_VISIBLE,WS_CLIPSIBLINGS
ExStyle Flags: WS_EX_LTRREADING,WS_EX_RIGHTSCROLLBAR,WS_EX_WINDOWEDGE,WS_EX_LEFT
Window procedure: 0x714f6f7a
```

# wintree #

This command enumerates windows in the same way as the `windows` command above, but it prints less verbose details so that the parent/child relationshop can be easily expressed in a tree form. Instead of a "flat" view, you can see which windows are contained within other windows.

```
$ python vol.py -f win7x64.dd --profile=Win7SP1x64 wintree
[snip]
.Debugging Tools for Windows (visible) hh.exe:1952 HH Parent
..#70422 (visible) hh.exe:1952 HH Child
...#90452 (visible) hh.exe:1952 SysTabControl32
....#a0202 (visible) hh.exe:1952 -
.....Found: 62 (visible) hh.exe:1952 Static
.....Select &topic: (visible) hh.exe:1952 Static
.....Type in the &word(s) to search for: (visible) hh.exe:1952 Static
.....Sea&rch titles only (visible) hh.exe:1952 Button
.....&Match similar words (visible) hh.exe:1952 Button
.....Search previous res&ults (visible) hh.exe:1952 Button
.....List1 (visible) hh.exe:1952 SysListView32
......#50164 (visible) hh.exe:1952 SysHeader32
.....&Display (visible) hh.exe:1952 Button
.....&List Topics (visible) hh.exe:1952 Button
.....#70424 (visible) hh.exe:1952 Button
.....#702cc (visible) hh.exe:1952 ComboBox
......#f038e (visible) hh.exe:1952 Edit
..#702ba (visible) hh.exe:1952 HH SizeBar
..#70420 (visible) hh.exe:1952 HH Child
...#a0478 (visible) hh.exe:1952 Shell Embedding
....#36029e (visible) hh.exe:1952 Shell DocObject View
.....#9013e (visible) hh.exe:1952 Internet Explorer_Server
..#18029a (visible) hh.exe:1952 ToolbarWindow32
```