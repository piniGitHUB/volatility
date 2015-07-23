

# Address Spaces #

This page will describe the interface used to implement address spaces (AS). An AS dictates how to access data in the storage format that contains the target system's RAM.

Volatility uses a stacked AS model. This approach allows a much needed layer of abstraction between the underlying file formats and the higher level plugins. For example, when you write a plugin, you don't need to worry about the differences (such as how data is stored, compressed, etc) between raw dumps, crash dumps, or hibernation files. All of that is handled within the AS.

Most often, a FileAddressSpace will be the lowest AS in the stack (unless you're working with something like firewire), since it interfaces directly with the memory dump file. If you're working with an x86 crash dump, there will be a WindowsCrashDumpSpace32 AS on top of the file AS, which provides parsing of the crash dump headers. Since crash dumps are paging address spaces, there will be yet another AS on top of the crash dump space (for example JKIA32PagedMemoryPae) which reads the page tables and translates virtual addresses to physical offsets.

The diagram below shows a simple example of how the AS layers work together.

```
*****************************
|          Plugins          | 1) request to read 0xffdf0000
*****************************
|  JKIA32PagedMemoryPae AS  | 2) translates address to 0x41000 using DTB
*****************************
|       Crash Dump AS       | 3) pass down the request to read 0x41000 
*****************************
|          File AS          | 4) access data at offset 0x41000 of the file
*****************************
```

Another way to visualize the AS stacking is to break into a [volshell](CommandReference22.md) and inspect the layering. For example:

```
$ python vol.py -f ~/Desktop/memory/win7.dmp --profile=Win7SP0x86 volshell
Volatile Systems Volatility Framework 2.2_alpha
Current context: process System, pid=4, ppid=0 DTB=0x185000
Welcome to volshell! Current memory image is:
file:///Users/Michael/Desktop/memory/win7.dmp
To get help, type 'hh()'
>>> self.addrspace
<volatility.plugins.addrspaces.intel.JKIA32PagedMemoryPae object at 0x100798950>
>>> self.addrspace.base
<volatility.plugins.addrspaces.crash.WindowsCrashDumpSpace32 object at 0x1042c6ed0>
>>> self.addrspace.base.base
<volatility.plugins.addrspaces.standard.FileAddressSpace object at 0x100798a90>
```

# Base Class #

All address spaces should inherit from the volatility.addrspace.BaseAddressSpace base class (either directly or indirectly).  This class maintains all the standard functions available to an address space which a full address space implementation should overload.

## Address Space Ordering ##

All available address spaces are instantiated against the provided `location` URI (determined from `volatility.conf.ConfObject().LOCATION`), in order (determined by the `order` attribute of the address space) from 0 upwards until an address space succeeds.  The list is then traversed again this time with a `base` address space just determined.  This process continues until all remaining address spaces fail.  If no address space was successful then an error is raised.  If at least one address space succeeds, it will be returned to the calling function.

## Attributes ##

  * `base`: The underlying address space to operate on, this is passed in by the constructor.

  * `profile`: The profile for the system being analyzed, this is set automatically based on `volatility.conf.ConfObject().PROFILE` and contains information about operating system structures for the system to be analyzed (such as Windows XP or Mac OS X, etc).

  * `name`: Most address spaces provide a name attribute, which offers a descriptive name of the address space in question (such as the filename for a file, or the bus and port node names for an ieee1394/firewire bus).

  * `order`: This determines which order address spaces are tried, so that those that are more likely to succeed correctly, or can better identify whether they can operate on the underlying data, can be chosen first.

  * `dtb`: The Directory Table Base (CR3) value if the AS is a paging space

  * `pae`: A boolean indicator if the AS is for PAE or Non-PAE

## Functions ##

### Constructor ###

The `__init__` function for any address space should accept an existing (base) address space on which the address space being constructed will operate.  The lowest (physical) address spaces, such as File or ieee1394/firewire, take a `base` of None, whilst all other address spaces (those that provide a logical view of an existing address space, such as a process address space or those that convert a file format such as a Hibernation file or Crash Dump) will act on a non-None `base`.

Classes inheriting directly from a physical address space can use the `layered` boolean parameter to specify to the underlying constructor that they should not halt if provided with a non-None _base_ value.

The constructor should establish any necessary variables for use by any methods specified in the class that require state be maintained (such as the mode or filename for file spaces, or node and bus information for ieee1394/firewire spaces).

If the constructor is called with the `astype` parameter set to "physical", higher level address spaces (those interpreting a physical address space) should raise an assertion error.

```
    assert astype != 'physical', "Explanation (user requested physical address space)"
```

### read ###

This function takes an `addr` parameter (which may be long or 0) and a `length` parameter (which again may be long or 0) and should read from the offset specified by `addr` within the address space to the offset specified by `addr + length` and return a byte string of the values returned.

**Note**: the returned value may be shorter than that specified by length, and all functions calling read directly should verify the returned length of data.  Address spaces can return gaps in data where the information cannot be read, or is not provided by the underlying system.

### zread ###

Some address spaces offer a zread function that will return 0's in any location that cannot be read, others provide this functionality as part of the read function. The most common scenario for using zread is when you're dealing with a paging address space (such as kernel or process memory) and you want all data within a certain range. If the range consists of multiple pages, and one or more of the pages are not memory resident (because they're paged to disk) then zread will pad all unavailable pages with 0's to retain the orignal size of the requested range.

### is\_valid\_address ###

This function accepts an `addr` parameter, and should return a boolean stating whether the requested address is valid for the address space or not. For a paging AS, an address is valid if its within a memory-resident page (this includes pages in transition). If an address within process memory is not allocated or allocated but paged to disk, this function will return False.

### write (optional) ###

This function does not necessarily need to be overridden since the BaseAddressSpace's function will raise the appropriate exception, but if so, it should accept an `offset` parameter, and a `data` parameter.  When called the byte string `data` will be written to the offset `offset` and flushed to the underlying system.  If the address space merely carries out address translation, then the underlying address space's write function should be called with the appropriate parameters.  If the data cannot be written (not enough space available, for example) or failed to write then an appropriate exception should be raised.

**Note**: This function should verify that `volatility.conf.ConfObject().WRITE` is True before attempting to change the underlying data in any way, it should otherwise return False.

Write support is not enabled by default, and requires both a command line parameter, and then a phrase to be typed manually into the program.  This should prevent any accidental enabling, since it cannot be automatically enabled without modification to the program source code.  As such, if write support can be added to an address space, it should, and the user will be protected from making changes to the underlying forensic data by the rest of the program (assuming the `volatility.conf.ConfObject().WRITE` is checked in the write function itself).

### vtop ###

If the AS is a paging / virtual memory AS then it should provide a `vtop` function for translating virtual addresses to physical offsets. The function returns either None (no valid mapping) or the offset in physical memory where the address maps.

### get\_available\_addresses ###

Returns a generator of address ranges as (offset, size) covered by this AS and sorted by offset. The address ranges produced must be disjoint (no overlaps) and not be continuous (there must be a gap between two ranges).

### get\_available\_pages ###

Return a list of lists of available memory pages. Each entry in the list is the starting virtual address and the size of the memory page.

# AS Recipes #

## Examine the stacked AS ##

In this example, you can see how address spaces stack. We'll use a virtualbox image for the test. Notice how you can reference ".base" to reach the base address space and traverse down the stack.

```
$ python vol.py -f winxpsp2x86_vbox.elf volshell
Volatile Systems Volatility Framework 2.3_beta
Current context: process System, pid=4, ppid=0 DTB=0x39000
To get help, type 'hh()'
>>> hh()

Use self.addrspace for Kernel/Virtual AS
Use self.addrspace.base for Physical AS
Use self.proc to get the current _EPROCESS object
  and self.proc.get_process_address_space() for the current process AS
  and self.proc.get_load_modules() for the current process DLLs

[...]

For help on a specific command, type 'hh(<command>)'
>>> self.addrspace
<volatility.plugins.addrspaces.intel.IA32PagedMemory object at 0x104a2c990>
>>> self.addrspace.base
<volatility.plugins.addrspaces.vboxelf.VirtualBoxCoreDumpElf64 object at 0x10123fb10>
>>> self.addrspace.base.base
<volatility.plugins.addrspaces.standard.FileAddressSpace object at 0x10123fd90>
>>> self.addrspace.base.base.base
```

## Read an address in every process ##

This example shows how to read a specific address in every process. We'll use the same virtualbox image as above and it is done inside volshell. Notice we call get\_process\_address\_space() on an _EPROCESS to acquire the private address space for the process. We can then read(), zread(), or write() with the AS object. You can also call the is\_valid\_address() methods, etc. In the example below, the address 0x1000000 is valid in all but the first three processes and contains an MZ executable header. For the first three that say None, the address is either not allocated or the data is swapped to disk (not available in the memory dump)._

```
>>> for proc in win32.tasks.pslist(self.addrspace):
...   process_space = proc.get_process_address_space()
...   data = process_space.read(0x1000000, 2)
...   print "Memory for Pid {0}: {1}".format(proc.UniqueProcessId, data)
... 
Memory for Pid 4: None
Memory for Pid 464: None
Memory for Pid 564: None
Memory for Pid 588: MZ
Memory for Pid 632: MZ
Memory for Pid 644: MZ
Memory for Pid 856: MZ
Memory for Pid 960: MZ
Memory for Pid 996: MZ
Memory for Pid 1212: MZ
Memory for Pid 1280: MZ
Memory for Pid 1496: MZ
Memory for Pid 180: MZ
Memory for Pid 488: MZ
Memory for Pid 260: MZ
Memory for Pid 1260: MZ
Memory for Pid 1168: MZ
Memory for Pid 352: MZ
```

## Enum all pages in a process ##

To enumerate all pages in a process, you can use the get\_available\_pages() function after acquiring a process AS.

```
>>> cc(pid = 1212)
Current context: process svchost.exe, pid=1212, ppid=632 DTB=0x9fe7000
>>> process_space = self.proc.get_process_address_space()
>>> for page, size in process_space.get_available_pages():
...   print hex(page), hex(size)
... 
0x10000 0x1000
0x20000 0x1000
0x30000 0x1000
0x7d000 0x1000
0x7e000 0x1000
0x7f000 0x1000
0x80000 0x1000
0x81000 0x1000
0x90000 0x1000
0x91000 0x1000
[snip]
```