# Address Spaces #

This page will describe the interface used to implement new pluggable Address Spaces for use in Volatility 2.0.

## Base Class ##

All address spaces in Volatility 2.0 should inherit from the _BaseAddressSpace_ class found in _volatility.addrspace_ (either directly or indirectly).  This class maintains all the standard functions available to an address space which a full address space implementation should overload.

## Determining Address Space ordering ##

All available address spaces are instantiated against the provided `location` URI (determined from `volatility.conf.ConfObject().LOCATION`), in order (determined by the `order` attribute of the address space) from 0 upwards until an address space succeeds.  The list is then traversed again this time with a `base` address space just determined.  This process continues until all remaining address spaces fail.  If no address space was successful then an error is raised.  If at least one address space succeeds, it will be returned to the calling function.

## Attributes ##

  * `base`: The underlying address space to operate on, this is passed in by the constructor.

  * `profile`: The profile for the system being analyzed, this is set automatically based on `volatility.conf.ConfObject().PROFILE` and contains information about operating system structures for the system to be analyzed (such as Windows XP or Mac OS X, etc).

  * `name`: Most address spaces provide a name attribute, which offers a descriptive name of the address space in question (such as the filename for a file, or the bus and port node names for an ieee1394/firewire bus).

  * `order`: This determines which order address spaces are tried, so that those that are more likely to succeed correctly, or can better identify whether they can operate on the underlying data, can be chosen first.

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

Some address spaces offer a zread function that will return 0 in any location that cannot be read, others provide this functionality as part of the read function.

### is\_valid\_address ###

This function accepts an `addr` parameter, and should return a boolean stating whether the requested address is valid for the address space or not.

### write (optional) ###

This function does not necessarily need to be overridden since the BaseAddressSpace's function will raise the appropriate exception, but if so, it should accept an `offset` parameter, and a `data` parameter.  When called the byte string `data` will be written to the offset `offset` and flushed to the underlying system.  If the address space merely carries out address translation, then the underlying address space's write function should be called with the appropriate parameters.  If the data cannot be written (not enough space available, for example) or failed to write then an appropriate exception should be raised.

**Note**: This function should verify that `volatility.conf.ConfObject().WRITE` is True before attempting to change the underlying data in any way, it should otherwise return False.

Write support is not enabled by default, and requires both a command line parameter, and then a phrase to be typed manually into the program.  This should prevent any accidental enabling, since it cannot be automatically enabled without modification to the program source code.  As such, if write support can be added to an address space, it should, and the user will be protected from making changes to the underlying forensic data by the rest of the program (assuming the `volatility.conf.ConfObject().WRITE` is checked in the write function itself).