# Introduction #

`VolatilityMagic` objects allow you to retrieve a value (either a constant or algorithmically generated value) from a profile.

# Parent class #

To keep conflicts between generated vtypes and `VolatilityMagic` values separate, a fixed CType of `VOLATILITY_MAGIC` is added to each profile.  The difference between this CType and any other normal CType is that this will **not** verify the address of its members in the underlying address space (since the values aren't read from the address space, but are instead constant or generated some other way).

# VolatilityMagic object #

This object has the following methods:

  * `__init__(value = None, configname = None)`: Initializer, which accepts a standard value to return (if None is provided then suggestions will be generated from `get_suggestions()`), and a configname, which will be used to look up a value passed in via the config, and return that instead of any other value provided to `v()`, or at the start of `get_suggestions()`.
  * `v()`: Returns the value of the object (either value passed during creation or `get_best_suggestion()`).
  * `get_suggestions()`: Returns a list of possible values (including any value specified during creation time, or any relevant config value), ordered best fit to worst fit.  This function is not intended to be overridden, please define `generate_suggestion` where required.
  * `generate_suggestions()`: Returns a list of possible values, ordered best fit to worst fit.  Intended to be overriden.
  * `get_best_suggestion()`: By default, returns the first item from get\_suggestion (or NoneObject if no suggestions are available).

# Examples #

`VolatilityMagic` objects are therefore defined like any other vtype.

## Simple Constant ##

The following example sets `VOLATILITY_MAGIC.DTBSignature` to be `\x03\x00\x1b\x00`.

```
'VOLATILITY_MAGIC' : [None, { 
    'DTB' : [ 0x0, ['VolatilityDTB', dict(configname = "DTB")]],
    'DTBSignature' : [ 0x0, ['VolatilityMagic', dict(value = "\x03\x00\x1b\x00")]],
}
```

## Returning Generated Values ##

To return generated values, create an object that inherits from `VolatilityMagic`, and which overrides one of the above functions.  So in the example of DTB finding:

```
class VolatilityDTB(VolatilityMagic):

    def generate_suggestions(self):
        offset = 0
        while 1:
            data = self.vm.read(offset, constants.SCAN_BLOCKSIZE)
            found = 0
            if not data:
                break

            while 1:
                found = data.find(str(self.parent.DTBSignature), found + 1)
                if found >= 0:
                    # (_type, _size) = unpack('=HH', data[found:found+4])
                    proc = obj.Object("_EPROCESS",
                                             offset = offset + found,
                                             vm = self.vm)
                    if 'Idle' in proc.ImageFileName.v():
                        yield proc.Pcb.DirectoryTableBase.v()
                else:
                    break

            offset += len(data)
```

Note that objects are created with an address space, so when creating the `VOLATILITY_MAGIC.DTB` object, you must pass in the address space you want scanned.  The offset isn't important, because `VOLATILITY_MAGIC` objects don't check their offset for validity.

`obj.Object('VOLATILITY_MAGIC', offset=0, vm=<vmtobescanned>)`

Also, since all `VOLATILITY_MAGIC` members have a common parent, other constants can be accessed by `self.parent` as seen above to retrieve the `DTBSignature`.  This allows the algorithm to stay the same between profiles, but still allow key constants to change between them.

Then overlay it on the VOLATILITY\_MAGIC class, as usual.

```
'VOLATILITY_MAGIC' : [None, { 
    'DTB' : [ 0x0, ['VolatilityDTB', dict(configname = "DTB")]],
}
```

## Creating configurable constants ##

A user may want to override a VolatilyMagic object (in case the initial suggestion isn't valid, or the user already knows the correct location and does not want to spend the time generating it again).  They can do this by passing the
`configname` parameter as shown in the above example.  Here a new **global** configuration object, called DTB will be created (without a short option).  If a value is ever specified for this option, then it will always be returned by the VolatilityMagic object, instead of any constant or generated value.

## Using existing Scanners ##

`generate_suggestions()` can implement new classes, so existing Scanner objects can easily be converted into `VolatilityMagic` objects:

```
class VolatilityKPCR(basic.VolatilityMagic):

    def generate_suggestions(self):
        scanner = KPCRScanner()
        for val in scanner.scan(self.vm):
            yield val
```