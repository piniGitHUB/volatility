# Introduction #

This page gives a short description of objects, how to create them, how to use them and some common pitfalls.

# Objects in Volatility #

Objects are the base element in volatility, and any time that data is needed from an [Address Space](Vol20AddressSpaces.md) it will usually be accessed through an object.

All objects are derived from a _BaseObject_ class.  Objects are designed to behave as one would expect their python equivalents to behave (so an value that should be an int, should behave and have the same functions applicable to it, as a normal integer).  Unfortunately due to the only manner in which this can be implemented, it is not always the case, but these issues are covered in the common pitfalls section.

# Creating Objects #

All objects should be created using the Object factory function, so for instance for an `_EPROCESS` object, for example, we could use the following code to access its members:

```
   import volatility.obj as obj

   eproc = obj.Object("_EPROCESS", offset = ouroffset, vm = ouraddressspace)
   print eproc.UniqueProcessId
```

# Standard Objects #

This section describes the BaseObject type, from which all objects are derived, and also some of the standard generic object types.

## BaseObjects ##

> All BaseObject derived classes have the following attributes:

  * **obj\_vm** (read-only)
> The [Address Space](Vol20AddressSpaces.md) for the object.  This should be used for accessing all matters relating to the address space, including accessing the profile that the object was created under.
  * **obj\_offset** (read-only)
> The offset within the obj\_vm for this object.
  * **obj\_parent** (read-only)
> The parent object (for members of a struct).  This attribute is often None for objects created directly, rather than accessed through their parent.
  * **obj\_name** (read-only)
> The name of the object (often merely the type of the object).  It is not recommended this value be relied upon.
  * **obj\_native\_vm** (read-only)
> The [Address Space](Vol20AddressSpaces.md) that the object normally lives in.  This should usually be the same at obj\_vm (and in fact, defaults to it if not provided).  It is used when instantiating an object in and address space that it does not normally live in.  For example, instantiating an object at an offset in physical address space, that references other objects in kernel address space, vm should be set to physical\_as and native\_vm should be set to kernel\_as.  _New in Volatility 2.1_
  * **v()**
> A function that returns the value of the object.  Should the object not behave as you would expect, this function can be used to reach the underlying python type (so a raw integer, for an int type, and so on).  The result from this function will have no knowledge of the surrounding address space, or its own offset within that space.
  * **is\_valid()**
> Determines whether the offset of the object is valid within the address space it was created.
  * **cast(type)**
> This will create a new object located at the same offset and address space, but of a different type as passed in the string parameter.
  * **dereference\_as(type)**
> This will create a new object located at the value of the object (generally a pointer) in the same address space.  This is generally used to cast the result of a pointer lookup, such as `PointerToVoid.dereference_as("NormalType")`.
  * **dereference()**
> Only useful for pointers, this returns a new object based on the offset pointed to by the pointer.
  * **rebase()**
> Creates an object of the same type at a new offset within the address space.

## NoneObject ##

> A special object (which is `== None`) which contains a reason attribute to determine why the object was created.  Used to indicate error conditions without requiring all further computation to cease (unlike an exception) and upon which any operation will return another NoneObject with the same reason.
## NativeType ##
> These objects represent integer/numerical values, and are based on struct format characters (such as "L" for long).  These should behave in the same manner as their python native equivalents, but with the additional attributes (as mentioned above).  Unfortunately these cannot behave identically,
## BitField ##
> Since volatility natively works with byte strings, handling bits requires an explicit type.  This type accepts a start\_bit (0 by default) and an end\_bit (32 by default) and returns an integer number based on those bits on from the offset.
## Pointer ##
> This type of object points at another type of object (the `targetType`).  Whilst any of the standard functions called against this will apply to the pointer (such as `v()` which will return the offset the pointer is pointing at), any non-standard attributes (such as specific members, etc) will be passed through to the underlying type.  This means that pointers do not always have to be dereferenced to access underlying structures and members.
## Array ##
> This type takes a `count` and a `targetType` string (or `target` object of the appropriate class) and returns an object that can be indexed like a python list.  Note: `v()` will not return a value for this type, access the first element instead.
## CType ##
> This is the most type, and generally the base class of all non-simple [vtypes](Vol20vtypes.md).  It has the following functions:

> Suppose a CType called `ctype` contains several members (`a`, `b`, and `c`), then these could be accessed by requesting `ctype.a`, `ctype.b` and `ctype.c`.

  * **v()**
> Returns the offset of the CType.
  * **size()**
> Returns the size of the CType (it should be noted that this is taken from the size specified in the [vtype](Vol20vtypes.md) definition, and is not always accurate).
  * **m(membername)**
> Returns a specific ctype member.  Generally not used, since it is quicker to write and easier to read `thing.membername` than `thing.m("membername")`, and both are essentially equivalent.

# Defining Complex Objects #

It is possible to produce objects that have specific additional methods, or can process specific data.  Volatility 2.0 already contains several predefined examples of additional objects, such as String, Flags, Enumeration, [VolatilityMagic](Vol20VolatilityMagic.md), _UNICODE\_STRING and_LIST\_ENTRY.  The most commonly used complex object is the _EPROCESS object, which features additional functions._

To create a complex object, simply create a new class deriving from `BaseObject` (directly or indirectly).  If you intend to overlay an existing structure (such as a vtype's definition of a CType), then be sure to inherit from CType.

Finally ensure that the object is added to the profile's object\_classes dictionary.  An example is provided below:

```
  import volatility.obj as obj

  class _EProcess(obj.CType):
    def additional_function(self):
      return self.UniqueProcessId

  windows7profile.object_classes['_EPROCESS'] = _EProcess

  ...

  eproc = obj.Object('_EPROCESS', offset=eprocoff, vm=eprocaddressspace)
  print eproc.additional_function()

```

By associating the object with the name `_EPROCESS` which matches an existing vtype definition for the profile, the object will be created with all the members, and the additional (or overridden) functions defined.  This can be used to create helper functions (such as `_EPROCESS.get_process_address_space()`), or in the case of types such as WinTimeStamp, to override the v() functions to return a more suitable interpretation of the data read from the address space.

# Common Pitfalls #

### Issues using proxied methods ###

Whilst most objects attempt to appear like native python objects (such as integers and strings), unfortunately they only proxy the common functions, rather than actually inherit from the standard python type.  This causes problems for certain functions and can lead to unusual results.  For instance, attempting to add a python long to a NativeType will fail, but adding a NativeType to a long will succeed (because NativeTypes are aware of python types, but not vice versa).  As such, any exceptions encountered along these lines, swapping the ordering may solve the problem.

### Adding Complex Objects to Profiles ###

The object\_classes list is stored internally as a class attribute of the profile.  This means that if the `object_classes` class variable of a profile is changed or added to, it will alter **all** profiles of that type, including any subtypes that have not defined their own attribute (both attributes refer to the same object).  This is compounded when the object is mutable, as the object\_classes dictionary is.  This can cause great confusion when the same `object_classes` key is set in two different files:

windows7.py:
```
    class _EPROCESS(obj.CType):
      def from_module(self):
        print "Windows 7"

    general_windows_profile.object_classes['_EPROCESS'] = _EPROCESS
```

windowsXP.py:
```
    class _EPROCESS(obj.CType):
      def from_module(self):
        print "Windows XP"

    general_windows_profile.object_classes['_EPROCESS'] = _EPROCESS
```

Depending on the order that these files are loaded, **all** _EPROCESS objects will return "Windows 7" in response to_EPROCESS.from\_module, or they will **all** return "Windows XP".  It is therefore very import to only apply complex objects to the profile they pertain to, and not to an abstract or underlying profiles.  The proper method of altering the _EPROCESS object for Windows 7 would be as follows:_

windows7.py:
```
    class _EPROCESS(obj.CType):
      def from_module(self):
        print "Windows 7"
    
    class windows7profile(general_windows_profile):
      object_classes = copy.deepcopy(general_windows_profile.object_classes)

    windows7profile.object_classes['_EPROCESS'] = _EPROCESS
```

Also note that once the deepcopy has been performed, further changes to general\_windows\_profile's object\_classes will not be seen by the windows 7 profile.  As such, the addition of complex objects which vary between profiles should be carried out with caution.