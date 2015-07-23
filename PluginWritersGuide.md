# Introduction #

This table provides information concerning the internals of volatility 2.0, that may be useful for those wishing to develop their own plugins.

# Details #

  * **[Plugin Interface](Vol20PluginInterface.md)** - This document is where you should begin, as it provides the basic requirements of a plugin object.

  * **[User-specified Options](CommandLineProcessing.md)** - This document discusses how to accept user input based on command line parameters, and to define new parameters for use.

  * **[Address Spaces](Vol20AddressSpaces.md)** - Most plugins will want to act on a memory image as specified by the user, this can be accessed as an address space, which are described in this document.

  * **[Objects](Vol20Objects.md)** - Once an address space has been loaded, most plugins will begin accessing objects are offsets within the space.  This document describes the object model, standard routines that can be used on objects and how to construct more complex objects.

  * **[Profile-specific Constants/Algorithms](Vol20VolatilityMagic.md)** - Occasionally there will be a particular offset in memory (the KernelProcessorControlRegister or KPCR, for example) which is at a fixed location for each profile, but that fixed location may change, or certain profiles need to be located algorithmically.  In Volatility 2.0, there are special objects called [VolatilityMagic](Vol20VolatilityMagic.md) objects that can be used to access this information from a plugin without hard-coding the different possibilities into the plugin.

  * **[Scanners](Scanners.md)** - This document will describe how scanners can be created to search through large address spaces efficiently to locate sections of memory of interest.

# Miscellaneous #

  * **[Coding Style Guide](StyleGuide.md)** - A guide for those wishing to contribute code to the main volatility project, or who wish to ensure their plugins match those of the core plugins.