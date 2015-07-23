# Introduction #

This page provides information concerning the internals of volatility, that may be useful for those wishing to develop their own plugins.

# Details #

  * [Plugin Interface](PluginInterface20.md) - This document is where you should begin, as it provides the basic requirements of a plugin object.

  * [Converting Plugins from 1.3 to 2.0](ConvertingPluginsFromVol13ToVol20.md) - This document tells you how to convert plugins from older version of volatility to the 2.0 style and syntax.

  * [Address Spaces](AddressSpaces20.md) - Most plugins will want to act on a memory image as specified by the user, this can be accessed as an address space, which are described in this document.

  * [Objects](VolatilityObjects20.md) - Once an address space has been loaded, most plugins will begin accessing objects at offsets within the space. This document describes the object model, standard routines that can be used on objects and how to construct more complex objects.

  * [Profile-specific Constants/Algorithms](VolatilityMagic20.md) - Occasionally there will be a particular offset in memory (the `_KPCR`, for example) which is at a fixed location for some profiles, but that needs to be located algorithmically in other profiles. Volatility uses special objects called VolatilityMagic objects that can be used to access this information from a plugin without hard-coding the different possibilities into the plugin.

  * [Scanners](VolatilityScanning20.md) - This document will describe how scanners can be created to search through large address spaces efficiently to locate sections of memory of interest.

  * [Caching System](CachingSystem20.md) - This document describes how the caching system works in volatility 2.0.

  * [Coding Style Guide](StyleGuide.md) - A guide for those wishing to contribute code to the main volatility project, or who wish to ensure their plugins match those of the core plugins.