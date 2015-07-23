# Introduction #

This page provides information concerning the internals of volatility, that may be useful for those wishing to develop their own plugins.

**Note: this page and sub-pages should be considered a work in progress until otherwise noted. That means documentation may not be update to date with current APIs in the code base.**

# Details #

  * [Plugin Interface](PluginInterface22.md) - This document is where you should begin, as it provides the basic requirements of a plugin object.

  * [Address Spaces](AddressSpaces22.md) - Most plugins will want to act on a memory image as specified by the user, this can be accessed as an address space, which are described in this document.

  * [Objects](VolatilityObjects22.md) - Once an address space has been loaded, most plugins will begin accessing objects at offsets within the space. This document describes the object model, standard routines that can be used on objects and how to construct more complex objects.

  * [Coding Style Guide](StyleGuide.md) - A guide for those wishing to contribute code to the main volatility project, or who wish to ensure their plugins match those of the core plugins.