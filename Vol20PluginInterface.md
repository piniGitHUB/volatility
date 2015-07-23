# Introduction #

This page will describe the interface used to implement standard volatility plugins.

# Base Class #

Plugins should inherit from the _commands.command_ base class, or any other plugin that descends from it.  A plugin (_command_ object) by default features the following functions:

  * `help`
  * `execute`
  * `calculate`

The `help` function should return a short string describing the plugin, by default this returns the plugin class docstring, and generally will not require overriding.

The `execute` function firsts calls the plugin's calculate function and then returns the results of calculate to an appropriate render function (based on the output command line parameter).  Again, this function should in general not be overridden.

The `calculate` function should carry out the main operation against any memory images being analyzed.  This function takes no arguments and returns a single "data" variable, which can be of any form as long as it is then successfully processed by the plugin's `render_<type>` functions.

## Options ##

Any additional command line parameters should be defined in the `__init__` function of the plugin (rather than outside of the plugin class) so that multiple plugins may make use of the same option identifiers.  These are handled in a very similar fashion to the optparse module that comes with python.  An add\_option function is available to specify a parameter name (--name), a short option (-n), and then the action/defaults for storing the variable.

```

   def __init__(self, config, *args):
       commands.command.__init__(self, config, *args)
       self._config.add_option('NAME', short_option='n', default=None,
                               help='Description of the NAME option',
                               action='store', type='str')

...

       if config.NAME == "blah":
           ...

```

If global command line options need to be defined by a plugin (and this should be extremely rare), this can be done by adding a static method to the plugin, which will be called when the plugins are initially loaded.  An example can be seen below:

```
   @staticmethod
   def register_options(config):
       config.add_option('NAME', short_option='n', default=None,
                         help='Description of the NAME option',
                         action='store', type='str')
```

A [complete description of option handling for plugins](CommandLineProcessing.md) is also available.

## Calculating ##

The most basic function required for most plugins is to load and access an address space.  This is now carried out by a stacked address space plugin mechanism.  The loading of an address space is carried out by the `utils.load_as` function.  More details on the stacking mechanism can be found on the [Address Spaces](Vol20AddressSpaces.md) page (see "determining address space ordering").

If a physical layer is required (rather than a paged/process address space), then the `astype` parameter can be provided with a value of "physical", and only physical layers will be returned.

## Rendering ##

The standard output/render type is `text`, and as such every plugin should define a `render_text` function.

Render functions accept a file descriptor (`outfd`) and the data object returned by the `calculate` function.  The file descriptor will operate just like a normal python file object, and normal use will involve the write function.

When outputting function values in a standard fashion, it is recommended to use `"{0}".format(value)`, over the deprecated `"%x" % value`.

**Note**: The file descriptor may not be a real file, but instead directly to the console that the program is run from (stdout).  As such results may be required in real time.  No output should be made in the calculate function, so to reduce the amount of time taken before being able to display the results a [python generator](http://docs.python.org/tutorial/classes.html#generators) should be used.

## Importing ##

Note that every class derived from commands.command, present in a module's namespace, will be registered as a plugin.  Two plugins with the same class name cannot be registered at the same time, therefore import plugin, address space, profile or object classes using:

```
from module import Class
```

are prohibited and must not be used.  If they are used, they will be added to the new module's namespace, be re-registered, and volatility will return a conflict error.  The correct method for importing plugins or other classes is as follows:

```
from long.module.name as shrtmdl

def SubClass(shrtmdl.Class):
   ...
```

For further information on this matter, please see [issue 36](https://code.google.com/p/volatility/issues/detail?id=36).