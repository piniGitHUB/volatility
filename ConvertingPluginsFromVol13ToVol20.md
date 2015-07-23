# Introduction #

There are many plugins already written for volatility 1.3, and this guide will help with converting existing volatility 1.3 plugins over to the new 2.0 framework.



# Basic Conversion #

## Namespaces ##

The forensics namespace is now the volatility namespace, so lines such as:

```
from forensics.win32.tasks import * 

class MyPlugin(forensics.commands.command):
```

should now read:

```
from volatility.win32.tasks import * 
import volatility.commands

class MyPlugin(volatility.commands.command):
```

Note that in previous versions most modules imported most other modules, so that volatility.commands.command was valid, even though it was not explicitly imported.  In more recent versions of volatility, it is strongly advised to only import the required modules,

```
  import volatility.win32.tasks as tasks
  import volatility.commands as commands

  class MyPlugin(commands.command):
```

## Address Spaces ##

Previously, in volatility 1.3, functions such as `load_and_identify_image` would be used to return a virtual address space object with which to work, and `FileAddressSpace` would be used to scan through a flat address space.  Each plugin was responsible for loading the appropriate address space and error checking the results.

In volatility 2.0, there is a single loading function which attempts to stack as many address spaces as possible on top of each other.  Meaning that rather than:

```
   def execute(self):
     (addr_space, symtab, types) = load_and_identify_image(self.op, self.opts)
```

in newer versions, this would be written as:

```
   def execute(self):
     addr_space = utils.load_as(self._config)
```

and

```
     flat_address_space = FileAddressSpace(filename)
```

would be:

```
     flat_address_space = utils.load_as(self._config, as_type = 'physical')
```

## Accessing Process Address Spaces ##

Previously accessing features of various objects would take an additional function call and did not allow direct access to the object's members.  In volatility 2.0, the new object model allows most parameters to be accessed directly, and adds supporting functions for common tasks on these objects.

In this example from volatility 1.3, most of the code is taken up calling auxiliary functions to get the list of tasks, find a particular process id, then access the directory table base of the process and finally create a new process address space based on the directory table base just discovered.

```
    (addr_space, symtab, types) = load_and_identify_image(self.op, self.opts)

    all_tasks = process_list(addr_space, types, symtab)

    task = process_find_pid(addr_space,types, symtab, all_tasks, opts.pid)[0]

    directory_table_base = process_dtb(addr_space, types, task)
    process_address_space = create_addr_space(addr_space, directory_table_base)
```

In volatility 2.0, the number of auxiliary functions required is much reduced.  Also, when objects are returned (such as `all_tasks`) they can now be interrogated directly, and treated as a standard python object.  Here all tasks is filtered by directly requesting each task's `UniqueProcessId` field.  Finally the task itself features a helper method `get_process_address_space` that automatically determines its own directory table base, and returns an address space based on that.

```
    addr_space = utils.load_as(self._config)

    all_tasks = win32.tasks.pslist(addr_space)

    task = [t for t in all_tasks if t.UniqueProcessId == self._config.PID][0]

    process_address_space = task.get_process_address_space()
```

## Command-line Parameters ##

In volatility 1.3, command line options were added using standard optparse syntax, and was added in a specific function called parser.  When options were needed they could be accessed using `self.opts`.

In volatility a few subtle but important changes have been made.  Firstly, config options should now be setting in the plugin's `__init__` function.  All plugins accept a `config` object (which should be passed to the subconstructor), and this features an `add_option` function.  The `add_option` for `config` objects behaves very similarly to optparse, however it always takes a long option, which will be used as the parameter name, and a short option must be specified explicitly.  In any function after initialization, the `config` object will feature the appropriate parameter name (in capitals to differentiate it from other methods or attributes of the `config` object).  Further, certain characters (such as -) will be converted to a value that can be used for python variable names.

```
  def parser(self):
    self.op.add_option('-l', '--log-file',
           help = 'save results to a file',
           action = 'store', type = 'string',
           dest = 'log')
  ...
  print self.opts.log
```

would now be written as:

```
  def __init__(self, config):
    config.add_option('LOG-FILE', short_option = 'l',
            help = 'save results to a file',
            action = 'store', type = 'string')           
    commands.command.__init__(self, config)
  ...
  print self._config.LOG_FILE
```

## Objects ##

The new object model makes accessing data much simpler.  In the following example, taken from the volatility 1.3 code, the function takes an offset to a process structure and an address space, and returns the exit time of the process.

```
   def process_exit_time(addr_space, types, task_vaddr):
     (exit_time_offset, tmp) = get_obj_offset(types, ['_EPROCESS', 'ExitTime'])    
     exit_time = read_time(addr_space, types, task_vaddr + exit_time_offset)
     if exit_time is None:
         return None
     exit_time = windows_to_unix_time(exit_time)
     return exit_time
```

Would now be written as:

```
     def process_exit_time(addr_space, task_vaddr):
       task = obj.Object("_EPROCESS", offset = task_vaddr, vm = addr_space)
       return task.ExitTime
```

As we can see in volatility 2.0, this is greatly simplified for several reasons:

  1. The address space contains a profile, which knows about all the various types
  1. An object's structure members can be accessed directly...
  1. ...meaning no need to mess around with offsets.
  1. Each object is aware of its own type, meaning no specific functions are necessary to read specific values (such as time)...
  1. ...nor to convert them into the appropriate output format.

In fact, in general this function would be unnecessary, because a plugin would have a task object, rather than a task\_vaddr, and so could access task.ExitTime directly.

## Split Execute function ##

In volatility 1.3, all plugins were written as a class featuring an `execute` function, which would be run and would be responsible for all processing and output, after which volatility would exit.

In volatility 2.0, there is still an `execute` function which can be overridden if required, but by default this function first calls `calculate` which should return a single result (currently this can be a list, a generator or any other data structure as required).  The results of this are then passed with an output file descriptor to a `render_text` function (other render functions can be written, but since all volatility 1.3 plugins tended to produce text, this is the only output format we will cover here).

It should also be noted that where print was used, this not easily allow results to be saved out to files, or easily distinguish between user feedback and actual results.  In volatility 2.0, all output is written to the `outfd` file descriptor, which is file-like object that may be standard out, or may be a file, or some other pipe that accepts results.

Finally, the [coding style guide](StyleGuide.md) recommends the use of the format function over the deprecated % symbol for string formatting.

So, what once was:

```
   def execute(self):
     data = generate_results_somehow()
     print "%08x" % data
```

would now read:

```
   def calculate(self):
     return generate_results_somehow()

   def render_text(self, outfd, data)
     outfd.write("{0:08x}".format(data))
```

## Help Messages ##

To provide a description of the plugin in volatility 1.3, a `help` function existed, which would return a short string used to describe the plugin.  In volatility 2.0 the help function has become a class function (one that returns the same value for every instance of the plugin), and so will no longer allow overriding as supported by 1.3.  However, it's no longer necessary because the default help function in volatility uses the plugin's own docstring to return the appropriate value.

```
  class MyPlugin(forensics.commands.command):
    def help(self):
      return "A plugin that mcjibberates the floosimacapacitor of a process"
```

would now be written as:

```
  class MyPlugin(commands.command):
    """A plugin that mcjibberates the floosimacapacitor of a process"""
```

# General comments #

Many of the library functions present in volatility 1.3 have changed, usually to make use of the new object framework.  However, almost all of the functionality present in volatility 1.3 is present in 2.0, and no longer requires helper functions to access.  The [source code](http://code.google.com/p/volatility/source/browse) should be well commented, but if it's not then please [file a bug](http://code.google.com/p/volatility/issues/list) and we'll improve it!