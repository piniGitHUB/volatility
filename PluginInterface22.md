

# Introduction #

A plugin is implemented as a Python class. The class name is the name of the plugin. The class must inherit from the commands.Command base class, common.AbstractWindowsCommand (for windows-only plugins), or common.AbstractLinuxCommand (for linux-only plugins). You can also inherit from another existing plugin which descends from one of the aforementioned classes.

The base class implements the following functions which can be overridden for customizing your plugin's behavior:

  * `__init__`
  * `register_options`
  * `help`
  * `execute`
  * `calculate`
  * `render_text`

The `__init__` function can be overridden if you need to register plugin-specific command-line options. If you want to install global options, the `register_options` function can be used instead, but that is quite rare.

The `help` function should return a short string describing the plugin and generally will not require overriding because by default it returns the plugin class docstring.

The `execute` function firsts calls the plugin's `calculate` function and then yields the results of `calculate` to an appropriate render function (based on the --output command-line parameter).  Again, this function should in general not be overridden.

The `calculate` function should carry out the main operation against any memory images being analyzed.  This function takes no arguments and yields a "data" variable, which can be of any form (for example a list, a tuple, dictionary, single object, etc) as long as it is then successfully processed by the plugin's render function(s).

# Plugin Example #

Let's begin writing a very simple plugin.

1. **Save an empty file** to volatility/plugins/myplugin.py. Alternately, if you don't want to write to the core volatility directories, you can save your plugin anywhere (for example on your desktop) as long as you then point the --plugins command-line parameter to that location when it comes time to invoke it.

2. **Create your plugin class**. Our example will be a windows-only plugin and we want to invoke it on command-line as myplugin. Note we also provide a description for the plugin.

```
import volatility.plugins.common as common 

class MyPlugin(common.AbstractWindowsCommand):
    """This is my example plugin"""
```

At this point, your plugin should show up in the output of --help like this:

```
$ python vol.py --help | grep myplugin
Volatile Systems Volatility Framework 2.2_alpha
		myplugin       	This is my example plugin
```

3. **Add the calculate function** and acquire an address space. This is the most basic function required for most plugins. To access an AS, you can use the `utils.load_as` API which by default returns a paged/kernel address space. However, if you need a physical space, the `astype` parameter can be provided with a value of "physical", and only physical layers will be returned. Assuming we want our example plugin to list processes, we'll request a kernel AS. Our code now looks like this:

```
import volatility.plugins.common as common 
+ import volatility.utils as utils

class MyPlugin(common.AbstractWindowsCommand):
    """This is my example plugin"""

+    def calculate(self):
+        kernel_space = utils.load_as(self._config) 
```

4. **Configure the `calculate` function** to yield some results based on data it carves from the address space. Generating the list of active processes is easy, because there are already APIs for doing so. For example, just import `tasks.pslist` as shown below:

```
import volatility.plugins.common as common 
import volatility.utils as utils
+ import volatility.win32.tasks as tasks

class MyPlugin(common.AbstractWindowsCommand):
    """This is my example plugin"""

    def calculate(self):
        kernel_space = utils.load_as(self._config) 

+        for process in tasks.pslist(kernel_space):
+            yield process
```

5. **Create the renderer**. All plugins should support rendering the output in text form. That means they'll require a `render_text` function. Render functions accept a file descriptor (`outfd`) and the data objects yielded by the `calculate` function.  The file descriptor will operate just like a normal python file object, and normal use will involve the write function. Let's say you just want to print the process names and pids to your terminal. Our code now looks like this:

```
import volatility.plugins.common as common 
import volatility.utils as utils
import volatility.win32.tasks as tasks

class MyPlugin(common.AbstractWindowsCommand):
    """This is my example plugin"""

    def calculate(self):
        kernel_space = utils.load_as(self._config) 

        for process in tasks.pslist(kernel_space):
            yield process

+    def render_text(self, outfd, data):
+        for process in data:
+            outfd.write("Process: {0}, Pid: {1}\n".format(process.ImageFileName, process.UniqueProcessId))
```

Now you can test your plugin and see how it works:

```
$ python vol.py -f ~/Downloads/cridex.vmem myplugin
Volatile Systems Volatility Framework 2.2_alpha
Process: System, Pid: 4
Process: smss.exe, Pid: 368
Process: csrss.exe, Pid: 584
Process: winlogon.exe, Pid: 608
Process: services.exe, Pid: 652
Process: lsass.exe, Pid: 664
Process: svchost.exe, Pid: 824
.....
```

# Rendering Text Tables #

Sometimes its easier to visualize data when its neatly organized in a table fashion. Thus instead of using outfd.write directly from the render function, you can utilize the existing table\_header and table\_row APIs. Here's a modified version of the above plugin's render\_text function. Note we added a column for the process offset (location of the `_EPROCESS` in kernel memory). The specified spacing for this column is "[addrpad](addrpad.md)" which is essentially an address padded to 4 bytes for x86 systems and 8 bytes for x64 systems.

```
    def render_text(self, outfd, data):
        self.table_header(outfd, [("Offset", "[addrpad]"),
                                  ("Process", "20"),
                                  ("Pid", "8")])
        for process in data:
            self.table_row(outfd, process.obj_offset, 
                                  process.ImageFileName, process.UniqueProcessId)
```

The output now looks like this:

```
$ python vol.py -f ~/Downloads/cridex.vmem myplugin
Volatile Systems Volatility Framework 2.2_alpha
Offset     Process              Pid     
---------- -------------------- --------
0x823c89c8 System                      4
0x822f1020 smss.exe                  368
0x822a0598 csrss.exe                 584
0x82298700 winlogon.exe              608
0x81e2ab28 services.exe              652
0x81e2a3b8 lsass.exe                 664
0x82311360 svchost.exe               824
.....
```

# Rendering Other Formats #

You can easily output results in other formats besides text and text tables. For example, CSV, HTML, XML, or JSON. You'll just need to add a new rendering function to the plugin class and then specify --output=format when you call the plugin. For example let's add CSV rendering:

```
+    def render_csv(self, outfd, data):
+        for process in data:
+            outfd.write("{0:#x},{1},{2}\n".format(process.obj_offset, 
+                       process.ImageFileName, process.UniqueProcessId))
```

Now you can output data as "csv" format:

```
$ python vol.py -f ~/Downloads/cridex.vmem myplugin --output=csv
Volatile Systems Volatility Framework 2.2_alpha
0x823c89c8,System,4
0x822f1020,smss.exe,368
0x822a0598,csrss.exe,584
0x82298700,winlogon.exe,608
0x81e2ab28,services.exe,652
0x81e2a3b8,lsass.exe,664
0x82311360,svchost.exe,824
....
```

# Adding Plugin Options #

You may have noticed our example plugin class above doesn't use `__init__` anywhere. That's because there's no need to modify the behavior of the underlying base class's initialization routines. If your plugin requires additional command-line parameters, then you will need to override `__init__` and add them to the config object that's passed into the plugin. These are handled in a very similar fashion to the optparse module that comes with python.  An add\_option function is available to specify a parameter name (--name), a short option (-n), and then the action/defaults for storing the variable.

Assume you wanted to filter processes by name. Let's modify the plugin to accept a -n or --name parameter.

```
...

class MyPlugin(common.AbstractWindowsCommand):
    """This is my example plugin"""

+    def __init__(self, config, *args, **kwargs):
+        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
+        self._config.add_option('NAME', short_option = 'n', default = None,
+                               help = 'Process name to match',
+                               action = 'store', type = 'str')

    def calculate(self):
        kernel_space = utils.load_as(self._config) 

        for process in tasks.pslist(kernel_space):
+            if (not self._config.NAME or 
+                           self._config.NAME.lower() == str(process.ImageFileName).lower()):
                yield process
```

The first thing you'll notice after making this change is that now when you ask for help with the plugin, a new option with your description will appear:

```
$ python vol.py -f ~/Downloads/cridex.vmem myplugin --help
Volatile Systems Volatility Framework 2.2_alpha
.....
  -g KDBG, --kdbg=KDBG  Specify a specific KDBG virtual address
  -k KPCR, --kpcr=KPCR  Specify a specific KPCR address
  -n NAME, --name=NAME  Process name to match
```

Go ahead and see if it works:

```
$ python vol.py -f ~/Downloads/cridex.vmem myplugin --name="explorer.exe"
Volatile Systems Volatility Framework 2.2_alpha
Offset     Process              Pid     
---------- -------------------- --------
0x821dea70 explorer.exe             1484
```

# Inheriting Plugin Options #

If you inherit from an existing plugin rather than a base class, you'll be inheriting that plugins options as well. For example, `taskmods.DllList` registers a --PID option which is a comma-separated list of process IDs to filter by and it includes a function `filter_tasks` which performs the filtering action. Instead of re-implementing all that yourself, you can just inherit from `taskmods.DllList` and either call `filter_tasks` from your own calculate function (method 1) or just customize the render function, accepting the calculate function from `taskmods.DllList` (method2).

Here's method 1:

```
import volatility.plugins.taskmods as taskmods
import volatility.win32.tasks as tasks

class MyPlugin(taskmods.DllList):
    """This is my example plugin"""

    def calculate(self):
        kernel_space = utils.load_as(self._config)
    
        # Leverage the filter_tasks API from DllList 
        for process in self.filter_tasks(tasks.pslist(kernel_space)):
            yield process

    def render_text(self, outfd, data):
        for process in data:
            outfd.write("Process: {0}, Pid: {1}\n".format(process.ImageFileName, process.UniqueProcessId))
```

Now you can supply a -p or --PID parameter to myplugin and it will automatically only yield those processes to the render function.

```
$ python vol.py -f ~/Downloads/cridex.vmem myplugin -p 4,368,584
Volatile Systems Volatility Framework 2.2_alpha
Process: System, Pid: 4
Process: smss.exe, Pid: 368
Process: csrss.exe, Pid: 584
```

Here's method 2:

```
import volatility.plugins.taskmods as taskmods

class MyPlugin(taskmods.DllList):
    """This is my example plugin"""

    def render_text(self, outfd, data):
        for process in data:
            outfd.write("Process: {0}, Pid: {1}\n".format(process.ImageFileName, process.UniqueProcessId))
```

The only difference between the two method is that Method 1 allows you to perform other actions on the address space before yielding the objects to the rendering function. If all you need is a simple list of processes that match your pids, Method 2 is quicker and easier.

# Adding Global Options #

If global command line options need to be defined by a plugin (and this should be extremely rare), this can be done by adding a static method to the plugin, which will be called when the plugins are initially loaded.  An example can be seen below:

```
   @staticmethod
   def register_options(config):
       config.add_option('NAME', short_option='n', default=None,
                         help='Description of the NAME option',
                         action='store', type='str')
```

For example, the commands.Command base class adds a global option for --verbose which is then available in all other plugins.

# Restricting Plugins Per Profile #

Sometimes you may have a plugin that works on one profile but not another. This can cause confusion among users who aren't familiar with the plugins (they may try to run a Linux-only plugin on a Windows memory dump and see ugly backtraces). Thus there are a few ways you can restrict which profiles your plugin applies to.

We've already discussed one way - and that is inheriting from one of the Abstract command base classes. For example if your plugin inherits from AbstractWindowsCommand, the plugin will be hidden from the output of --help when a non-Windows profile is being used. You can get even more granular and prevent the plugin from being shown on various versions of the same operating system.

For example, the plugin below will only be displayed for 32-bit Windows. As you can see, we're filtering based on the profile's metadata fields which include os (windows, linux, mac, android), memory\_model (32-bit or 64-bit), major, and minor (such as 5.1 for XP, 6.1 for Windows 7).

```
class MyPlugin(common.AbstractWindowsCommand):
    """This is my example plugin"""

    @staticmethod
    def is_valid_profile(profile):
        """Returns True if the plugin is valid for the current profile"""

        return (profile.metadata.get('os', 'unknown') == 'windows' and
                profile.metadata.get('memory_model', '32bit') == '32bit')
```

The `is_valid_profile` method only prevents the plugin from being displayed when users type --help. Its entirely possible that a user tries to execute a command anyway. To blacklist commands forcefully, you must modify the `calculate` function to check `is_valid_profile` and then abort. For example let's say you absolutely don't want the plugin running on anything besides 32-bit windows:

```
+ import volatility.debug as debug 

class MyPlugin(common.AbstractWindowsCommand):
    """This is my example plugin"""

    @staticmethod
    def is_valid_profile(profile):
        """Returns True if the plugin is valid for the current profile"""

        return (profile.metadata.get('os', 'unknown') == 'windows' and
                profile.metadata.get('memory_model', '32bit') == '32bit')

+    def calculate(self):
+        kernel_space = utils.load_as(self._config)
+        if not self.is_valid_profile(kernel_space.profile):
+            debug.error("This command does not support the selected profile.")
+        ......
```