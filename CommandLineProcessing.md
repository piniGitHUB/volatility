This page describes features available since Volatility 2.0 beta

# Introduction #

Volatility is a modular system with plugins doing much of the work. Sometimes its necessary to have a plugin require some additional information and the easiest way is to get it through command line options. This page describes do you go about adding new command line parameter parsing for your plugin.

# Overview #

First we need to have an overview of command line processing in volatility. When you type:

```
$ vol.py -h
Volatile Systems Volatility Framework 2.0
Usage: Volatility - A memory forensics analysis platform.

Options:
  -h, --help            list all available options and their default values.
                        Default values may be set in the configuration file
                        (/etc/volatilityrc)
  --conf-file=/home/mic/.volatilityrc
                        User based configuration file
  -d, --debug           Debug volatility
  --info                Print information about all registered objects
  --plugins=./plugins   Additional plugin directories to use (colon separated)
  --profile=WinXPSP2    Name of the profile to load
  -l LOCATION, --location=LOCATION
                        A URN location from which to load an address space
  --output=text         Output in this format (format support is module
                        specific)
  --output-file=OUTPUT_FILE
                        write output in this file
  -v, --verbose         Verbose information
  -f FILENAME, --filename=FILENAME
                        Filename to use when opening an image
  --tz=TZ               Sets the timezone for displaying timestamps
  --use-old-as          Use the legacy address spaces
  -w, --write           Enable write support
  --dtb=DTB             DTB Address
  --cache-dtb           Cache virtual to physical mappings

	Supported Plugin Commands:

		bioskbd        	Reads the keyboard buffer from Real Mode memory
		connections    	Print list of open connections
		connscan2      	Scan Physical memory for _TCPT_OBJECT objects (tcp connections)
		crashinfo      	Dump crash-dump information
		datetime       	Get date/time information for image
    ....
```

Volatility is telling us about all the options it knows about. The options have a long name and sometimes a short name, a description and a default value which is also listed. Option processing is broken into 2 steps:

  1. A module registers a specific option
  1. When the module requires the option, the framework retrieves it from the following places in this order:
    1. Command line - the option can be specified on the command line
    1. Environment variables - the environment variable which corresponds to the option is checked. For example a dtb address can be set by doing: export VOLATILITY\_DTB=0x12345
    1. The configuration file which is normally found in "volatilityrc" in the current directory or ~/.volatilityrc or a user specified file (using the --conf-file option).
    1. Finally a default value can be suggested in code for a sensible value for the parameter. This ensures some value is always set.

This is useful since the way one processes images is normally by setting many parameters and running the many plugins on the same image using the same parameters. This allows one to set the parameters in the environment and then just run lots of modules on the same image without needing to crowd the command line with similar parameters. For example:

```
$ export VOLATILITY_PROFILE=Win7SP0x86
$ export VOLATILITY_LOCATION=file:///tmp/myimage.img
$ ./vol.py pslist
$ ./vol.py files

etc
```

Example contents of ~/.volatilityrc can be seen below:

```
[DEFAULT]
PROFILE=Win7SP0x86
LOCATION=file:///tmp/myimage.img
```

Note also that to avoid confusion, the (-h) option also lists the current value of each parameter so you can easily check what value is being used (from the environment or the config files).

## Registering a new command line option ##

All plugins and address spaces are passed a config option, which they can use to determine information about their calling environment.

The config variable is (currently) a singleton object which gets access to the configuration system. In order to use it we need to register an option:

```
        config.add_option("HIVE-OFFSET", short_option='o',
                          default = None, type='int',
                          help = "Offset to registry hive")

```

We need to define the long option, the short\_option is optional, the default value can be set in the code to ensure some value is always set for that parameter (even if its None). The type of the variable is specified and will be used to convert the variable to it. Finally a help message is defined which will show when the user does -h. Note that this system is derived from python's standard optparse module and further documentation of that module can be used.

The option can be used at any time:
```
if config.HIVE_OFFSET:
    hives = [config.HIVE_OFFSET] 
```

There are two types of options in general. The first type are system wide, these can be used between modules, and are commonly needed for all modules. Examples include --filename, --dtb or --output.

To set global options, the config.add\_option() call can be made in the plugin module body in a staticmethod called register\_options:

```
   class Plugin(commands.command):

     @staticmethod
     def register_options(config):
       config.add_option(...)
```

This will add the config option once the plugin is loaded into the system, i.e. at the start of every run. Therefore your option will appear even when another plugin command is selected.

Some parameters should only be registered for your own plugin - these are private options. Generally plugin writers should only use private options to prevent polluting the whole program with their options.

To set private options, the options should only be declared after the command in your plugin was selected to run. When a user selects to run your command, the class will be instantiated, and that is a good place to add the config option:

```
    def __init__(self, config, *args):
        ## Add the option only after we got selected
        config.add_option("HIVE-OFFSET", short_option='o',
                          default = None, type='int',
                          help = "Offset to registry hive")

        ## Call the baseclass constructor
        hs.hivescan.__init__(self, config, *args)
```

The above examples were taken from hivelist.py