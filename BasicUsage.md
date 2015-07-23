# Basic Usage of Volatility 2.0 #

Volatility 2.0 has the ability to analyze Windows 2003 SP0/SP1/SP2, Vista SP0/SP1/SP2, Windows 2008 SP1/SP2 and Windows 7 SP0/SP1 images in addition to Windows XP SP2 and SP3.  In order to analyze an image that is not Windows XP SP2, you should provide the correct profile when running Volatility commands.  You can obtain the profile from Volatility by typing:

```
$ python vol.py --info
```

In addition to scanners, plugins and other items that Volatility "knows" about, you should see a section for profiles:

```
PROFILES
--------
VistaSP0x86  - A Profile for Windows Vista SP0 x86
VistaSP1x86  - A Profile for Windows Vista SP1 x86
VistaSP2x86  - A Profile for Windows Vista SP2 x86
Win2003SP0x86 - A Profile for Windows 2003 SP0 x86
Win2003SP1x86 - A Profile for Windows 2003 SP1 x86
Win2003SP2x86 - A Profile for Windows 2003 SP2 x86
Win2008SP1x86 - A Profile for Windows 2008 SP1 x86
Win2008SP2x86 - A Profile for Windows 2008 SP2 x86
Win7SP0x86   - A Profile for Windows 7 SP0 x86
Win7SP1x86   - A Profile for Windows 7 SP1 x86
WinXPSP2x86  - A Profile for Windows XP SP2
WinXPSP3x86  - A Profile for windows XP SP3
```


Therefore for all images except WinXPSP2x86 should have the profile defined at the commandline. A typical usage for Volatility can be seen below:

```
$ python vol.py [plugin] -f [image] --profile=[PROFILE]
```

Unlike Volatility 1.3, in 2.0 you can interchange the order of the arguments including the plugin name itself.  For example we could get the same results with the following command:

```
$ python vol.py -f [image] --profile=[PROFILE] [plugin]
```

Options with dashes must maintain their order however (e.g. -f `[image]`).  The above commands will run the given plugin on the given image using the given profile.

To get a list of available plugins and commandline options you can type:

```
$ python vol.py -h
```

You can type the following to get a usage for a particular plugin:

```
$ python vol.py [plugin] -h
```

If the profile is not given in the command line, the WinXPSP2x86 profile will be used.  A real example for getting the process listing from a Windows 7 image is shown below:

```
$ python vol.py -f win7.dd --profile=Win7SP0x86 pslist
```

If you are manually typing in commands, it may be easier to put the plugin at the end of the line so you can use the up-arrow and more easily replace the plugin name for each command.

## Other Output Options ##


Default output is to standard out.  Plugins may have other options that you can use or other output options such as html, sqlite or csv.

You can figure out what other options are supported for a plugin by typing:

```
$ python vol.py [plugin] -h
```


Output can be saved to a file by using the --output-file option and the type of output can be specified by the --output option:

```
[some output removed]

  --output=text         Output in this format (format support is module
                        specific)
  --output-file=OUTPUT_FILE
                        write output in this file
[some output removed]
```

A real example using mutantscandb from malware.py:

```
$ python vol.py mutantscandb -f win7.dd --output=html --output-file=mutants.html --profile=Win7SP0x86 -D artifacts.db
```

Here we can see that we are using html output and saving the output to a file called mutants.html

## Other Resources ##

For a list of plugins and their features look at FeaturesByPlugin

For a usage examples of each plugin look at CommandReference

For more details on commandlines look at CommandLineProcessing