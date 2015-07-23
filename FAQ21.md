

# General #

## What is the latest stable version of Volatility ##

The latest stable version is 2.1. It was released August 2012. The code in available in the following formats, all of which can be found on the [Downloads page](http://code.google.com/p/volatility/downloads/list).

  * Source code in zip or tar archive (all platforms).
  * Pyinstaller executable (Windows only).
  * Standalone executable (Windows only).

If you plan to develop your own plugins or address spaces, or examine Volatility's internals, choose the source code or Pyinstaller executable. Both options will give you access to the Python source files. You must already have a Python interpreter and dependent libraries installed. To just be up and running in a matter of seconds, and you're on a Windows analysis system, choose the standalone executable - it comes packaged with Python and the dependencies. The standalone executable is portable and can be run from USB drives or CDROMs.

## What's new in 2.1 ##

Please see the [VolatilityRoadmap 2.1 Release](http://code.google.com/p/volatility/wiki/VolatilityRoadmap#Volatility_2.1_(Official_x64_Support))

## What is the latest development version of Volatility ##

The VolatilityRoadmap should tell you everything you need to know about upcoming release dates and features. We always make an effort to keep the code in [svn trunk](http://code.google.com/p/volatility/source/checkout) as stable as possible, while preparing it for the next release. For that reason, we may fork and perform development in a separate [branch](http://code.google.com/p/volatility/source/browse/#svn/branches) and then merge it back in with trunk after the necessary testing.

Currently, there are several major new features under development in separate branches. For example, the [linux-trunk](http://code.google.com/p/volatility/source/browse/#svn/branches/linux-trunk) and [mac-trunk](http://code.google.com/p/volatility/source/browse/#svn/branches/mac-trunk) provide memory analysis capabilities for linux and mac osx systems, respectively. They are planned to be merged with trunk for the 2.2 release (October 2012). Also, the [technology preview](http://code.google.com/p/volatility/source/browse/#svn/branches/scudette) branch is being designed in preparation for the exciting new features coming in 3.0.

## What operating systems are supported ##

The 2.1 release supports the following:

  * Microsoft Windows:
    * 32-bit Windows XP Service Pack 2 and 3
    * 32-bit Windows 2003 Server Service Pack 0, 1, 2
    * 32-bit Windows Vista Service Pack 0, 1, 2
    * 32-bit Windows 2008 Server Service Pack 1, 2 (there is no SP0)
    * 32-bit Windows 7 Service Pack 0, 1
    * 64-bit Windows XP Service Pack 1 and 2 (there is no SP0)
    * 64-bit Windows 2003 Server Service Pack 1 and 2 (there is no SP0)
    * 64-bit Windows Vista Service Pack 0, 1, 2
    * 64-bit Windows 2008 Server Service Pack 1 and 2 (there is no SP0)
    * 64-bit Windows 2008 `R2` Server Service Pack 0 and 1
    * 64-bit Windows 7 Service Pack 0 and 1

Development branches as described above contain support for the following additional systems:

  * Mac OS X:
    * 32-bit and 64-bit 10.6.x Snow Leopard (partial support only)
    * 32-bit and 64-bit 10.7.x Lion (full support)
    * 32-bit and 64-bit 10.8.x Mountain Lion (partial support only)
  * Linux and Android:
    * 32-bit Linux 2.6.9 - 3.x
    * 64-bit Linux 2.6.9 - 3.x

## What memory dump formats are supported ##

The following formats for Windows memory dumps are supported:

  * Raw dd style, such as those produced by most live acquisition tools and VMware's .vmem files
  * Microsoft Crash Dump
  * Hibernation (hiberfil.sys) files
  * EWF (requires installation of [libewf](http://sourceforge.net/projects/libewf/))

Volatility will automatically determine which format your file is in and treat it accordingly. However, if you wish to convert your sample to raw format, use [imagecopy](http://code.google.com/p/volatility/wiki/CommandReference21#imagecopy). You can also convert from raw to a crash dump with [raw2dmp](http://code.google.com/p/volatility/wiki/CommandReference21#raw2dmp).

In addition, the 2.2 release of Volatility is planned to support:

  * VirtualBox ELF64 core dumps (thanks to Philippe Teuwen)
  * VMware snapshot and suspended state files - .vmss and .vmsn (thanks to Nir Izraeli)
  * LiME (Linux Memory Extractor) format for Linux and Android devices (thanks to Joe Sylve)

## Can Volatility acquire physical memory ##

Traditionally, the goal of Volatility is to analyze physical memory, not acquire it. Thus, all versions up to and including 2.1 do not have any acquisition capabilities. We do however, support acquisition of memory over firewire with the [imagecopy](http://code.google.com/p/volatility/wiki/CommandReference21#imagecopy) plugin, since that is just a generic copy of any address space into a raw memory dump format.

## Is there a maximum memory dump size ##

There is technically no limit. We've heard reports of Volatility handling 30-40 GB images on both Windows and Linux host operating systems. More recently, a member of the Volatility community tested successfully on an 80 GB RAM dump. If you routinely analyze large memory dumps and would like to supply some performance benchmarks for the FAQ, please let us know.

## How can I report a bug ##

You can use the [issue tracker](http://code.google.com/p/volatility/issues/list). Please collect details on the system from which the memory dump was acquired, including OS, service pack, amount of memory installed, and memory model (x86 vs x64). Depending on the problem, you may be asked other details such as your analysis system (windows, linux, mac), python version, samples of output from Volatility plugins - anything to help reproduce the bug.

# Installation/Usage #

## How do I install Volatility ##

If you're using the standalone Windows executable, no installation is necessary - just run it from a command prompt. No dependencies are required, because they're already packaged inside the exe.

If you're using the Pyinstaller (Windows-only) executable, double click and follow through with the installation instructions (which basically consists of clicking Next a few times and then Finish). You must already have a working Python 2.6 or 2.7. Also see below for the dependency libraries.

If you downloaded the zip or tar source code archive (Windows, Linux, OSX) there are two ways to "install" the code:

1) Extract the archive and run setup.py. This will take care of copying files to the right locations on your disk. Running setup.py is only necessary if you want to have access to the Volatility namespace from other Python scripts (for example if you plan on [importing Volatility as a library](http://code.google.com/p/volatility/wiki/BasicUsage21#Using_Volatility_as_a_Library)). Pros: easy use as a library. Cons: more difficult to upgrade or uninstall.

2) Extract the archive to a directory of your choice. When you want to use Volatility just do python /path/to/directory/vol.py. This is a cleaner method since no files are ever moved outside of your chosen directory, which makes it easier to upgrade to new versions when they're released. Also, you can easily have multiple versions of Volatility installed at the same time, by just keeping them in separate directories (like /home/me/vol2.0 and /home/me/vol2.1). Pros: clean, easy to run multiple versions, easy to upgrade or uninstall. Cons: more difficult to use as a library.

Regarding dependencies, for the most comprehensive plugin support, you should install the following libraries. Keep in mind this does not apply to the standalone Windows executable with dependent libraries included.

  * [Distorm3](http://code.google.com/p/distorm/) - Powerful Disassembler Library For x86/AMD64
  * [Yara](http://code.google.com/p/yara-project/) - A malware identification and classification tool
  * [PyCrypto](https://www.dlitz.net/software/pycrypto/) - The Python Cryptography Toolkit

If you do not install these libraries, you may see a warning message to raise your awareness, but all plugins that do not rely on the missing libraries will still work properly.

## How do I upgrade from an older version ##

If you used setup.py to install Volatility, the files will be placed in a few standard locations. For example:

```
$ sudo python setup.py install
....
byte-compiling /usr/local/lib/python2.6/dist-packages/volatility/fmtspec.py to fmtspec.pyc
byte-compiling /usr/local/lib/python2.6/dist-packages/volatility/utils.py to utils.pyc
running install_scripts
copying build/scripts-2.6/vol.py -> /usr/local/bin
changing mode of /usr/local/bin/vol.py to 755
running install_data
creating /usr/local/contrib/plugins
copying contrib/plugins/example.py -> /usr/local/contrib/plugins
copying contrib/plugins/psdispscan.py -> /usr/local/contrib/plugins
....
creating /usr/local/contrib/plugins/addrspaces
copying contrib/plugins/addrspaces/ewf.py -> /usr/local/contrib/plugins/addrspaces
copying contrib/plugins/addrspaces/ewf-python.py -> /usr/local/contrib/plugins/addrspaces
running install_egg_info
Writing /usr/local/lib/python2.6/dist-packages/volatility-2.1.egg-info
```

Unfortunately there is no uninstaller, and if you simply try to run setup.py for a new version of Volatility, you may end up with some mixed source files which will surely lead to trouble. So before you install a new version of Volatility, remove everything the previous setup.py created:

```
$ sudo rm -rf /usr/local/lib/python2.6/dist-packages/volatility
$ sudo rm `which vol.py`
$ sudo rm -rf /usr/local/contrib/plugins 
```

Now you can run the setup.py for your new Volatility version. As stated above, please remember setup.py is only necessary if you plan on importing Volatility as a library from other Python scripts. If you just want to use Volatility, no installation is necessary (just extract the archive and run vol.py inside).

## How do I use Volatility ##

If you're using the standalone Windows executable, run it from a command prompt:

```
C:\> volatility.exe -h 
```

If you're using the Pyinstaller executable, run it using the python interpreter. The main vol.py script will be in the Scripts folder for your python version. Note: for convenience you might want to add the "C:\Python??" directory to your PATH environment variable.

```
C:\> python C:\Python27\Scripts\vol.py -h 
```

If you're using the zip or tar source code archive, just run the vol.py script in the top level directory. For convenience on Linux/OSX systems, you might set up a command alias for "/usr/bin/python /path/to/vol.py" to be just "volatility" - then you can always type "volatility" from any directory.

```
$ python vol.py -h 
```

The -h/--help option shows the available plugins and other command-line parameters. It should be enough to get you started. If not, please read the BasicUsage21 or CommandReference21 wiki pages.

# Contact #

## Who wrote/is writing Volatility ##

See the AUTHORS.txt and CREDITS.txt files provided with the Volatility source code.

## How can I contribute to Volatility ##

If you have documentation, code or ideas to contribute, use one of the following methods:

  * Through the [Google Code web interface](http://code.google.com/p/volatility/issues/list)
  * Through IRC: #volatility on freenode
  * Through the [Volatility Mailing List](http://lists.volatilesystems.com/mailman/listinfo)