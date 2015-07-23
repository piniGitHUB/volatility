# Introduction #

The firewire [address space](Vol20AddressSpaces.md) in Volatility allows an investigator to access a running machine's physical memory and run any of the existing Volatility plugins against it.

Volatility's firewire support can use one of two implementations, depending upon the firewire stack in use by the kernel.  The Two Stacks will be discussed in the implementation section.

# Technique #

The following sections describe the technique used to read forensic information from a device over firewire.

### Masquerading as an SBP2 device ###

The investigator's machine must look as though it is an SBP2 device for a Windows computer to allow direct access to physical memory.  By default, linux is set to present itself as a 1394 network device.  These are not given full access to the physical memory of the target machine, therefore the CSR registers must be updated to appear as if they are an SBP2 device.

# Implementations #

## Forensic1394 / JuJu ##

The new firewire stack, and the [forensic1394](http://gitweb.freddie.witherden.org/?p=forensic1394.git;a=summary) library by Freddie Witherden make using volatility on a firewire device much simpler.

Prerequisites:
  * New (JuJu) Firewire stack compiled into kernel
  * [forensic1394](http://gitweb.freddie.witherden.org/?p=forensic1394.git;a=summary) installed

### Usage ###

Simply run volatility with the following command line:

```
volatility -l firewire://forensic1394/<devno> <plugin> [<plugin_opts>]
```

It will automatically set your firewire card into SBP2 mode, and allow the reading and writing of memory, thus enabling all plugins.

The devices should be numbered in order that they were connected to the system, so for instance if you were to connect a laptop, and then also a digital camera, the laptop would have a `<devno>` of 0, and the camera a `<devno>` of 1.

Please note, there are still limitations, such as reading beyond the existing memory size, which will cause the connected machine to Bluescreen or crash.

## Raw1394 / Old Firewire Stack ##

To interoperate with the old firewire stack, volatility makes use of [pythonraw1394](http://www.storm.net.nz/static/files/pythonraw1394-1.0.tar.gz) by Adam Boileau.  This means it is only available under a linux or BSD operating system with libraw1394 installed.

Prerequisites:
  * Old (ieee1394) Firewire stack compiled into kernel
  * libraw1394
  * [pythonraw1394](http://www.storm.net.nz/static/files/pythonraw1394-1.0.tar.gz)

### Setup ###

The _romtool_ program, packaged as part of pythonraw1394, can be used to alter the linux CSRs to those of another device.  The pythonraw1394 package includes an example ipod file _ipod.csr_ which is an SBP2 device.

New CSRs can be acquired by plugging into the remote device with the CSR to be copied and run the following commands (from the pythonraw1394 package).  _businfo_ first returns the port and node number of the available devices, and then _romtool_ can be used to read the other device's CSRs into a file.

```
businfo
```
```
romtool -o <port> <node> new.csr
```

An investigator's machine can be spoofed to appear as another type of firewire device by alter the CSRs.  This can be done from a saved copy of the CSR with the following command:

```
romtool -s <port> ipod.csr
```

Here the port number is that of the investigator's firewire card, rather than the target machine's bus.

A tool included with pythonraw1394 can be used to copy memory from a remote firewire device once the target computer believes the investigator's computer is an SBP2 device.

```
1394memimage <port> <node> output.dump [<range>]
```

Note that the optional range parameter should be provided, since if the program attempts to copy more data than is available, the machine will likely blue screen.

The following command will attempt to copy 10K of data and therefore determine quickly whether access is available or not.

```
1394memimage <port> <node> output.dump [0-1K]
```

### Usage ###

Once read/write access is operating correctly, the device can be accessed through volatility by running the following command:

```
volatility -l firewire://raw1394/<port>/<node> <plugin> [<plugin_opts>]
```

# Limitations #

Firewire can only access the first 4Gb of physical memory on any machine.  This means that for machines capable of accessing more than 4Gb of memory, any image taken, or access gained directly by Volatility, may be inconsistent or reference inaccessible areas of memory.

**Not all plugins are safe**: It should be noted that reading beyond the bounds of physical memory (ie, reading the 4th Gb of a machine with 2 Gb of memory) will likely cause the device to Bluescreen or crash.  At the moment it is not possible to specify the size of a firewire address space, even if know, although we hope to resolve this in the future.