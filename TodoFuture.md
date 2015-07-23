# Long Term Goals #

## Design ##

  * Consider output formats (UI/unified plugin data output)
    * Report output
    * Command-line (low-latency) output
    * Interactive use (separation of obj/ASs models from application/plugins)
    * GUI plugin result analysis
  * Examine performance/profiling and possibly develop C modules for some parts
  * Consider overhauling the config system
    * Potentially moving to argparse, to allow subcommand options specified by the plugins.
  * Further remove/reduce the use of globals to allow volatility to be used as a library.

## Practical ##

  * ~~Investigate Vista/Windows 7 hibernation work~~
  * ~~Write a raw2dump plugin (possibly dependent on write support)~~
  * Improve Hive AS integration
  * Allow module loading from http/other locations
  * Implement/improve linux support
    * ~~Requires linux overlay/types~~
    * ~~Requires linux plugins~~
    * Might require shuffling windows specific global features (--kpcr, etc)
  * ~~Support arches other than x86~~
  * Conversion to Python 3+
  * Integrate pdbparse into the framework?
  * Create "scan3" versions of the scanners, so accurate structure locators like psscan3, but for sockscan and driverscan, etc.
  * pagefile analysis

# Features for current Milestone #

Since the current milestone is 2.1, please see [Todo21](Todo21.md).