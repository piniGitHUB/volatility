# Introduction #

This page documents the things we want to accomplish in the 2.0 branch, so we can a) keep track of them, and b) people new to the project can find things to work on.

# To Do for 2.0 #

## Completed Tasks ##

  1. ~~Clear out [issue 1](https://code.google.com/p/volatility/issues/detail?id=1)~~
  1. ~~Auto-generate XPSP2 vtypes to unify variable naming~~
  1. ~~Implement caching in any cachable areas of the framework~~
    * ~~Still requires BlockingCacheNodes and some testing~~
  1. ~~Test suites/unit tests~~
  1. ~~Add in profile (OS) dependent default variables (DTB/KPCR, etc)~~
    * ~~Done by:~~
      * ~~implementing constant/algorithmic vtypes for profile-specific signatures~~
    * ~~Goals for 2.0 are:~~
      1. ~~DTB finder plugin~~
      1. ~~KPCR finder plugin~~
  1. ~~Stabilize the interfaces for ASes/Scanners/Plugins/etc~~
    * ~~These seem to be relatively stable, but this should also be a long term goal~~
  1. ~~Documentation, documentation, documentation!~~
  1. ~~Profile (OS) dependent default variables:~~
    * ~~KDDEBUGGER\_DATA64 finder plugin~~
  1. ~~Add caching to other functions and test~~

  * ~~Convert over some malware plugins~~

## Miscellaneous Todo ##

  * Convert psscan3, objtypescan, symlinkobjscan (tasks carried over from the deprecated [Plugins page](http://code.google.com/p/volatility/wiki/Plugins))

## Longterm Tasks ##

Please see TodoFuture for long term tasks.