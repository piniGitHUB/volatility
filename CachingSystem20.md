# The volatility Caching Subsystem #

The volatility caching subsystem has the following design goals:

  1. Ability to cache arbitrary objects - The allows complex objects to be cached for later retrieval. For example, objects may be as simple as constants for KPCR addresses, to entire x86 page translation tables, or even hibernation decompression datastructures. To achieve this we use the standard python pickle system. In many use cases, the cache needs to facilitate persistant memoising of functions and generators (more on that below).
  1. Cached objects are stored by a hierarchical key namespace. Keys are specified in a URL notation. By default, relative URLs are interpreted relative to the memory image location (the value of the --location option). This scheme allows us to specify both global (per installation) and per image keys. For example given an image located in /tmp/foobar.img:
    1. [file:///tmp/foobar.img/kernel/debugging/KPCR](file:///tmp/foobar.img/kernel/debugging/KPCR) refers to this image's KPCR location.
    1. [file:///tmp/foobar.img/address_spaces/memory_translation/pdpte](file:///tmp/foobar.img/address_spaces/memory_translation/pdpte) refers to the cached page tables.
    1. http://www.volatility.org/schema#configuration/renderer specifies the currently configured renderer (i.e. its a global setting).
  1. Storage of the cache is abstracted and selectable via the --cache\_engine configuration variable. This allows the separation from the concerete storage of the cache and the abstraction of the cache in a running process.

## Abstraction of Cache ##

Within the running volatiltiy framework the cache appears as an
abstract tree with nodes inherited from the CacheNode class:

```
class CacheNode:
    def __init__(self, name, parent, payload = None):
        ''' Creates a new Cache node under the parent. The new node
        will carry the specified payload
        '''

    def add_child(self, child):
        ''' Adds the child to our children list. If the child already
        exists, we simply replace it. '''

    def __str__(self):
        ''' Produce a human readable version of the payload '''

    def update_payload(self, payload):
        ''' Update the current payload with the new specified payload '''

    def dump(self):
        ''' Dump the node to disk for later retrieval. This is
        normally called when the process has exited. '''

    def get_payload(self):
       ''' retrieve this node's payload '''
```

In order to check the cache, plugins issue the Cache.Check() function:

```
def Check(url, callback = None, cache_node_class = CacheNode):
    ''' Traverse the cache tree and retrieve the stored CacheNode.

    If there is no such stored CacheNode and callback is specified,
    attempt to create it using the cache_node_class with the payload
    returned from the callback. If callback is not specified we just
    return None.'''
```

## Decorators ##

You can also use the cache decorator to cache the results of any
function - this is probably the easiest way to apply caching to
existing code. For example, suppose we want to cache the results of
the psscan plugin:

```
class psscan(commands.command):
....
   @cache("/scanners/psscan")
   def calculate(self):
       .....
```

This will automatically create the CacheNode at the specified tree
location (note that since the URL is given as a relative URL it is
based at the current value of the --location - that means it applies
to the current memory image only).

Note that since calculate() returns a generator, the decorator will
also return a generator - It will not iterate over the calculate
method unnecessarily, but will yield results immediately. This does
not compromise performance in the case of a cache miss. Unfortunately
this also means that if the generator is stopped prematurely, we are
unable to cache the result set in the general case. This is the only
caveat on caching generators.

## Storage classes ##

The cache system discussed above can be thought of as an abstract
construct in the process memory. To make it persistant on disk we have
the storage class (which can be selected using the --cache\_engine
directive). The following cache engines are implemented:

### File Storage ###

This is the default cache engine. We simply maintain a directory
structure which corresponds to the URL of the key after applying the
appropriate filesystem safe escaping operation. Objects are stored in
stand alone files using the pickle module.

### Zip Storage ###

This storage is essentially the same as the File storage above, except
that the cache directory for each image file is maintained in a Zip
file stored at the --cache\_direcory directive with the same filename
as the image and a .zip extension.

## Use cases ##

The following common use cases are discussed:

  1. Dynamic address spaces. In some address spaces memory address mappings can not be cached since they change all the time. For example in the firewire address space, it is incorrect to cache any page translations or scanning results etc. This is easily achieved by having the firewire address space store a BlockingCacheNode() instance at critical tree nodes. These prevent new nodes from being inserted into the tree and force a cache miss whenever any keys are searched under these nodes. Note that this still allows the cache to store the locations of things which might not change, even for live memory analysis, such as KPCR locations.
  1. History logging and audit logs. Currently volatility works by running the framework multiple times on the same plugin with different command line options. This can be audited using the caching system by storing the current command line in a specific location using a specific CacheNode. This implementation can be used to append new commandlines to the same key. Configuration options can also become sticky in this way and remember the same values they had previously. This avoid users having to append many command line arguements (i.e. having to specify --profile, --kpcr, --dtb on every command line).
  1. Unit tests.  Unit tests can be easily implemented using the caching subsystem as follows:
    * A test() method is added to each plugin. Usually this is actually the same as calculate().
    * This method is decorated to be cached under the "/tests/pluginname" key (i.e. relative to the current image). The CacheNode implementation is TestCacheNode which implements a special update\_payload() method. The TestCacheNode also ensures that cache miss always occurs (by implementing a get\_payload() method which returns None).
    * The update\_payload() method ensures that the old payload and the new payloads are the same (if they are generators we ensure each member is the same as well - using the eq method).
> > The overall result is that unit tests can be run on any image as normal. If the particular test was never run on the image, we just cache the result of the plugin. If on the other hand, the result was already run on this image, the old result is compared to the new result and if a discrepancy is detected, an exception is raised.
> > This testing framework is easy to implement and automatically guards against regression bugs. Since we use the eq method of arbitrary objects, its also not limited to testing text string matches. For example, the object framework defines two objects are being equal if they are of the same type and they point at the same address. Even if the textual representation of the object's printouts has changed between versions, as long as the same objects are found in both cases no regressions will be reported.
  1. Reporting framework. By having a persistant caching framework we now have the concept of a volatility analysis session. In other words, each new execution of volatility adds new information to what we know about the image. This new information is stored in the cache tree. We can actually produce a full report from the cache tree by traversing all the CacheNodes and calling their str() methods.
> > If caching is introduced via decorators, the CacheNode already knows about the render() method of the plugin and can automatically generate the output from the plugin (this is very fast as the calculate is received from the cache). We therefore can generate a full report of all the plugins very quickly automatically.
> > By default CacheNodes have an empty str() methods, so things like pas2kas lookup tables are not reported. Specialised reporting functions can be made if needed by implementing str() functions as needed.