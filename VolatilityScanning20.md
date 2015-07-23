# Scanning Framework #

A useful analysis of memory is to try to find objects that remain in memory, but are currently unlinked or unreachable through list traversal techniques. For example, we might want to find residues of processes which have terminated, and therefore are removed from the list of running processes. Once the process is terminated, the EPROCESS structure is removed from process lists, but might still remain in unallocated memory for quite some time after being terminated by the system. Similarly a rootkit might be able to unlink the process from the EPROCESS structure, yet the process might continue running - this is a common way of hiding processes.

Scanning for various memory structures is a technique which is effective against such hiding methods. The idea is that we test each byte of memory as a candidate in representing the structure we want and run a number of sanity tests on it to make sure it actually is such a structure. Therefore, we do not traverse any lists, and even if the process is terminated or unlinked we still find it.

## Methodology ##

This section describes how one would implement a memory scanner for EPROCESS as an example. The next section describes the specific implementation in volatility.

For an EPROCESS to be considered valid, we might require the following conditions:

  1. `_EPROCESS.Pcb.Header.Type == 0x03` and `eprocess.Pcb.Header.Size == 0x1b`
  1. `_EPROCESS.Pcb.DirectoryTableBase` must be aligned to 0x20
  1. `_EPROCESS` thread list points to the kernel Address Space (Both Flink and Blink for `eprocess.ThreadListHead`)
  1. `_EPROCESS.WorkingSetLock` and `_EPROCESS.AddressCreationLock` look valid

We start off at the begining of the virtual space and check each byte against these conditions. If any of these conditions dont match we continue on with the next byte. If all conditions match for a particular offset, this is a potential candidate for an `_EPROCESS`.

### Optimization ###

The first thing thats obvious is that since all tests have to match, failing any test will allow us to not consider this current byte offset. Therefore we can order the tests such that simpler tests can be made first, while more complex tests happen later, providing the simple tests passed. This allows us to shortcut performing complex tests in cases where its immediately obvious that the structure can not possibly match since the simple test has failed.

In our case the first test checks that `_EPROCESS.Pcb.Header.Type` is exactly 0x03. It should be immediately obvious that since this test will always fail when the particular offset is not 0x03, we can simply search forward for the next 0x03 at that offset - completely ignoring all bytes in between. So a further optimization is that the first test can skip a bunch of data for us which is obviously not going to match, and save us testing each byte in between.

So these are the most crucial optimizations:
  1. Allow us to order the tests such that we put the fast, simple tests earlier, and stop checking if they fail.
  1. Allow each test to read ahead and discount a large range of bytes where it knows its not going to match.

## Implementation Details ##

Volatility provides two classes for implementing Scanners, both are automatically registered through the registry system. All you have do is extend the right classes in the plugin and they will be made available.

### Defining a Check ###

Specific checks are implemented using the `volatility.scan.ScannerCheck` base class. For example:

```
class DispatchHeaderCheck(scan.ScannerCheck):
    """ A very fast check for an _EPROCESS.Pcb.Header.

    This check assumes that the type and size of
    _EPROCESS.Pcb.Header are unsigned chars, but allows their
    offsets to be determined from vtypes (so they could change
    between OS versions).
    """
    order = 10
    
    def __init__(self, address_space, **kwargs):
        ## Because this checks needs to be super fast we first
        ## instantiate the _EPROCESS and work out the offsets of the
        ## type and size members. Then in the check we just read those
        ## offsets directly.
        eprocess = obj.Object("_EPROCESS", vm=address_space, offset=0)
        self.type = eprocess.Pcb.Header.Type
        self.size = eprocess.Pcb.Header.Size
        self.buffer_size = max(self.size.offset, self.type.offset) + 2
        scan.ScannerCheck.__init__(self, address_space)

    def check(self, offset):
        data = self.address_space.read(offset + self.type.offset, self.buffer_size)
        return data[self.type.offset] == "\x03" and data[self.size.offset] == "\x1b"

    def skip(self, data, offset):
        try:
            nextval = data.index("\x03", offset+1)
            return nextval - self.type.offset - offset
        except ValueError:
            ## Substring is not found - skip to the end of this data buffer
            return len(data) - offset

```

The check does some initialization work in its constructor (in this case, pre-calculates some offsets). The two interesting methods are:

  1. check(self, offset) returns True if the current offset is a possibility and False otherwise. Note that the actual data is read directly from the address space using self.address\_space - this allows the check to follow any potential pointers anywhere in the image (i.e. we are not restricted to the current buffer of data).
  1. skip(self, data, offset) returns the number of bytes that should be skipped to make it possible to get to a valid offset. We are provided a current buffer of data and the offset here refers to the buffer. This means we do not need to read anything from the Address space as we can use the pre-read buffer.

### Defining A Scanner ###

A scanner is just a set of such checks specified in order:

```
class PSScan(scan.BaseScanner):
    """ This scanner carves things that look like _EPROCESS structures.

    Since the _EPROCESS does not need to be linked to the process
    list, this scanner is useful to recover terminated or cloaked
    processes.
    """
    checks = [ ("DispatchHeaderCheck", {}),
               ("CheckDTBAligned", {}),
               ("CheckThreadList", {}),
               ("CheckSynchronization", {})
               ]
```

The checks are a list of tuples containing (name of test, argv). The argv is a dictionary which will be used to instantiate the check with (in case it takes parameters in its constructors). Note that the check is specified as a named string since the actual class implementation is retrieved from the registry system. This allows us to define a check in one plugin and use it in many other plugins without regard to the exact place its defined from.

### Using the scanner ###

To actually use the scanner we instantiate the scanner and then call its scan() method - causing it to iterate over all matches in the address space. The scanner will generate all offsets which are deemed to have matched. For example:

```
    def calculate(self):
        address_space = utils.load_as(astype = 'physical')

        for offset in PSScan().scan(address_space):
            yield obj.Object('_EPROCESS', vm=address_space, offset=offset)
```

You can do anything with the offsets returned - for example display them, save them to a file or even perform further checks on them.

### Pool Scanners ###

A very useful technique in windows memory analysis is the use of pool scanners. When a piece of memory is allocated in windows, its often allocated with a special tag which corresponds to the driver or subsystem to allocate the memory. This tag is used for debugging and is not really essential for use by the system (which is why many rootkits overwrite the tag or change it). Never the less, the tag is very useful for locating objects quickly. In volatility use use the PoolTagCheck to test for pool tags. For example:

```
class PoolScanSockFast(scan.PoolScanner):
    checks = [ ('PoolTagCheck', dict(tag = "TCPA")),
               ('CheckPoolSize', dict(condition = lambda x: x == 0x170)),
               ('CheckPoolType', dict(non_paged = True, free = True)),
               ## Valid sockets have time > 0
               ('CheckSocketCreateTime', dict(condition = lambda x: x > 0)),
               ('CheckPoolIndex', dict(value = 0))
               ]
    
```

In the above example, we see that the PoolTagCheck check takes a single argument of tag, which can be passed in the second member of the check tuple. Note that the PoolTagCheck implements a skip method, which as described above, allows us to skip all the data which does not contain the pool tag - this makes this scanner extremely fast.

Further checks include CheckSocketCreateTime which allows us to pass a callable to its constructor for checking the sanity of the creation time field - in this case we check that its greater than 0.

Note that this scanner extends scan.PoolScanner. That class simply allows us to specify a bunch of structures which follow the pool tag and appear before the object of interest such that the scan method yields the object of interest. For example, the default:

```
    preamble = [ '_POOL_HEADER', ]
```

Means we skip a pool header and yield the next object after that.

In this way pool tag scanning is actually the same as regular scanning - just employing a much faster condition. Since pool scanning is less reliable than more thorough scanning we can produce fast and slow versions of the same scanner by including the pool tag check for the fast check, and relying on more complex checks for slow scanner.

The above examples were taken from psscan.py.