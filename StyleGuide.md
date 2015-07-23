# Introduction #

Here's a brief guide to coding styles for adding to volatility.  They mostly follow [PEP 8](http://www.python.org/dev/peps/pep-0008), and also pylint (although with certain rules ignored including C0111, C0103, C0301, W0511, [R0201](https://code.google.com/p/volatility/source/detail?r=0201), [R0903](https://code.google.com/p/volatility/source/detail?r=0903) and W0142).  The reasoning behind each decision should be given after the guideline.

Please note, this is just a guideline, and if anyone feels like changing any of these, please do.  If everyone's happy, then someone can remove this paragraph.  If you have any additions you'd like to make, again please make them.

Volatility currently requires python-2.6 or greater.

# Details #

  * Spacing: 4 space indents, no tabs.
    * Consistency, PEP8
  * Multiple statements on one line are discouraged.
    * PEP8
  * Always try to use if x == None rather than if x is None
    * The New Object model overrides equivalence, allowing NoneObjects to be equal to None
    * Note that if you want to test for validity you should use if x: ....  This is because x might be an actual real object (i.e. not equivalent to None) but actually invalid. For example it might be an invalid pointer.
  * Importing specific objects or functions is discouraged.
    * It pollutes the namespace and causes confusion.  Previous versions of volatility allowed people to import functions from files they weren't defined in.
  * "from blah import `*`" is **strongly** discouraged.
    * Again, namespace pollution and inappropriate imports.
  * Module names should be lower case, Class names should be CamelCase, function names should be lower\_case\_with\_underscores).
    * PEP8 using most historically common style (hence function names aren't mixedCase).
  * Whitespace on either side of all operators, and a space after all commas.
    * This includes the = in method(arg = default).
    * PEP8, clarity.
  * No whitespace at the end of a line
    * clarity, easier diffs.
  * No need for docstrings on init, since they're implicit.
    * Pylint, obvious.
  * Use "{0:spec}".format(blah) over "%spec" % blah.
    * In preparation for python-3, % is evil.
  * Use lowercase format specifier when outputting hex offsets ("{0:08x}" or "{0:#010x}").
    * Consistency, ease of reading (particularly 0x123 vs 0X123).
  * Avoid using super, call the superclass's function by name instead.
    * This is primarily in regards to init, because you need to pass the underlying init function's arguments, and you don't know which init you'll end up calling in the case of multiple inheritance.  As such, that requires the entire codebase to ensure that all inits take kwargs, and are co-operative to this coding style.  Super's only really useful for multiple-inheritance, and even then it's easy to get wrong.
    * See http://fuhm.net/super-harmful/
  * Always try to catch the most specific exception you can.
    * Never use "except:" (see [idioms and anti-idioms in Python](http://docs.python.org/howto/doanddont.html#except))
    * Makes debugging far easier if you only catch what you're expecting.