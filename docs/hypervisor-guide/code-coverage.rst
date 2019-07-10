Code Coverage
=============

Xen can be compiled with coverage support.  When configured, Xen will record
the coverage of its own basic blocks.  Being a piece of system software rather
than a userspace, it can't automatically write coverage out to the filesystem,
so some extra steps are required to collect and process the data.

.. warning::

  ARM doesn't currently boot when the final binary exceeds 2MB in size,
  and the coverage build tends to exceed this limit.


Compiling Xen
-------------

Coverage support is dependent on the compiler and toolchain used.  As Xen
isn't a userspace application, it can't use the compiler supplied library, and
instead has to provide some parts of the implementation itself.

For x86, coverage support was introduced with GCC 3.4 or later, and Clang 3.9
or later, and Xen is compatible with these.  However, the compiler internal
formats do change occasionally, and this may involve adjustments to Xen.
While we do our best to keep up with these changes, Xen may not be compatible
with bleeding edge compilers.

To build with coverage support, enable ``CONFIG_COVERAGE`` in Kconfig.  The
build system will automatically select the appropriate format based on the
compiler in use.

The resulting binary will record its own coverage while running.


Accessing the raw coverage data
-------------------------------

The ``SYSCTL_coverage_op`` hypercall is used to interact with the coverage
data.  A dom0 userspace helper, ``xenconv`` is provided as well, which thinly
wraps this hypercall.

The ``read`` subcommand can be used to obtain the raw coverage data::

  [root@host ~]# xencov read > coverage.dat

This is toolchain-specific data and needs to be fed back to the appropriate
programs to post-process.

Alternatively, the ``reset`` subcommand can be used reset all counters back to
0::

  [root@host ~]# xencov reset


GCC coverage
------------

A build using GCC's coverage will result in ``*.gcno`` artefact for every
object file.  The raw coverage data needs splitting to form the matching
``*.gcda`` files.

An example of how to view the data is as follows.  It uses ``lcov`` which is a
graphical frontend to ``gcov``.

* Obtain the raw coverage data from the test host, and pull it back to the
  build working tree.
* Use ``xencov_split`` to extract the ``*.gcda`` files.  Note that full build
  paths are used by the tools, so splitting needs to output relative to ``/``.
* Use ``geninfo`` to post-process the raw data.
* Use ``genhtml`` to render the results as HTML.
* View the results in a browser.

::

  xen.git/xen$ ssh root@host xencov read > coverage.dat
  xen.git/xen$ ../tools/xencov_split coverage.dat --output-dir=/
  xen.git/xen$ geninfo . -o cov.info
  xen.git/xen$ genhtml cov.info -o cov/
  xen.git/xen$ $BROWSER cov/index.html

Clang coverage
--------------

An example of how to view the data is as follows.

* Obtain the raw coverage data from the test host, and pull it back to the
  build working tree.
* Use ``llvm-profdata`` to post-process the raw data.
* Use ``llvm-cov show`` in combination with ``xen-syms`` from the build to
  render the results as HTML.
* View the results in a browser.

::

  xen.git/xen$ ssh root@host xencov read > xen.profraw
  xen.git/xen$ llvm-profdata merge xen.profraw -o xen.profdata
  xen.git/xen$ llvm-cov show -format=html -output-dir=cov/ xen-syms -instr-profile=xen.profdata
  xen.git/xen$ $BROWSER cov/index.html

Full documentation on Clang's coverage capabilities can be found at:
https://clang.llvm.org/docs/SourceBasedCodeCoverage.html
