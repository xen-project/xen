# Coverage support for Xen

Coverare support allow you to get coverage information from Xen execution.
You can see how many times a line is executed.

The compiler have specific options that enable the collection of these
information. Every basic block in the code will be instructed by the compiler
to compute these statistics. It should not be used in production as it slow
down your hypervisor.

## Enable coverage

Test coverage support can be turned on compiling Xen with coverage option set
to y.

Something like:
    cd xen
    make coverage=y

(or change your `Config.mk` file).

## Extract coverage data

The way GCC and other tools deal with coverage information is to use some files
created during build phase (.gcno) and some files produced by executing the
*program* (.gcda). The program in this case is Xen but Xen cannot write files
so the way you can use coverage from Xen is extract coverage data from Xen and
then split these information into files.

To extract data you use a simple utility called `xencov`. Mainly `xencore`
allow you to do 3 operations:

* `xencov read` extract data
* `xencov reset` reset all coverage counters
* `xencov read-reset` extract data and reset counters at the same time.

Another utility (**TODO**) is used to split extracted data file into files
needed by userspace tools.

