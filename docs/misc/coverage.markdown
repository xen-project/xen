# Coverage support for Xen

Coverage support allows you to get coverage information from Xen execution.
You can see how many times a line is executed.

Some compilers have specific options that enable the collection of this
information. Every basic block in the code will be instrumented by the compiler
to compute these statistics. It should not be used in production as it slows
down your hypervisor.

## Enable coverage

Test coverage support can be turned on compiling Xen with the `CONFIG_GCOV`
option set to `y`.

Change your `.config` or run `make -C xen menuconfig`.

## Extract coverage data

To extract data you use a simple utility called `xencov`.
It allows you to do 2 operations:

* `xencov read` extract data
* `xencov reset` reset all coverage counters

Another utility (`xencov_split`) is used to split extracted data file into
files needed by userspace tools.

## Split coverage data

Once you extracted data from Xen, it is time to create files which the coverage
tools can understand. To do it you need to run `xencov_split` utility.

The utility just takes an input file and splits the blob into gcc .gcda files
in the same directory that you execute the script. As file names are generated
relative to the current directory, it could be a good idea to run the script
from `/` on your build machine.

Code for splitting the blob is put in another utility for some reason:
* It is simpler to maintain a high level script than a C program;
* You don't need to execute on the Xen host so you just need to copy the file to
  your development box (you usually need development files anyway).

## Possible use

**This section is just an example on how to use these tools!**

This example assumes you compiled Xen from `~/xen-unstable` and installed into
the host. **Consider that if you even recompile Xen you are not able to use
blob extracted from xencov!**

* Ensure the `lcov` package is installed
* From the Xen host machine extract the coverage blob

        cd /root
        xencov read coverage.dat

* Copy the extracted blob to your dev machine

        cd ~
        scp root@myhost:coverage.dat

* Extract the coverage information

        (cd / && xencov_split ~/coverage.dat)

* Produce coverage html output

        cd ~/xen-unstable
        rm -rf cov.info cov
        geninfo -o cov.info xen
        mkdir cov
        genhtml -o cov cov.info

* See output in a browser

        firefox cov/index.html
