.. SPDX-License-Identifier: CC-BY-4.0

Xen static analysis
===================

The Xen codebase integrates some scripts and tools that helps the developer to
perform static analysis of the code, currently Xen supports three analysis tool
that are eclair, coverity and cppcheck.
The Xen tree has a script (xen-analysis.py) available to ease the analysis
process and it integrates a way to suppress findings on these tools, please
check the documenting-violation.rst document to know more about it.

Analyse Xen with Coverity or Eclair
-----------------------------------

The xen-analysis.py script has two arguments to select which tool is used for
the analysis:

 - xen-analysis.py --run-coverity -- [optional make arguments]
 - xen-analysis.py --run-eclair -- [optional make arguments]

For example when using Coverity to analyse a Xen build obtained by passing these
arguments to the make system: XEN_TARGET_ARCH=arm64
CROSS_COMPILE=aarch64-linux-gnu-, the optional make arguments passed to
xen-analysis.py must be the same and the command below should be passed to
Coverity in its build phase:

 - xen-analysis.py --run-coverity -- XEN_TARGET_ARCH=arm64
   CROSS_COMPILE=aarch64-linux-gnu-

Which tells to the script to prepare the codebase for an analysis by Coverity
and forwards the make arguments to the make build invocation.

When invoking the script, the procedure below will be followed:

 1. Find which files among \*.c and \*.h has any in-code comment as
    /* SAF-X-[...] \*/, the meaning of these comments is explained in
    documenting-violation.rst.
    Save the files obtained as <file>.safparse and generate <file> files where
    the special in-code comments above are substituted with the proprietary
    in-code comment used by the selected analysis tool. The safe.json and
    false-positive-<tool>.json text file database are used to link each Xen tag
    to the right proprietary in-code comment.
 2. Now Xen compilation starts using every <additional make parameters> supplied
    at the script invocation. Coverity and Eclair are capable of intercepting
    the compiler running from make to perform their analysis without
    instrumenting the makefile.
 3. As final step every <file>.safparse file are reverted back as <file> and
    every artifact related to the analysis will be cleaned.
    This step is performed even in case any of the previous step fail, to skip
    this step, call the script adding the --no-clean argument, but before
    running again the script, call it with the --clean-only argument, that will
    execute only this cleaning step.


Analyse Xen with Cppcheck
-------------------------

Cppcheck tool is integrated in xen-analysis.py script, when using the script,
the tool will be called on every source file compiled by the make build system.
Here how to start the analysis with Cppcheck:

 - xen-analysis.py --run-cppcheck [--cppcheck-misra] [--cppcheck-html] --
   [optional make arguments]

The command above tells the script to prepare the codebase and use Cppcheck tool
for the analysis.
The optional argument --cppcheck-misra activates the analysis also for MISRA
compliance.
The optional argument --cppcheck-html instruct cppcheck to produce an additional
HTML report.

When invoking the script for Cppcheck analysis, the followed procedure is
similar to the one above for Coverity or Eclair, but it has some additional
steps:

 1. This step is the same as step 1 for Coverity/Eclair.
 2. The cppcheck dependency are created, build directory for cppcheck analysis
    and an header file containing internal compiler macro
    (include/generated/compiler-def.h) are generated
 3. Xen compilation starts using every <additional make parameters> supplied
    at the script invocation, but because cppcheck is not able to intercept the
    compiled files and flags on compiler invocation, a script (cppcheck-cc.sh)
    is passed as CC to the make system, it is a wrapper for the compiler that
    will also execute cppcheck on every compiled file.
 4. After the compilation and analysis, the cppcheck report will be created
    putting together all the cppcheck report fragments for every analysed file.
    Cppcheck will produce a text fragment and an additional XML report fragment
    if the script is configured to produce the HTML output.
 5. This step is the same as step 3 for Coverity/Eclair.
