.. SPDX-License-Identifier: GPL-2.0

=============
Xen Makefiles
=============

Documentation for the build system of Xen, found in xen.git/xen/.

Makefile files
==============

Description of the syntax that can be used in most Makefiles named
'Makefile'. ('xen/Makefile' isn't part of the description.)

'Makefile's are consumed by 'Rules.mk' when building.

Goal definitions
----------------

	Goal definitions are the main part (heart) of the Makefile.
	These lines define the files to be built, any special compilation
	options, and any subdirectories to be entered recursively.

	The most simple makefile contains one line:

	Example::

		obj-y += foo.o

	This tells the build system that there is one object in that
	directory, named foo.o. foo.o will be built from foo.c or foo.S.

	The following pattern is often used to have object selected
	depending on the configuration:

	Example::

		obj-$(CONFIG_FOO) += foo.o

	$(CONFIG_FOO) can evaluates to y.
	If CONFIG_FOO is not y, then the file will not be compiled nor linked.

Descending down in directories
------------------------------

	A Makefile is only responsible for building objects in its own
	directory. Files in subdirectories should be taken care of by
	Makefiles in these subdirs. The build system will automatically
	invoke make recursively in subdirectories, provided you let it know of
	them.

	To do so, obj-y is used.
	acpi lives in a separate directory, and the Makefile present in
	drivers/ tells the build system to descend down using the following
	assignment.

	Example::

		#drivers/Makefile
		obj-$(CONFIG_ACPI) += acpi/

	If CONFIG_ACPI is set to 'y'
	the corresponding obj- variable will be set, and the build system
	will descend down in the apci directory.
	The build system only uses this information to decide that it needs
	to visit the directory, it is the Makefile in the subdirectory that
	specifies what is modular and what is built-in.

	It is good practice to use a `CONFIG_` variable when assigning directory
	names. This allows the build system to totally skip the directory if the
	corresponding `CONFIG_` option is 'y'.

Compilation flags
-----------------

    CFLAGS-y and AFLAGS-y
	These two flags apply only to the makefile in which they
	are assigned. They are used for all the normal cc, as and ld
	invocations happening during a recursive build.

	$(CFLAGS-y) is necessary because the top Makefile owns the
	variable $(XEN_CFLAGS) and uses it for compilation flags for the
	entire tree. And the variable $(CFLAGS) is modified by Config.mk
	which evaluated in every subdirs.

	CFLAGS-y specifies options for compiling with $(CC).
	AFLAGS-y specifies assembler options.
