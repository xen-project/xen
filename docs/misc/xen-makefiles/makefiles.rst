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


Build system infrastructure
===========================

This chapter describe some of the macro used when building Xen.

Macros
------


    if_changed
	if_changed is the infrastructure used for the following commands.

	Usage::

		target: source(s) FORCE
			$(call if_changed,ld/objcopy/...)

	When the rule is evaluated, it is checked to see if any files
	need an update, or the command line has changed since the last
	invocation. The latter will force a rebuild if any options
	to the executable have changed.
	Any target that utilises if_changed must be listed in $(targets),
	otherwise the command line check will fail, and the target will
	always be built.
	if_changed may be used in conjunction with custom commands as
	defined in "Custom commands".

	Note: It is a typical mistake to forget the FORCE prerequisite.
	Another common pitfall is that whitespace is sometimes
	significant; for instance, the below will fail (note the extra space
	after the comma)::

		target: source(s) FORCE

	**WRONG!**	$(call if_changed, ld/objcopy/...)

	Note:
		if_changed should not be used more than once per target.
		It stores the executed command in a corresponding .cmd file
		and multiple calls would result in overwrites and unwanted
		results when the target is up to date and only the tests on
		changed commands trigger execution of commands.

    ld
	Link target.

	Example::

		targets += setup setup.o bootsect bootsect.o
		$(obj)/setup $(obj)/bootsect: %: %.o FORCE
			$(call if_changed,ld)

	$(targets) are assigned all potential targets, by which the build
	system knows the targets and will:

		1) check for commandline changes

	The ": %: %.o" part of the prerequisite is a shorthand that
	frees us from listing the setup.o and bootsect.o files.

	Note:
		It is a common mistake to forget the "targets :=" assignment,
		resulting in the target file being recompiled for no
		obvious reason.

    objcopy
	Copy binary. Uses OBJCOPYFLAGS usually specified in
	arch/$(ARCH)/Makefile.

Custom commands
---------------

	When the build system is executing with V=0, then only
	a shorthand of a command is normally displayed.
	To enable this behaviour for custom commands, two variables are
	required to be set::

		quiet_cmd_<command>	- what shall be echoed
		      cmd_<command>	- the command to execute

	Example::

		# xsm/flask/Makefile
		mkflask := policy/mkflask.sh
		quiet_cmd_mkflask = MKFLASK $@
		cmd_mkflask = $(CONFIG_SHELL) $(mkflask) $(AWK) include \
			$(FLASK_H_DEPEND)

		include/flask.h: $(FLASK_H_DEPEND) $(mkflask) FORCE
			$(call if_changed,mkflask)

	When updating the include/flask.h target, the line:

		MKFLASK include/flask.h

	will be displayed with "make V=0". (V=0 is the default)
