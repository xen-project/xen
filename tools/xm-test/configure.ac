# xm-test configure.ac input script

# Basic header information
AC_INIT([xm-test], [0.6.0])
AM_INIT_AUTOMAKE([1.7 foreign])

# Check for dependencies
AC_PROG_CC
#AC_PROG_INSTALL

# Right now, we can assume that the lib/ and ramdisk/ directories
# are two levels above the tests
TESTLIB=../../lib
RD_PATH=../../ramdisk
TENV="PYTHONPATH=$PYTHONPATH:$TESTLIB:/usr/lib/python RD_PATH=$RD_PATH"

AC_ARG_ENABLE(vmx-support,
	[[  --enable-vmx-support           use block devices instead of ramdisks]],
	[
		ENABLE_VMX=True
	],[
		ENABLE_VMX=False
	])

AC_SUBST(ENABLE_VMX)

AC_SUBST(TENV)
AC_SUBST(PACKAGE_VERSION)

AC_PROG_YACC
AC_PROG_LEX

# basic build files
AC_CONFIG_FILES([
    Makefile 
    ramdisk/Makefile
    tests/Makefile
    tests/block-list/Makefile
    tests/block-create/Makefile
    tests/block-destroy/Makefile
    tests/console/Makefile
    tests/create/Makefile
    tests/destroy/Makefile
    tests/dmesg/Makefile
    tests/domid/Makefile
    tests/domname/Makefile
    tests/help/Makefile
    tests/info/Makefile
    tests/list/Makefile
    tests/memmax/Makefile
    tests/memset/Makefile
    tests/migrate/Makefile
    tests/network-attach/Makefile
    tests/pause/Makefile
    tests/reboot/Makefile
    tests/restore/Makefile
    tests/save/Makefile
    tests/sedf/Makefile
    tests/shutdown/Makefile
    tests/sysrq/Makefile
    tests/unpause/Makefile
    tests/vcpu-pin/Makefile
    tests/vcpu-disable/Makefile
    tests/enforce_dom0_cpus/Makefile
    lib/XmTestReport/xmtest.py
    lib/XmTestLib/config.py
    ])

AC_OUTPUT

chmod a+x lib/XmTestReport/xmtest.py
