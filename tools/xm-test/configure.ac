# xm-test configure.ac input script

# Basic header information
AC_INIT([xm-test], [0.6.0])
AM_INIT_AUTOMAKE([1.7 foreign])

# Check for dependencies
AC_PROG_CC
#AC_PROG_INSTALL
AC_CHECK_PROG([LILO],	lilo,	lilo,	"no",	[$PATH])

# Right now, we can assume that the lib/ and ramdisk/ directories
# are two levels above the tests
TESTLIB=../../lib
RD_PATH=../../ramdisk
TENV="PYTHONPATH=$PYTHONPATH:$TESTLIB:/usr/lib/python RD_PATH=$RD_PATH"

AC_ARG_ENABLE(vmx-support,
	[[  --enable-vmx-support           enable hardware virtual machine assist]],
	[
		ENABLE_VMX=True
	],[
		ENABLE_VMX=False
	])

if test "x$ENABLE_VMX" = "xTrue"; then
	if test "$LILO" = "no"; then 
		AC_MSG_ERROR([lilo not found
lilo version 22.7 or greater must be installed for testing with vmx enabled.])
	else
		pass=`$LILO -V | sed -e "s/LILO version //" | awk -F "." '{if ($1 >=22 && $2 >= 7) print "true"; else print "false"}'`
		if test "$pass" != "true"; then
			AC_MSG_ERROR(Lilo version must be equal or greater to 22.7+.)
		fi
	fi
fi

AM_CONDITIONAL(VMX, test x$ENABLE_VMX = xTrue)
AC_SUBST(ENABLE_VMX)

AC_ARG_WITH(vmx-kernel,
	[[  --with-vmx-kernel=kernel       Use this kernel for vmx disk.img testing]],
	VMXKERNEL=$withval,
	VMXKERNEL="no")

dnl substitute @VMXKERNEL@ in all Makefiles
AC_SUBST(VMXKERNEL)

AC_SUBST(TENV)
AC_SUBST(PACKAGE_VERSION)

AC_PROG_YACC
AC_PROG_LEX

# basic build files
AC_CONFIG_FILES([
    Makefile 
    ramdisk/Makefile
    tests/Makefile
    tests/_sanity/Makefile
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
    tests/network/Makefile
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
