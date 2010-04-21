# xm-test configure.ac input script

# Basic header information
AC_INIT([xm-test], [1.1.0])
AM_INIT_AUTOMAKE([1.7 foreign])

MK=''; AC_SUBST(MK)

# Check for dependencies
AC_PROG_CC
#AC_PROG_INSTALL
AC_CHECK_PROG([LILO],	lilo,	lilo,	"no",	[$PATH])

XEN_PYTHON_PATH=$(/usr/sbin/xen-python-path)

# Right now, we can assume that the lib/ directory
# is two levels above the tests
TESTLIB=../../lib
TENV="PYTHONPATH=$PYTHONPATH:$TESTLIB:$XEN_PYTHON_PATH"

AC_ARG_ENABLE(hvm-support,
	[[  --enable-hvm-support           enable hardware virtual machine assist]],
	[
		ENABLE_HVM=True
	],[
		ENABLE_HVM=False
	])

if test "x$ENABLE_HVM" = "xTrue"; then
	if test "$LILO" = "no"; then 
		AC_MSG_ERROR([lilo not found
lilo version 22.7 or greater must be installed for testing with hvm enabled.])
	else
		pass=`$LILO -V | sed -e "s/LILO version //" | awk -F "." '{if ($1 >=22 && $2 >= 7) print "true"; else print "false"}'`
		if test "$pass" != "true"; then
			AC_MSG_ERROR(Lilo version must be equal or greater to 22.7+.)
		fi
	fi
fi

AM_CONDITIONAL(HVM, test x$ENABLE_HVM = xTrue)
AC_SUBST(ENABLE_HVM)

AC_ARG_ENABLE(full-labeling,
	[[  --enable-full-labeling         allows the test suite to label all resources]],
	[
		ENABLE_LABELING=True
	],[
		ENABLE_LABELING=False
	])

if test "x$ENABLE_LABELING" = "xTrue"; then
	echo "ACM_LABEL_RESOURCES = True" > lib/XmTestLib/acm_config.py
else
	rm -f lib/XmTestLib/acm_config.py*
fi

# Network needs to know ips to use: dhcp or a range of IPs in the form
# of: 192.0.2.1-192.0.2.100
# If not dhcp, a netmask and network address must be supplied. Defaults to
# range allocated in www.ucam.org/cam-grin.
NET_IP_RANGE="172.30.206.1-172.30.206.254"
AC_ARG_WITH(net-ip-range,
	[  --with-net-ip-range=ip-range	Set a range of ip addresses to use for xm-test guest domain networks. Can specify dhcp or a range of IPs: 192.0.2.1-192.0.2.100 [[default="172.30.206.1-172.30.206.254"]]],
	[ NET_IP_RANGE="$withval" ])

iprange=`echo $NET_IP_RANGE | perl -e 'while(<>) { print if /\d+\.\d+\.\d+\.\d+-\d+\.\d+\.\d+\.\d+/ }'`

NETWORK_ADDRESS="172.30.206.0"
AC_ARG_WITH(network-address,
	[ --with-network-address=ip Set network address to use with ip range [[default="172.30.206.0"]]],
	[ NETWORK_ADDRESS="$withval" ])

NETMASK="255.255.255.0"
AC_ARG_WITH(netmask,
	[ --with-netmask=mask Set netmask to use with ip range [[default="255.255.255.0"]]],
	[ NETMASK="$withval" ])

if test "x$NET_IP_RANGE" != "xdhcp" && test -z "$iprange"
then
	AC_MSG_ERROR(Invalid net-ip-range.)
fi

AC_SUBST(NET_IP_RANGE)
AC_SUBST(NETWORK_ADDRESS)
AC_SUBST(NETMASK)

DOM0_INTF="eth0"
AC_ARG_WITH(dom0-intf,
        [ --with-dom0-intf=intf Set dom0 interface name [[default="eth0"]]],
        [ DOM0_INTF="$withval" ])

AC_SUBST(DOM0_INTF)

AC_ARG_WITH(hvm-kernel,
      [[  --with-hvm-kernel=kernel       Use this kernel for hvm disk.img testing]],
      HVMKERNEL=$withval,
      HVMKERNEL="no")

dnl substitute @HVMKERNEL@ in all Makefiles
AC_SUBST(HVMKERNEL)

AC_ARG_WITH(driver-dir,
	[[  --with-driver-dir=drvdir       Look in this directory for the pcnet32 driver for the vmx disk.img. drvdir can equal key word "builtin" if driver is built into the kernel]],
	DRVDIR=$withval,
	DRVDIR="no")

dnl substitute @DRVDIR@ in all Makefiles
AC_SUBST(DRVDIR)

NETDRV="8139too.ko"
AC_ARG_WITH(network-drv,
	[  --with-network-drv=driver Set network driver to use [[default="8139too.ko"]]],
	[ NETDRV="$withval" ])

dnl substitute @DRVDIR@ in all Makefiles
AC_SUBST(NETDRV)

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
    tests/block-integrity/Makefile
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
    tests/sched-credit/Makefile
    tests/security-acm/Makefile
    tests/sedf/Makefile
    tests/shutdown/Makefile
    tests/sysrq/Makefile
    tests/unpause/Makefile
    tests/vcpu-pin/Makefile
    tests/vcpu-disable/Makefile
    tests/vtpm/Makefile
    tests/xapi/Makefile
    tests/enforce_dom0_cpus/Makefile
    tests/cpupool/Makefile
    lib/XmTestReport/xmtest.py
    lib/XmTestLib/config.py
    ])

AC_OUTPUT

chmod a+x lib/XmTestReport/xmtest.py
