#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.67])
AC_INIT([Xen Hypervisor Tools], m4_esyscmd([../version.sh ../xen/Makefile]),
    [xen-devel@lists.xen.org], [xen], [http://www.xen.org/])
AC_CONFIG_SRCDIR([libxl/libxl.c])
AC_CONFIG_FILES([
../config/Tools.mk
hotplug/FreeBSD/rc.d/xencommons
hotplug/FreeBSD/rc.d/xendriverdomain
hotplug/Linux/init.d/sysconfig.xencommons
hotplug/Linux/init.d/sysconfig.xendomains
hotplug/Linux/init.d/xen-watchdog
hotplug/Linux/init.d/xencommons
hotplug/Linux/init.d/xendomains
hotplug/Linux/init.d/xendriverdomain
hotplug/Linux/launch-xenstore
hotplug/Linux/vif-setup
hotplug/Linux/xen-hotplug-common.sh
hotplug/Linux/xendomains
hotplug/NetBSD/rc.d/xencommons
hotplug/NetBSD/rc.d/xendriverdomain
ocaml/xenstored/oxenstored.conf
])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([../])

# Check if CFLAGS, LDFLAGS, LIBS, CPPFLAGS or CPP is set and print a warning

AS_IF([test -n "$CC$CFLAGS$LDFLAGS$LIBS$CPPFLAGS$CPP"], [
    AC_MSG_WARN(
[Setting CC, CFLAGS, LDFLAGS, LIBS, CPPFLAGS or CPP is not \
recommended, use PREPEND_INCLUDES, PREPEND_LIB, \
APPEND_INCLUDES and APPEND_LIB instead when possible.])
])

AC_CANONICAL_HOST

case $host_vendor in
rumpxen|rumprun) CONFIG_RUMP=y; rump=true ;;
*)               CONFIG_RUMP=n; rump=false ;;
esac
AC_SUBST(CONFIG_RUMP)

AC_SYS_LARGEFILE

case $ac_cv_sys_file_offset_bits in #(
  no | unknown) ;;
  *)
  FILE_OFFSET_BITS=$ac_cv_sys_file_offset_bits
;;
esac
AC_SUBST(FILE_OFFSET_BITS)

# M4 Macro includes
m4_include([../m4/savevar.m4])
m4_include([../m4/features.m4])
m4_include([../m4/path_or_fail.m4])
m4_include([../m4/checkpolicy.m4])
m4_include([../m4/set_cflags_ldflags.m4])
m4_include([../m4/python_version.m4])
m4_include([../m4/python_devel.m4])
m4_include([../m4/python_fortify_noopt.m4])
m4_include([../m4/ocaml.m4])
m4_include([../m4/uuid.m4])
m4_include([../m4/pkg.m4])
m4_include([../m4/curses.m4])
m4_include([../m4/pthread.m4])
m4_include([../m4/ptyfuncs.m4])
m4_include([../m4/extfs.m4])
m4_include([../m4/fetcher.m4])
m4_include([../m4/ax_compare_version.m4])
m4_include([../m4/paths.m4])
m4_include([../m4/systemd.m4])

AX_XEN_EXPAND_CONFIG()

# Enable/disable options
AX_ARG_DEFAULT_DISABLE([rpath], [Build tools with -Wl,-rpath,LIBDIR])
AX_ARG_DEFAULT_DISABLE([githttp], [Download GIT repositories via HTTP])
AX_ARG_DEFAULT_ENABLE([monitors], [Disable xenstat and xentop monitoring tools])
AX_ARG_DEFAULT_ENABLE([ocamltools], [Disable Ocaml tools])
AX_ARG_DEFAULT_ENABLE([xsmpolicy], [Disable XSM policy compilation])
AX_ARG_DEFAULT_DISABLE([ovmf], [Enable OVMF])
AX_ARG_DEFAULT_ENABLE([seabios], [Disable SeaBIOS])

AC_ARG_WITH([linux-backend-modules],
    AS_HELP_STRING([--with-linux-backend-modules="mod1 mod2"],
    [List of Linux backend module or modalias names to be autoloaded on startup.]),
    [LINUX_BACKEND_MODULES="$withval"],
    [case "$host_os" in
*linux*)
LINUX_BACKEND_MODULES="
xen-evtchn
xen-gntdev
xen-gntalloc
xen-blkback
xen-netback
xen-pciback
evtchn
gntdev
netbk
blkbk
xen-scsibk
usbbk
pciback
xen-acpi-processor
"
;;
*)
LINUX_BACKEND_MODULES=
;;
esac])
LINUX_BACKEND_MODULES="`eval echo $LINUX_BACKEND_MODULES`"
AC_SUBST(LINUX_BACKEND_MODULES)

AC_ARG_ENABLE([qemu-traditional],
    AS_HELP_STRING([--enable-qemu-traditional],
                   [Enable qemu traditional device model, (DEFAULT is on for Linux or NetBSD x86, otherwise off)]),,[
    case "$host_cpu" in
        i[[3456]]86|x86_64)
           enable_qemu_traditional="yes";;
        *) enable_qemu_traditional="no";;
    esac
    case "$host_os" in
        freebsd*)
           enable_qemu_traditional="no";;
    esac

])
AS_IF([test "x$enable_qemu_traditional" = "xyes"], [
AC_DEFINE([HAVE_QEMU_TRADITIONAL], [1], [Qemu traditional enabled])
    qemu_traditional=y],[
    qemu_traditional=n
])
AC_SUBST(qemu_traditional)

AC_ARG_ENABLE([rombios],
    AS_HELP_STRING([--enable-rombios],
                   [Enable ROMBIOS, (DEFAULT is on if qemu-traditional is enabled, otherwise off)]),,[
    AS_IF([test "x$enable_qemu_traditional" = "xyes"], [
        enable_rombios="yes"
    ], [
        enable_rombios="no"
    ])
])
AS_IF([test "x$enable_rombios" = "xyes"], [
    dnl as86, ld86, and bcc are only required when building rombios. They
    dnl are only needed when the host system is x86 but that check is done
    dnl for us above when checking if we should build with qemu-traditional.
    AX_PATH_PROG_OR_FAIL([AS86], [as86])
    AX_PATH_PROG_OR_FAIL([LD86], [ld86])
    AX_PATH_PROG_OR_FAIL([BCC], [bcc])
    AC_CHECK_LIB([lzma], [lzma_version_number], [],
        [AC_MSG_ERROR([Could not find lzma, needed to build rombios])])
    AC_DEFINE([HAVE_ROMBIOS], [1], [ROMBIOS enabled])
    rombios=y],[
    rombios=n
])
AC_SUBST(rombios)

AC_ARG_WITH([system-qemu],
    AS_HELP_STRING([--with-system-qemu@<:@=PATH@:>@],
       [Use system supplied qemu PATH or qemu (taken from $PATH) as qemu-xen
        device model instead of building and installing our own version]),[
    case $withval in
        yes)
            qemu_xen=n ; qemu_xen_path="qemu-system-i386"
            qemu_xen_systemd="/usr/bin/env $qemu_xen_path" ;;
        no)
            qemu_xen=y ;;
        *)
            qemu_xen=n ; qemu_xen_path="$withval" ;
            qemu_xen_systemd="$qemu_xen_path" ;;
    esac
],[
    case "$host_cpu" in
        i[[3456]]86|x86_64)
           qemu_xen=y;;
        arm*|aarch64)
           qemu_xen=y;;
        *) qemu_xen=n;;
    esac
])
AS_IF([test "x$qemu_xen" = "xy"], [
    qemu_xen_path="$LIBEXEC_BIN/qemu-system-i386"
    qemu_xen_systemd="$qemu_xen_path"
])
AC_DEFINE_UNQUOTED([QEMU_XEN_PATH], ["$qemu_xen_path"], [Qemu Xen path])
AC_SUBST(qemu_xen)
AC_SUBST(qemu_xen_path)
AC_SUBST(qemu_xen_systemd)

AC_ARG_WITH([system-seabios],
    AS_HELP_STRING([--with-system-seabios@<:@=PATH@:>@],
       [Use system supplied seabios PATH instead of building and installing
        our own version]),[
    # Disable compilation of SeaBIOS.
    seabios=n
    case $withval in
        no) seabios_path= ;;
        /*)  seabios_path=$withval ;;
        *) AC_MSG_ERROR([Seabios specified, but is not an absolute path]) ;;
    esac
],[])
AS_IF([test "x$seabios" = "xy" -o -n "$seabios_path" ], [
    AC_DEFINE_UNQUOTED([SEABIOS_PATH],
                       ["${seabios_path:-$XENFIRMWAREDIR/seabios.bin}"],
                       [SeaBIOS path])
])

AC_ARG_WITH([system-ovmf],
    AS_HELP_STRING([--with-system-ovmf@<:@=PATH@:>@],
       [Use system supplied OVMF PATH instead of building and installing
        our own version]),[
    # Disable compilation of OVMF.
    ovmf=n
    case $withval in
        no) ovmf_path= ;;
        /*)  ovmf_path=$withval ;;
        *) AC_MSG_ERROR([OVMF specified, but is not an absolute path]) ;;
    esac
],[])
AS_IF([test "x$ovmf" = "xy" -o -n "$ovmf_path" ], [
    AC_DEFINE_UNQUOTED([OVMF_PATH],
                       ["${ovmf_path:-$XENFIRMWAREDIR/ovmf.bin}"],
                       [OVMF path])
])

AC_ARG_ENABLE([ipxe],
    AS_HELP_STRING([--disable-ipxe],
                   [Enable in-tree IPXE, (DEFAULT is on if rombios is enabled,
                    otherwise off, see also --with-system-ipxe)]),
    [
     AS_IF([test "x$enable_ipxe" = "xno"], [ipxe=n], [ipxe=y])
    ],
    [
    AS_IF([test "x$enable_rombios" = "xno"], [ipxe=n], [ipxe=y])
])
AC_ARG_WITH([system-ipxe],
    AS_HELP_STRING([--with-system-ipxe@<:@=PATH@:>@],
       [Use system supplied IPXE PATH instead of building and installing
        our own version, it takes precedence over --{en,dis}able-ipxe and is
        bound by the presence of rombios, --without-system-ipxe is an error]),[
    case $withval in
        no) AC_MSG_ERROR([--without-system-ipxe has no effect]) ;;
        /*)  ipxe_path=$withval; ipxe=n ;;
        *) AC_MSG_ERROR([IPXE specified, but is not an absolute path]) ;;
    esac
],[])
AS_IF([test "x$ipxe" = "xy" -o -n "$ipxe_path" ], [

    AS_IF([test "x$enable_rombios" = "xno"], [
        AC_MSG_ERROR([Rombios is required to use IPXE])
    ], [])

    AC_DEFINE_UNQUOTED([IPXE_PATH],
                       ["${ipxe_path:-$XENFIRMWAREDIR/ipxe.bin}"],
                       [IPXE path])
])
AC_SUBST(ipxe)

AC_ARG_WITH([extra-qemuu-configure-args],
    AS_HELP_STRING([--with-extra-qemuu-configure-args@<:@="--ARG1 ..."@:>@],
       [List of additional configure options for upstream qemu]),[
    case $withval in
        no) EXTRA_QEMUU_CONFIGURE_ARGS= ;;
        *)  EXTRA_QEMUU_CONFIGURE_ARGS=$withval ;;
    esac
],[])
AC_SUBST(EXTRA_QEMUU_CONFIGURE_ARGS)

AC_ARG_VAR([PREPEND_INCLUDES],
    [List of include folders to prepend to CFLAGS (without -I)])
AC_ARG_VAR([PREPEND_LIB],
    [List of library folders to prepend to LDFLAGS (without -L)])
AC_ARG_VAR([APPEND_INCLUDES],
    [List of include folders to append to CFLAGS (without -I)])
AC_ARG_VAR([APPEND_LIB],
    [List of library folders to append to LDFLAGS (without -L)])

AX_SET_FLAGS

AC_ARG_VAR([PYTHON], [Path to the Python parser])
AC_ARG_VAR([PERL], [Path to Perl parser])
AC_ARG_VAR([BISON], [Path to Bison parser generator])
AC_ARG_VAR([FLEX], [Path to Flex lexical analyser generator])
AC_ARG_VAR([BASH], [Path to bash shell])
AC_ARG_VAR([XGETTEXT], [Path to xgetttext tool])
AC_ARG_VAR([AS86], [Path to as86 tool])
AC_ARG_VAR([LD86], [Path to ld86 tool])
AC_ARG_VAR([BCC], [Path to bcc tool])
AC_ARG_VAR([IASL], [Path to iasl tool])
AC_ARG_VAR([AWK], [Path to awk tool])

# Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET
AC_PROG_INSTALL
AC_PATH_PROG([BISON], [bison])
AC_PATH_PROG([FLEX], [flex])
AX_PATH_PROG_OR_FAIL([PERL], [perl])
AX_PATH_PROG_OR_FAIL([AWK], [awk])

AC_PROG_OCAML
AC_PROG_FINDLIB

AS_IF([test "x$ocamltools" = "xy"], [
    AS_IF([test "x$OCAMLOPT" = "xno" || test "x$OCAMLFIND" = "xno"], [
        AS_IF([test "x$enable_ocamltools" = "xyes"], [
            AC_MSG_ERROR([Ocaml tools enabled, but missing ocamlopt or ocamlfind])])
        ocamltools="n"
    ], [
        AX_COMPARE_VERSION([$OCAMLVERSION], [lt], [4.02.0], [
            AS_IF([test "x$enable_ocamltools" = "xyes"], [
                AC_MSG_ERROR([Your version of OCaml: $OCAMLVERSION is not supported])])
            ocamltools="n"
        ])
    ])
])

m4_include([../m4/xenstored.m4])
AX_XENSTORE_OPTIONS
AX_XENSTORE_SET

AS_IF([test "x$xsmpolicy" = "xy"], [
    AC_PROG_CHECKPOLICY
    AS_IF([test "x$CHECKPOLICY" = "xno"], [
        AS_IF([test "x$enable_xsmpolicy" = "xyes"], [
            AC_MSG_ERROR([XSM policy compilation enabled, but unable to find checkpolicy])])
        xsmpolicy="n"
    ])
])
dnl FreeBSD doesn't require bash (hotplug scripts are in plain sh)
case "$host_os" in
  freebsd*) ;;
  *) AX_PATH_PROG_OR_FAIL([BASH], [bash]);;
esac
AS_IF([test -z "$PYTHON"], [PYTHON="python"])
AS_IF([echo "$PYTHON" | grep -q "^/"], [], [PYTHON=`type -p "$PYTHON"`])
PYTHONPATH=$PYTHON
PYTHON=`basename $PYTHONPATH`

AX_PATH_PROG_OR_FAIL([PYTHONPATH], [$PYTHON])
AX_CHECK_PYTHON_VERSION([2], [6])

AS_IF([test "$cross_compiling" != yes], [
    AX_CHECK_PYTHON_DEVEL()
    AX_CHECK_PYTHON_FORTIFY_NOOPT()
])

if ! $rump; then

AX_PATH_PROG_OR_FAIL([XGETTEXT], [xgettext])
dnl as86, ld86, bcc and iasl are only required when the host system is x86*.
dnl "host" here means the platform on which the hypervisor and tools is
dnl going to run, not the platform on which we are building (known as
dnl "build" in gnu speak).
case "$host_cpu" in
i[[3456]]86|x86_64|aarch64)
    AX_PATH_PROG_OR_FAIL([IASL], [iasl])
    ;;
esac
 AX_CHECK_UUID
 AX_CHECK_CURSES
AS_IF([test "$ncurses" = "y"], [
AC_CHECK_LIB([tinfo], [define_key], [TINFO_LIBS=-ltinfo])
])
AC_SUBST(TINFO_LIBS)

dnl The following are only required when upstream QEMU is built
AS_IF([test "x$qemu_xen" = "xy"], [
PKG_CHECK_MODULES(glib, [glib-2.0 >= 2.12])
PKG_CHECK_MODULES(pixman, [pixman-1 >= 0.21.8])
])
AX_CHECK_FETCHER

# Checks for libraries.
AC_CHECK_HEADER([bzlib.h], [
AC_CHECK_LIB([bz2], [BZ2_bzDecompressInit], [zlib="$zlib -DHAVE_BZLIB -lbz2"])
])
AC_CHECK_HEADER([lzma.h], [
AC_CHECK_LIB([lzma], [lzma_stream_decoder], [zlib="$zlib -DHAVE_LZMA -llzma"])
])
AC_CHECK_HEADER([lzo/lzo1x.h], [
AC_CHECK_LIB([lzo2], [lzo1x_decompress], [zlib="$zlib -DHAVE_LZO1X -llzo2"])
])
AC_SUBST(zlib)
AC_SUBST(system_aio)
AX_CHECK_EXTFS
AX_CHECK_PTHREAD
AX_CHECK_PTYFUNCS
AC_CHECK_LIB([yajl], [yajl_alloc], [],
    [AC_MSG_ERROR([Could not find yajl])])
AC_CHECK_LIB([z], [deflateCopy], [], [AC_MSG_ERROR([Could not find zlib])])
AC_CHECK_LIB([iconv], [libiconv_open], [libiconv="y"], [libiconv="n"])
AC_SUBST(libiconv)
AC_CHECK_HEADER([argp.h], [
AC_CHECK_LIB([argp], [argp_usage], [argp_ldflags="-largp"])
], [AC_MSG_ERROR([Could not find argp])])
AC_SUBST(argp_ldflags)

# FDT is needed only on ARM
case "$host_cpu" in
arm*|aarch64)
AC_CHECK_LIB([fdt], [fdt_create], [], [AC_MSG_ERROR([Could not find libfdt])])

# Check for libfdt >= 1.4.0. If present enable passthrough
# Note that libfdt doesn't provide versionning. So we need to rely on
# function present in new version.
# Use fdt_first_property_offset which has been correctly exported since v1.4.0
AC_CHECK_FUNC(fdt_first_property_offset, [partial_dt="y"], [partial_dt="n"])

AS_IF([test "x$partial_dt" = "xy" ],
      [AC_DEFINE([ENABLE_PARTIAL_DEVICE_TREE], [1],
                 [Enabling support partial device tree in libxl])],
      [AC_MSG_WARN([Disabling support for partial device tree in libxl.
       Please install libfdt library - version 1.4.0 or higher])])

# The functions fdt_{first,next}_subnode may not be available because:
#   * It has been introduced in 2013 => Doesn't work on Wheezy
#   * The prototype exists but the functions are not exposed. Don't ask why...
AC_CHECK_FUNCS([fdt_first_subnode fdt_next_subnode])
AC_CHECK_DECLS([fdt_first_subnode, fdt_next_subnode],,,[#include <libfdt.h>])

# The helper fdt_property_u32 is only present in libfdt >= 1.4.0
# It's an inline function, so only check if the declaration is present
AC_CHECK_DECLS([fdt_property_u32],,,[#include <libfdt.h>])
esac

# Checks for header files.
AC_CHECK_HEADERS([yajl/yajl_version.h sys/eventfd.h valgrind/memcheck.h utmp.h])

# Check for libnl3 >=3.2.8. If present enable remus network buffering.
PKG_CHECK_MODULES(LIBNL3, [libnl-3.0 >= 3.2.8 libnl-route-3.0 >= 3.2.8],
    [libnl3_lib="y"], [libnl3_lib="n"])

AS_IF([test "x$libnl3_lib" = "xn" ], [
    AC_MSG_WARN([Disabling support for Remus network buffering and COLO.
    Please install libnl3 libraries (including libnl3-route), command line tools and devel
    headers - version 3.2.8 or higher])
    AC_SUBST(libnl, [n])
    ],[
    AC_SUBST(libnl, [y])
])

AC_SUBST(LIBNL3_LIBS)
AC_SUBST(LIBNL3_CFLAGS)

fi # ! $rump

AX_AVAILABLE_SYSTEMD()

AS_IF([test "x$systemd" = "xy"], [
    AC_CONFIG_FILES([
    hotplug/Linux/systemd/proc-xen.mount
    hotplug/Linux/systemd/var-lib-xenstored.mount
    hotplug/Linux/systemd/xen-init-dom0.service
    hotplug/Linux/systemd/xen-qemu-dom0-disk-backend.service
    hotplug/Linux/systemd/xen-watchdog.service
    hotplug/Linux/systemd/xenconsoled.service
    hotplug/Linux/systemd/xendomains.service
    hotplug/Linux/systemd/xendriverdomain.service
    hotplug/Linux/systemd/xenstored.service
    ])
])

AC_ARG_ENABLE([9pfs],
    AS_HELP_STRING([--enable-9pfs],
                   [Explicitly enable 9pfs support in QEMU build (default is to defer to QEMU configure default)]),
    [AS_IF([test "x$enable_9pfs" = "xyes"], [ninepfs=y], [ninepfs=n])],[
])

AC_SUBST(ninepfs)

AC_ARG_ENABLE([pvshim],
    AS_HELP_STRING([--disable-pvshim],
                   [Disable pvshim build (enabled by default on 64bit x86)]),
    [AS_IF([test "x$enable_pvshim" = "xno"], [pvshim=n], [pvshim=y])], [
    cpu=`test -z "$target_cpu" && echo "$host_cpu" || echo "$target_cpu"`
    case "$cpu" in
        x86_64)
           pvshim="y";;
        *) pvshim="n";;
    esac
])
AC_SUBST(pvshim)

AC_OUTPUT()
