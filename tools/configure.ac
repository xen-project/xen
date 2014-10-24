#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.67])
AC_INIT([Xen Hypervisor Tools], m4_esyscmd([../version.sh ../xen/Makefile]),
    [xen-devel@lists.xen.org], [xen], [http://www.xen.org/])
AC_CONFIG_SRCDIR([libxl/libxl.c])
AC_CONFIG_FILES([
../config/Tools.mk
hotplug/FreeBSD/rc.d/xencommons
hotplug/Linux/init.d/sysconfig.xencommons
hotplug/Linux/init.d/xen-watchdog
hotplug/Linux/init.d/xencommons
hotplug/Linux/init.d/xendomains
hotplug/Linux/systemd/proc-xen.mount
hotplug/Linux/systemd/var-lib-xenstored.mount
hotplug/Linux/systemd/xen-init-dom0.service
hotplug/Linux/systemd/xen-qemu-dom0-disk-backend.service
hotplug/Linux/systemd/xen-watchdog.service
hotplug/Linux/systemd/xenconsoled.service
hotplug/Linux/systemd/xendomains.service
hotplug/Linux/systemd/xenstored.service
hotplug/Linux/systemd/xenstored.socket
hotplug/Linux/systemd/xenstored_ro.socket
hotplug/Linux/vif-setup
hotplug/Linux/xen-backend.rules
hotplug/Linux/xen-hotplug-common.sh
hotplug/Linux/xendomains
hotplug/NetBSD/rc.d/xencommons
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
rumpxen) CONFIG_RUMP=y; rump=true ;;
*)       CONFIG_RUMP=n; rump=false ;;
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
AX_ARG_DEFAULT_ENABLE([debug], [Disable debug build of tools])
AX_ARG_DEFAULT_DISABLE([blktap1], [Enable blktap1 tools])

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
blktap2
blktap
"
;;
*)
LINUX_BACKEND_MODULES=
;;
esac])
LINUX_BACKEND_MODULES="`eval echo $LINUX_BACKEND_MODULES`"
AC_SUBST(LINUX_BACKEND_MODULES)

dnl Enable blktap2 on Linux only.
AC_ARG_ENABLE([blktap2],
    AS_HELP_STRING([--enable-blktap2],
                   [Enable blktap2, (DEFAULT is on for Linux, otherwise off)]),,[
    case "$host_os" in
        linux*)
           enable_blktap2="yes";;
        *) enable_blktap2="no";;
    esac
])
AS_IF([test "x$enable_blktap2" = "xyes"], [
AC_DEFINE([HAVE_BLKTAP2], [1], [Blktap2 enabled])
    blktap2=y],[
    blktap2=n
])
AC_SUBST(blktap2)


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
    yes) qemu_xen=n ; qemu_xen_path=qemu ;;
    no)  qemu_xen=y ; qemu_xen_path= ;;
    *)   qemu_xen=n ; qemu_xen_path=$withval ;;
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
AS_IF([test "x$qemu_xen" = "xn"], [
    AC_DEFINE_UNQUOTED([QEMU_XEN_PATH], ["$qemu_xen_path"], [Qemu Xen path])
])
AC_SUBST(qemu_xen)

AC_ARG_WITH([system-seabios],
    AS_HELP_STRING([--with-system-seabios@<:@=PATH@:>@],
       [Use system supplied seabios PATH instead of building and installing
        our own version]),[
    case $withval in
        no) seabios_path= ;;
        *)  seabios_path=$withval ;;
    esac
],[])
AC_SUBST(seabios_path)

AC_ARG_WITH([system-ovmf],
    AS_HELP_STRING([--with-system-ovmf@<:@=PATH@:>@],
       [Use system supplied OVMF PATH instead of building and installing
        our own version]),[
    case $withval in
        no) ovmf_path= ;;
        *)  ovmf_path=$withval ;;
    esac
],[])
AC_SUBST(ovmf_path)

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
AC_ARG_VAR([CURL], [Path to curl-config tool])
AC_ARG_VAR([XML], [Path to xml2-config tool])
AC_ARG_VAR([BASH], [Path to bash shell])
AC_ARG_VAR([XGETTEXT], [Path to xgetttext tool])
AC_ARG_VAR([AS86], [Path to as86 tool])
AC_ARG_VAR([LD86], [Path to ld86 tool])
AC_ARG_VAR([BCC], [Path to bcc tool])
AC_ARG_VAR([IASL], [Path to iasl tool])

# Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET
AC_PROG_INSTALL
AC_PATH_PROG([BISON], [bison])
AC_PATH_PROG([FLEX], [flex])
AX_PATH_PROG_OR_FAIL([PERL], [perl])

AC_PROG_OCAML
AC_PROG_FINDLIB

AS_IF([test "x$ocamltools" = "xy"], [
    AS_IF([test "x$OCAMLC" = "xno" || test "x$OCAMLFIND" = "xno"], [
        AS_IF([test "x$enable_ocamltools" = "xyes"], [
            AC_MSG_ERROR([Ocaml tools enabled, but unable to find Ocaml])])
        ocamltools="n"
    ], [
        AX_COMPARE_VERSION([$OCAMLVERSION], [lt], [3.09.3], [
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
AX_PATH_PROG_OR_FAIL([BASH], [bash])
AS_IF([echo "$PYTHON" | grep -q "^/"], [
    PYTHONPATH=$PYTHON
    PYTHON=`basename $PYTHONPATH`
],[test -z "$PYTHON"], [PYTHON="python"],
[AC_MSG_ERROR([PYTHON specified, but is not an absolute path])])
AX_PATH_PROG_OR_FAIL([PYTHONPATH], [$PYTHON])
AX_CHECK_PYTHON_VERSION([2], [3])

AS_IF([test "$cross_compiling" != yes], [
    AX_CHECK_PYTHON_DEVEL()
])

if ! $rump; then

AX_PATH_PROG_OR_FAIL([XGETTEXT], [xgettext])
dnl as86, ld86, bcc and iasl are only required when the host system is x86*.
dnl "host" here means the platform on which the hypervisor and tools is
dnl going to run, not the platform on which we are building (known as
dnl "build" in gnu speak).
case "$host_cpu" in
i[[3456]]86|x86_64)
    AX_PATH_PROG_OR_FAIL([AS86], [as86])
    AX_PATH_PROG_OR_FAIL([LD86], [ld86])
    AX_PATH_PROG_OR_FAIL([BCC], [bcc])
    AX_PATH_PROG_OR_FAIL([IASL], [iasl])
    ;;
esac
 AX_CHECK_UUID
 AX_CHECK_CURSES
PKG_CHECK_MODULES(glib, [glib-2.0 >= 2.12])
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
AS_IF([test "x$enable_blktap1" = "xyes" || test "x$enable_blktap2" = "xyes"], [
AC_CHECK_LIB([aio], [io_setup], [], [AC_MSG_ERROR([Could not find libaio])])
])
AC_SUBST(system_aio)
AC_CHECK_LIB([crypto], [MD5], [], [AC_MSG_ERROR([Could not find libcrypto])])
AX_CHECK_EXTFS
AC_CHECK_LIB([gcrypt], [gcry_md_hash_buffer], [libgcrypt="y"], [libgcrypt="n"])
AC_SUBST(libgcrypt)
AX_CHECK_PTHREAD
AX_CHECK_PTYFUNCS
AC_CHECK_LIB([yajl], [yajl_alloc], [],
    [AC_MSG_ERROR([Could not find yajl])])
AC_CHECK_LIB([z], [deflateCopy], [], [AC_MSG_ERROR([Could not find zlib])])
AC_CHECK_LIB([iconv], [libiconv_open], [libiconv="y"], [libiconv="n"])
AC_SUBST(libiconv)

# FDT is needed only on ARM
case "$host_cpu" in
arm*|aarch64)
AC_CHECK_LIB([fdt], [fdt_create], [], [AC_MSG_ERROR([Could not find libfdt])])
esac

# Checks for header files.
AC_CHECK_HEADERS([yajl/yajl_version.h sys/eventfd.h valgrind/memcheck.h utmp.h])

# Check for libnl3 >=3.2.8. If present enable remus network buffering.
PKG_CHECK_MODULES(LIBNL3, [libnl-3.0 >= 3.2.8 libnl-route-3.0 >= 3.2.8],
    [libnl3_lib="y"], [libnl3_lib="n"])

AS_IF([test "x$libnl3_lib" = "xn" ], [
    AC_MSG_WARN([Disabling support for Remus network buffering.
    Please install libnl3 libraries, command line tools and devel
    headers - version 3.2.8 or higher])
    AC_SUBST(remus_netbuf, [n])
    ],[
    AC_SUBST(remus_netbuf, [y])
])

AC_SUBST(LIBNL3_LIBS)
AC_SUBST(LIBNL3_CFLAGS)

fi # ! $rump

AX_AVAILABLE_SYSTEMD()
AC_OUTPUT()

