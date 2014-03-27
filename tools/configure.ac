#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.67])
AC_INIT([Xen Hypervisor Tools], m4_esyscmd([../version.sh ../xen/Makefile]),
    [xen-devel@lists.xen.org], [xen], [http://www.xen.org/])
AC_CONFIG_SRCDIR([libxl/libxl.c])
AC_CONFIG_FILES([../config/Tools.mk])
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
m4_include([../m4/python_version.m4])
m4_include([../m4/python_devel.m4])
m4_include([../m4/ocaml.m4])
m4_include([../m4/checkpolicy.m4])
m4_include([../m4/set_cflags_ldflags.m4])
m4_include([../m4/uuid.m4])
m4_include([../m4/pkg.m4])
m4_include([../m4/curses.m4])
m4_include([../m4/pthread.m4])
m4_include([../m4/ptyfuncs.m4])
m4_include([../m4/extfs.m4])
m4_include([../m4/fetcher.m4])
m4_include([../m4/ax_compare_version.m4])

# Enable/disable options
AX_ARG_DEFAULT_DISABLE([githttp], [Download GIT repositories via HTTP])
AX_ARG_DEFAULT_ENABLE([monitors], [Disable xenstat and xentop monitoring tools])
AX_ARG_DEFAULT_ENABLE([ocamltools], [Disable Ocaml tools])
AX_ARG_DEFAULT_ENABLE([xsmpolicy], [Disable XSM policy compilation])
AX_ARG_DEFAULT_DISABLE([ovmf], [Enable OVMF])
AX_ARG_DEFAULT_ENABLE([rombios], [Disable ROM BIOS])
AX_ARG_DEFAULT_ENABLE([seabios], [Disable SeaBIOS])
AX_ARG_DEFAULT_ENABLE([debug], [Disable debug build of tools])
AX_ARG_DEFAULT_DISABLE([blktap1], [Enable blktap1 tools])

AC_ARG_ENABLE([qemu-traditional],
    AS_HELP_STRING([--enable-qemu-traditional],
                   [Enable qemu traditional device model, (DEFAULT is on for x86, otherwise off)]),,[
    case "$host_cpu" in
        i[[3456]]86|x86_64)
           enable_qemu_traditional="yes";;
        *) enable_qemu_traditional="no";;
    esac
])
AS_IF([test "x$enable_qemu_traditional" = "xyes"], [
AC_DEFINE([HAVE_QEMU_TRADITIONAL], [1], [Qemu traditional enabled])
    qemu_traditional=y],[
    qemu_traditional=n
])
AC_SUBST(qemu_traditional)

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
AS_IF([test "x$ocamltools" = "xy"], [
    AC_PROG_OCAML
    AC_PROG_FINDLIB
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
AC_CHECK_LIB([aio], [io_setup], [], [AC_MSG_ERROR([Could not find libaio])])
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
AC_CHECK_HEADERS([yajl/yajl_version.h sys/eventfd.h])

AC_OUTPUT()

