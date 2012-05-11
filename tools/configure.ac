#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.67])
AC_INIT([Xen Hypervisor], m4_esyscmd([../version.sh ../xen/Makefile]),
    [xen-devel@lists.xensource.com])
AC_CONFIG_SRCDIR([libxl/libxl.c])
AC_CONFIG_FILES([../config/Tools.mk])
AC_CONFIG_HEADERS([config.h])
AC_PREFIX_DEFAULT([/usr])
AC_CONFIG_AUX_DIR([.])

# Check if CFLAGS, LDFLAGS, LIBS, CPPFLAGS or CPP is set and print a warning

AS_IF([test -n "$CC$CFLAGS$LDFLAGS$LIBS$CPPFLAGS$CPP"], [
    AC_MSG_WARN(
[Setting CC, CFLAGS, LDFLAGS, LIBS, CPPFLAGS or CPP is not \
recommended, use PREPEND_INCLUDES, PREPEND_LIB, \
APPEND_INCLUDES and APPEND_LIB instead when possible.])
])

# M4 Macro includes
m4_include([m4/savevar.m4])
m4_include([m4/features.m4])
m4_include([m4/path_or_fail.m4])
m4_include([m4/python_version.m4])
m4_include([m4/python_devel.m4])
m4_include([m4/ocaml.m4])
m4_include([m4/default_lib.m4])
m4_include([m4/set_cflags_ldflags.m4])
m4_include([m4/uuid.m4])
m4_include([m4/pkg.m4])
m4_include([m4/curses.m4])
m4_include([m4/pthread.m4])

# Enable/disable options
AX_ARG_DEFAULT_DISABLE([githttp], [Download GIT repositories via HTTP])
AX_ARG_DEFAULT_ENABLE([monitors], [Disable xenstat and xentop monitoring tools])
AX_ARG_DEFAULT_DISABLE([vtpm], [Enable Virtual Trusted Platform Module])
AX_ARG_DEFAULT_DISABLE([xenapi], [Enable Xen API Bindings])
AX_ARG_DEFAULT_ENABLE([pythontools], [Disable Python tools])
AX_ARG_DEFAULT_ENABLE([ocamltools], [Disable Ocaml tools])
AX_ARG_DEFAULT_DISABLE([miniterm], [Enable miniterm])
AX_ARG_DEFAULT_DISABLE([lomount], [Enable lomount])
AX_ARG_DEFAULT_DISABLE([ovmf], [Enable OVMF])
AX_ARG_DEFAULT_ENABLE([rombios], [Disable ROM BIOS])
AX_ARG_DEFAULT_ENABLE([seabios], [Disable SeaBIOS])
AX_ARG_DEFAULT_ENABLE([debug], [Disable debug build of tools])

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
AS_IF([test "x$xapi" = "xy"], [
    AX_PATH_PROG_OR_FAIL([CURL], [curl-config])
    AX_PATH_PROG_OR_FAIL([XML], [xml2-config])
])
AS_IF([test "x$ocamltools" = "xy"], [
    AC_PROG_OCAML
    AS_IF([test "x$OCAMLC" = "xno"], [
        AS_IF([test "x$enable_ocamltools" = "xyes"], [
            AC_MSG_ERROR([Ocaml tools enabled, but unable to find Ocaml])])
        ocamltools="n"
    ])
])
AX_PATH_PROG_OR_FAIL([BASH], [bash])
AS_IF([test "x$pythontools" = "xy"], [
    AS_IF([echo "$PYTHON" | grep -q "^/"], [
        PYTHONPATH=$PYTHON
        PYTHON=`basename $PYTHONPATH`
    ],[test -z "$PYTHON"], [PYTHON="python"],
    [AC_MSG_ERROR([PYTHON specified, but is not an absolute path])])
    AX_PATH_PROG_OR_FAIL([PYTHONPATH], [$PYTHON])
    AX_CHECK_PYTHON_VERSION([2], [3])
    AX_CHECK_PYTHON_DEVEL()
])
AX_PATH_PROG_OR_FAIL([XGETTEXT], [xgettext])
AX_PATH_PROG_OR_FAIL([AS86], [as86])
AX_PATH_PROG_OR_FAIL([LD86], [ld86])
AX_PATH_PROG_OR_FAIL([BCC], [bcc])
AX_PATH_PROG_OR_FAIL([IASL], [iasl])
AX_CHECK_UUID
AX_CHECK_CURSES
PKG_CHECK_MODULES(glib, glib-2.0)

# Check library path
AX_DEFAULT_LIB

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
AC_CHECK_LIB([aio], [io_setup], [system_aio="y"], [system_aio="n"])
AC_SUBST(system_aio)
AC_CHECK_LIB([crypto], [MD5], [], [AC_MSG_ERROR([Could not find libcrypto])])
AC_CHECK_LIB([ext2fs], [ext2fs_open2], [libext2fs="y"], [libext2fs="n"])
AC_SUBST(libext2fs)
AC_CHECK_LIB([gcrypt], [gcry_md_hash_buffer], [libgcrypt="y"], [libgcrypt="n"])
AC_SUBST(libgcrypt)
AX_CHECK_PTHREAD
AC_CHECK_LIB([yajl], [yajl_alloc], [],
    [AC_MSG_ERROR([Could not find yajl])])
AC_CHECK_LIB([z], [deflateCopy], [], [AC_MSG_ERROR([Could not find zlib])])
AC_CHECK_LIB([iconv], [libiconv_open], [libiconv="y"], [libiconv="n"])
AC_SUBST(libiconv)

# Checks for header files.
AC_CHECK_HEADERS([yajl/yajl_version.h])

AC_OUTPUT()
