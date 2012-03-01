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

AC_USE_SYSTEM_EXTENSIONS
AC_CANONICAL_HOST

# M4 Macro includes
m4_include([m4/enable_feature.m4])
m4_include([m4/disable_feature.m4])
m4_include([m4/path_or_fail.m4])
m4_include([m4/python_xml.m4])
m4_include([m4/python_version.m4])
m4_include([m4/python_devel.m4])
m4_include([m4/ocaml.m4])
m4_include([m4/default_lib.m4])
m4_include([m4/set_cflags_ldflags.m4])
m4_include([m4/uuid.m4])
m4_include([m4/pkg.m4])

# Enable/disable options
AX_ARG_ENABLE_AND_EXPORT([githttp], [Download GIT repositories via HTTP])
AX_ARG_DISABLE_AND_EXPORT([monitors],
    [Disable xenstat and xentop monitoring tools])
AX_ARG_ENABLE_AND_EXPORT([vtpm], [Enable Virtual Trusted Platform Module])
AX_ARG_ENABLE_AND_EXPORT([xapi], [Enable Xen API Bindings])
AX_ARG_DISABLE_AND_EXPORT([pythontools], [Disable Python tools])
AX_ARG_DISABLE_AND_EXPORT([ocamltools], [Disable Ocaml tools])
AX_ARG_ENABLE_AND_EXPORT([miniterm], [Enable miniterm])
AX_ARG_ENABLE_AND_EXPORT([lomount], [Enable lomount])
AX_ARG_DISABLE_AND_EXPORT([debug], [Disable debug build of tools])

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
AC_ARG_VAR([IP], [Path to ip tool])
AC_ARG_VAR([BISON], [Path to Bison parser generator])
AC_ARG_VAR([FLEX], [Path to Flex lexical analyser generator])
AC_ARG_VAR([CURL], [Path to curl-config tool])
AC_ARG_VAR([XML], [Path to xml2-config tool])
AC_ARG_VAR([BASH], [Path to bash shell])
AC_ARG_VAR([XGETTEXT], [Path to xgetttext tool])

# Checks for programs.
AC_PROG_SED
AC_PROG_CC
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_INSTALL
AX_PATH_PROG_OR_FAIL([PERL], [perl])
AX_PATH_PROG_OR_FAIL([IP], [ip])
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
    AX_CHECK_PYTHON_XML()
    AX_CHECK_PYTHON_DEVEL()
])
AX_PATH_PROG_OR_FAIL([XGETTEXT], [xgettext])
AX_CHECK_UUID
PKG_CHECK_MODULES(glib, glib-2.0)

# Check library path
AX_DEFAULT_LIB

# Checks for libraries.
AC_CHECK_LIB([aio], [io_setup], [system_aio="y"], [system_aio="n"])
AC_SUBST(system_aio)
AC_CHECK_LIB([crypto], [MD5], [], [AC_MSG_ERROR([Could not find libcrypto])])
AC_CHECK_LIB([ext2fs], [ext2fs_open2], [libext2fs="y"], [libext2fs="n"])
AC_SUBST(libext2fs)
AC_CHECK_LIB([gcrypt], [gcry_md_hash_buffer], [libgcrypt="y"], [libgcrypt="n"])
AC_SUBST(libgcrypt)
AC_CHECK_LIB([pthread], [pthread_create], [] ,
    [AC_MSG_ERROR([Could not find libpthread])])
AC_CHECK_LIB([rt], [clock_gettime])
AC_CHECK_LIB([uuid], [uuid_clear], [],
    [AC_MSG_ERROR([Could not find libuuid])])
AC_CHECK_LIB([yajl], [yajl_alloc], [],
    [AC_MSG_ERROR([Could not find yajl])])
AC_CHECK_LIB([z], [deflateCopy], [], [AC_MSG_ERROR([Could not find zlib])])
AC_CHECK_LIB([iconv], [libiconv_open], [libiconv="y"], [libiconv="n"])
AC_SUBST(libiconv)

# Checks for header files.
AC_FUNC_ALLOCA
AC_CHECK_HEADERS([ \
                arpa/inet.h fcntl.h inttypes.h libintl.h limits.h malloc.h \
                netdb.h netinet/in.h stddef.h stdint.h stdlib.h string.h \
                strings.h sys/file.h sys/ioctl.h sys/mount.h sys/param.h \
                sys/socket.h sys/statvfs.h sys/time.h syslog.h termios.h \
                unistd.h yajl/yajl_version.h \
                ])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_UID_T
AC_C_INLINE
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_C_RESTRICT
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_CHECK_MEMBERS([struct stat.st_blksize])
AC_STRUCT_ST_BLOCKS
AC_CHECK_MEMBERS([struct stat.st_rdev])
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T
AC_CHECK_TYPES([ptrdiff_t])

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_FORK
AC_FUNC_FSEEKO
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_HEADER_MAJOR
AC_FUNC_MALLOC
AC_FUNC_MKTIME
AC_FUNC_MMAP
AC_FUNC_REALLOC
AC_FUNC_STRNLEN
AC_FUNC_STRTOD
AC_CHECK_FUNCS([ \
                alarm atexit bzero clock_gettime dup2 fdatasync ftruncate \
                getcwd gethostbyname gethostname getpagesize gettimeofday \
                inet_ntoa isascii localtime_r memchr memmove memset mkdir \
                mkfifo munmap pathconf realpath regcomp rmdir select setenv \
                socket strcasecmp strchr strcspn strdup strerror strndup \
                strpbrk strrchr strspn strstr strtol strtoul strtoull tzset \
                uname \
                ])

AC_OUTPUT()
