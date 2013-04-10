AC_DEFUN([AX_CHECK_PYTHON_DEVEL], [
ac_previous_cppflags=$CPPFLAGS
ac_previous_ldflags=$LDFLAGS
ac_python_version=`$PYTHON -c 'import distutils.sysconfig; \
    print distutils.sysconfig.get_config_var("VERSION")'`
AC_PATH_PROG([pyconfig], [$PYTHON-config], [no])
AS_IF([test x"$pyconfig" = x"no"], [
    dnl For those that don't have python-config
    CPPFLAGS="$CFLAGS `$PYTHON -c 'import distutils.sysconfig; \
        print "-I" + distutils.sysconfig.get_config_var("INCLUDEPY")'`"
    CPPFLAGS="$CPPFLAGS `$PYTHON -c 'import distutils.sysconfig; \
        print distutils.sysconfig.get_config_var("CFLAGS")'`"
    LDFLAGS="$LDFLAGS `$PYTHON -c 'import distutils.sysconfig; \
        print distutils.sysconfig.get_config_var("LIBS")'`"
    LDFLAGS="$LDFLAGS `$PYTHON -c 'import distutils.sysconfig; \
        print distutils.sysconfig.get_config_var("SYSLIBS")'`"
    LDFLAGS="$LDFLAGS `$PYTHON -c 'import distutils.sysconfig; \
        print "-L" + distutils.sysconfig.get_python_lib(plat_specific=1,\
        standard_lib=1) + "/config"'`"
    LDFLAGS="$LDFLAGS `$PYTHON -c 'import distutils.sysconfig; \
        print distutils.sysconfig.get_config_var("LINKFORSHARED")'`"
    LDFLAGS="$LDFLAGS `$PYTHON -c 'import distutils.sysconfig; \
        print distutils.sysconfig.get_config_var("LDFLAGS")'`"
], [
    dnl If python-config is found use it
    CPPFLAGS="$CFLAGS `$PYTHON-config --cflags`"
    LDFLAGS="$LDFLAGS `$PYTHON-config --ldflags`"
])

AC_CHECK_HEADER([Python.h], [],
    [AC_MSG_ERROR([Unable to find Python development headers])],)
AC_CHECK_LIB(python$ac_python_version, PyArg_ParseTuple, [],
    [AC_MSG_ERROR([Unable to find a suitable python development library])])
CPPFLAGS=$ac_previous_cppflags
LDLFAGS=$ac_previous_ldflags
])
