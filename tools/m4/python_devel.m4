AC_DEFUN([AX_CHECK_PYTHON_DEVEL], [
ac_python_version=`$PYTHON -c 'import distutils.sysconfig; \
    print distutils.sysconfig.get_config_var("VERSION")'`
ac_previous_cppflags=$CPPFLAGS
CPPFLAGS="$CFLAGS `$PYTHON -c 'import distutils.sysconfig; \
    print "-I" + distutils.sysconfig.get_config_var("INCLUDEPY")'`"
CPPFLAGS="$CPPFLAGS `$PYTHON -c 'import distutils.sysconfig; \
    print distutils.sysconfig.get_config_var("CFLAGS")'`"
ac_previous_ldflags=$LDFLAGS
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

AC_CHECK_HEADER([Python.h], [],
    [AC_MSG_ERROR([Unable to find Python development headers])],)
AC_CHECK_LIB(python$ac_python_version, PyArg_ParseTuple, [],
    [AC_MSG_ERROR([Unable to find a suitable python development library])])
CPPFLAGS=$ac_previous_cppflags
LDLFAGS=$ac_previous_ldflags
])
