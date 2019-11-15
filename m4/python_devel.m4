AC_DEFUN([AX_CHECK_PYTHON_DEVEL], [
ac_previous_cppflags=$CPPFLAGS
ac_previous_ldflags=$LDFLAGS
ac_previous_libs=$LIBS
AC_PATH_PROG([pyconfig], [$PYTHON-config], [no])
AS_IF([test x"$pyconfig" = x"no"], [
    dnl For those that don't have python-config
    CPPFLAGS="$CFLAGS `$PYTHON -c 'import distutils.sysconfig; \
        print("-I" + distutils.sysconfig.get_config_var("INCLUDEPY"))'`"
    CPPFLAGS="$CPPFLAGS `$PYTHON -c 'import distutils.sysconfig; \
        print(distutils.sysconfig.get_config_var("CFLAGS"))'`"
    LDFLAGS="$LDFLAGS `$PYTHON -c 'import distutils.sysconfig; \
        print("-L" + distutils.sysconfig.get_python_lib(plat_specific=1,\
        standard_lib=1) + "/config")'`"
    LDFLAGS="$LDFLAGS `$PYTHON -c 'import distutils.sysconfig; \
        print(distutils.sysconfig.get_config_var("LINKFORSHARED"))'`"
    LDFLAGS="$LDFLAGS `$PYTHON -c 'import distutils.sysconfig; \
        print(distutils.sysconfig.get_config_var("LDFLAGS"))'`"
    LIBS="$LIBS `$PYTHON -c 'import distutils.sysconfig; \
        print(distutils.sysconfig.get_config_var("LIBS"))'`"
    LIBS="$LIBS `$PYTHON -c 'import distutils.sysconfig; \
        print(distutils.sysconfig.get_config_var("SYSLIBS"))'`"
], [
    dnl If python-config is found use it
    CPPFLAGS="$CFLAGS `$PYTHON-config --cflags`"
    dnl We need to use --embed with python 3.8 but not with earlier version so
    dnl check if it is recognized.
    python_devel_embed=""
    if $PYTHON-config --embed >/dev/null 2>/dev/null; then
      python_devel_embed="--embed"
    fi
    LDFLAGS="$LDFLAGS `$PYTHON-config --ldflags $python_devel_embed`"
    LIBS="$LIBS `$PYTHON-config --libs $python_devel_embed`"
    unset python_devel_embed
])

AC_CHECK_HEADER([Python.h], [],
    [AC_MSG_ERROR([Unable to find Python development headers])],)
AC_CHECK_FUNC([PyArg_ParseTuple], [],
    [AC_MSG_ERROR([Unable to find a suitable python development library])]) 

CPPFLAGS=$ac_previous_cppflags
LDFLAGS=$ac_previous_ldflags
LIBS=$ac_previous_libs
])
