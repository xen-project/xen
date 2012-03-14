AC_DEFUN([AX_CHECK_PYTHON_DEVEL], [
ac_previous_cppflags=$CPPFLAGS
CPPFLAGS="$CFLAGS `$PYTHON-config --includes`"
ac_previous_ldflags=$LDFLAGS
for flag in `$PYTHON-config --ldflags`
do
    case $flag in
    -L*)
        LDFLAGS="$LDLFAGS $flag"
        ;;
    -lpython*)
        python_lib=`echo $flag | sed 's/^-l//'`
        ;;
    -l*)
        # Ignore other libraries, we are only interested in testing python-dev
        ;;
    *)
        AC_MSG_WARN([Strange ldflag found in $PYTHON-config output: $flag])
        ;;
    esac
done
AC_CHECK_HEADER([Python.h], [],
    [AC_MSG_ERROR([Unable to find Python development headers])],)
AC_CHECK_LIB($python_lib, PyArg_ParseTuple, [],
    [AC_MSG_ERROR([Unable to find a suitable python development library])])
CPPFLAGS=$ac_previous_cppflags
LDLFAGS=$ac_previous_ldflags
])
