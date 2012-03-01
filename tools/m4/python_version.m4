AC_DEFUN([AX_CHECK_PYTHON_VERSION],
[AC_MSG_CHECKING([for python version >= $1.$2 ])
`$PYTHON -c 'import sys; sys.exit(eval("sys.version_info < ($1, $2)"))'`
if test "$?" != "0"
then
    python_version=`$PYTHON -V 2>&1`
    AC_MSG_RESULT([no])
    AC_MSG_ERROR(
        [$python_version is too old, minimum required version is $1.$2])
else
    AC_MSG_RESULT([yes])
fi])
