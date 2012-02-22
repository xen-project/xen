AC_DEFUN([AX_CHECK_PYTHON_DEVEL],
[AC_MSG_CHECKING([for python devel])

`$PYTHON -c '
import os.path, sys
for p in sys.path:
    if os.path.exists(p + "/config/Makefile"):
        sys.exit(0)
sys.exit(1)
' > /dev/null 2>&1`

if test "$?" != "0"
then
    AC_MSG_RESULT([no])
    AC_MSG_ERROR([Python devel package not found])
else
    AC_MSG_RESULT([yes])
fi])
