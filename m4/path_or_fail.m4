AC_DEFUN([AX_PATH_PROG_OR_FAIL],
[AC_PATH_PROG([$1], [$2], [no])
if test x"${$1}" = x"no"
then
    AC_MSG_ERROR([Unable to find $2, please install $2])
fi])
