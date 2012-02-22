AC_DEFUN([AX_DEFAULT_LIB],
[AS_IF([test -d "$prefix/lib64"], [
    LIB_PATH="lib64"
],[
    LIB_PATH="lib"
])
AC_SUBST(LIB_PATH)])

