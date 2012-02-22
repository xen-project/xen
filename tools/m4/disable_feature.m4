AC_DEFUN([AX_ARG_DISABLE_AND_EXPORT],
[AC_ARG_ENABLE([$1],
    AS_HELP_STRING([--disable-$1], [$2]))

AS_IF([test "x$enable_$1" = "xno"], [
    ax_cv_$1="n"
], [test "x$enable_$1" = "xyes"], [
    ax_cv_$1="y"
], [test -z $ax_cv_$1], [
    ax_cv_$1="y"
])
$1=$ax_cv_$1
AC_SUBST($1)])
