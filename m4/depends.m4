
AC_DEFUN([AX_DEPENDS_PATH_PROG], [
AS_IF([test "x$$1" = "xy"], [AX_PATH_PROG_OR_FAIL([$2], [$3])], [
AS_IF([test "x$$1" = "xn"], [
$2="/$3-disabled-in-configure-script"
], [
AC_PATH_PROG([$2], [$3], [no])
AS_IF([test x"${$2}" = "xno"], [
$1=n
$2="/$3-disabled-in-configure-script"
])
])
])
AC_SUBST($2)
])
