AC_DEFUN([AX_STUBDOM_DEFAULT_ENABLE], [
AC_ARG_ENABLE([$1],
AS_HELP_STRING([--disable-$1], [Build and install $1 (default is ENABLED)]),[
AX_STUBDOM_INTERNAL([$1], [$2])
],[
AX_ENABLE_STUBDOM([$1], [$2])
])
AC_SUBST([$2])
])

AC_DEFUN([AX_STUBDOM_DEFAULT_DISABLE], [
AC_ARG_ENABLE([$1],
AS_HELP_STRING([--enable-$1], [Build and install $1 (default is DISABLED)]),[
AX_STUBDOM_INTERNAL([$1], [$2])
],[
AX_DISABLE_STUBDOM([$1], [$2])
])
AC_SUBST([$2])
])

AC_DEFUN([AX_STUBDOM_CONDITIONAL], [
AC_ARG_ENABLE([$1],
AS_HELP_STRING([--enable-$1], [Build and install $1]),[
AX_STUBDOM_INTERNAL([$1], [$2])
])
])

AC_DEFUN([AX_STUBDOM_CONDITIONAL_FINISH], [
AS_IF([test "x$$2" = "xy" || test "x$$2" = "x"], [
AX_ENABLE_STUBDOM([$1],[$2])
],[
AX_DISABLE_STUBDOM([$1],[$2])
])
AC_SUBST([$2])
])

AC_DEFUN([AX_STUBDOM_AUTO_DEPENDS], [
AS_IF([test "x$$1" = "x" && test "x$$2" = "xn"], [
$1="n"
])
])


AC_DEFUN([AX_ENABLE_STUBDOM], [
$2=y
STUBDOM_TARGETS="$STUBDOM_TARGETS $2"
STUBDOM_BUILD="$STUBDOM_BUILD $1"
STUBDOM_INSTALL="$STUBDOM_INSTALL install-$2"
STUBDOM_UNINSTALL="$STUBDOM_UNINSTALL install-$2"
])

AC_DEFUN([AX_DISABLE_STUBDOM], [
$2=n
])

dnl Don't call this outside of this file
AC_DEFUN([AX_STUBDOM_INTERNAL], [
AS_IF([test "x$enableval" = "xyes"], [
AX_ENABLE_STUBDOM([$1], [$2])
],[
AS_IF([test "x$enableval" = "xno"],[
AX_DISABLE_STUBDOM([$1], [$2])
])
])
])

AC_DEFUN([AX_STUBDOM_FINISH], [
AC_SUBST(STUBDOM_TARGETS)
AC_SUBST(STUBDOM_BUILD)
AC_SUBST(STUBDOM_INSTALL)
AC_SUBST(STUBDOM_UNINSTALL)
echo "Will build the following stub domains:"
for x in $STUBDOM_BUILD; do
	echo "  $x"
done
])

AC_DEFUN([AX_STUBDOM_LIB], [
AC_ARG_VAR([$1_URL], [Download url for $2])
AS_IF([test "x$$1_URL" = "x"], [
	AS_IF([test "x$extfiles" = "xy"],
		[$1_URL=\@S|@\@{:@XEN_EXTFILES_URL\@:}@],
		[$1_URL="$4"])
	])
$1_VERSION="$3"
AC_SUBST($1_URL)
AC_SUBST($1_VERSION)
])

AC_DEFUN([AX_STUBDOM_LIB_NOEXT], [
AC_ARG_VAR([$1_URL], [Download url for $2])
AS_IF([test "x$$1_URL" = "x"], [
	$1_URL="$4"
	])
$1_VERSION="$3"
AC_SUBST($1_URL)
AC_SUBST($1_VERSION)
])
