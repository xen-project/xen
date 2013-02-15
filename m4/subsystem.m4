AC_DEFUN([AX_ENABLE_SUBSYSTEM], [
$1=y
SUBSYSTEMS="$SUBSYSTEMS $1"
])

AC_DEFUN([AX_DISABLE_SUBSYSTEM], [
$1=n
])

AC_DEFUN([AX_SUBSYSTEM_DEFAULT_ENABLE], [
AC_ARG_ENABLE([$1],
AS_HELP_STRING([--disable-$1], [Disable build and install of $1]),[
AX_SUBSYSTEM_INTERNAL([$1])
],[
AX_ENABLE_SUBSYSTEM([$1])
])
AX_SUBSYSTEM_CONFIGURE([$1])
AC_SUBST([$1])
])

AC_DEFUN([AX_SUBSYSTEM_DEFAULT_DISABLE], [
AC_ARG_ENABLE([$1],
AS_HELP_STRING([--enable-$1], [Enable build and install of $1]),[
AX_SUBSYSTEM_INTERNAL([$1])
],[
AX_DISABLE_SUBSYSTEM([$1])
])
AX_SUBSYSTEM_CONFIGURE([$1])
AC_SUBST([$1])
])

AC_DEFUN([AX_SUBSYSTEM_CONDITIONAL], [
AC_ARG_ENABLE([$1],
AS_HELP_STRING([--enable-$1], [Enable build and install of $1]),[
AX_SUBSYSTEM_INTERNAL([$1])
],[
AS_IF([test "x$2" = "xy"],[
AX_ENABLE_SUBSYSTEM([$1])
],[
AX_DISABLE_SUBSYSTEM([$1])
])
])
AX_SUBSYSTEM_CONFIGURE([$1])
AC_SUBST($1)
])

AC_DEFUN([AX_SUBSYSTEM_FINISH], [
AC_SUBST(SUBSYSTEMS)
echo "Will build the following subsystems:"
for x in $SUBSYSTEMS; do
	echo "  $x"
done
])

AC_DEFUN([AX_SUBSYSTEM_INTERNAL], [
AS_IF([test "x$enableval" = "xyes"], [
AX_ENABLE_SUBSYSTEM([$1])
],[
AS_IF([test "x$enableval" = "xno"],[
AX_DISABLE_SUBSYSTEM([$1])
])
])
])

AC_DEFUN([AX_SUBSYSTEM_CONFIGURE], [
AS_IF([test -e "$1/configure"], [
if test "x$$1" = "xy" || test "x$$1" = "x" ; then
    AC_CONFIG_SUBDIRS([$1])
fi
])
])
