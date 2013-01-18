AC_DEFUN([AX_SUBSYSTEM_DEFAULT_ENABLE], [
AC_ARG_ENABLE([$1],
AS_HELP_STRING([--disable-$1], [Disable build and install of $1]),[
$1=n
],[
$1=y
SUBSYSTEMS="$SUBSYSTEMS $1"
AS_IF([test -e "$1/configure"], [
AC_CONFIG_SUBDIRS([$1])
])
])
AC_SUBST($1)
])

AC_DEFUN([AX_SUBSYSTEM_DEFAULT_DISABLE], [
AC_ARG_ENABLE([$1],
AS_HELP_STRING([--enable-$1], [Enable build and install of $1]),[
$1=y
SUBSYSTEMS="$SUBSYSTEMS $1"
AS_IF([test -e "$1/configure"], [
AC_CONFIG_SUBDIRS([$1])
])
],[
$1=n
])
AC_SUBST($1)
])


AC_DEFUN([AX_SUBSYSTEM_FINISH], [
AC_SUBST(SUBSYSTEMS)
])
