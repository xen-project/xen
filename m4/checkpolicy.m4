AC_DEFUN([AC_PROG_CHECKPOLICY],
[dnl
  # check for a checkpolicy binary with support for -t xen
  AC_CHECK_TOOL([CHECKPOLICY],[checkpolicy],[no])

  if test "$CHECKPOLICY" != "no"; then
     CHECKPOLICYHELP=`$CHECKPOLICY -h | grep xen`
     if test "$CHECKPOLICYHELP" = ""; then
        CHECKPOLICY=no
     fi
  fi
])
