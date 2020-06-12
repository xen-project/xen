AC_DEFUN([AC_PROG_GO], [
    dnl Check for the go compiler
    AC_CHECK_TOOL([GO],[go],[no])

    if test "$GO" != "no"; then
        GOVERSION=`$GO version | cut -d " " -f 3 | sed "s/go//"`
    fi
])
