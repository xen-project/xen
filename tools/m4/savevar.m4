AC_DEFUN([AX_SAVEVAR_SAVE],[
    saved_$1="$$1"
])
AC_DEFUN([AX_SAVEVAR_RESTORE],[
    $1="$saved_$1"
])
