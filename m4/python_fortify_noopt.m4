dnl Defines PY_NOOPT_CFLAGS to either '' or -O1
dnl

dnl This is necessary because on some systems setup.py includes
dnl -D_FORTIFY_SOURCE but have a -D_FORTIFY_SOURCE which breaks
dnl with -O0.  On those systems we arrange to use -O1 for debug
dnl builds instead.

AC_DEFUN([AX_CHECK_PYTHON_FORTIFY_NOOPT], [
    AC_CACHE_CHECK([whether Python setup.py brokenly enables -D_FORTIFY_SOURCE],
                   [ax_cv_python_fortify],[
        ax_cv_python_fortify=no
        for arg in $($PYTHON-config --cflags); do
            case "$arg" in
            -D_FORTIFY_SOURCE=0) ax_cv_python_fortify=no ;;
            -D_FORTIFY_SOURCE=*) ax_cv_python_fortify=yes ;;
            -Wp,-D_FORTIFY_SOURCE=0) ax_cv_python_fortify=no ;;
            -Wp,-D_FORTIFY_SOURCE=*) ax_cv_python_fortify=yes ;;
            *) ;;
            esac
        done
    ])

    AS_IF([test x$ax_cv_python_fortify = xyes],[
        PY_NOOPT_CFLAGS=-O1
    ], [
        PY_NOOPT_CFLAGS=''
    ])

    AC_SUBST(PY_NOOPT_CFLAGS)
])
