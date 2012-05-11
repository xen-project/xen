AC_DEFUN([AX_CHECK_PTYFUNCS], [
    AC_CHECK_HEADER([libutil.h],[
      AC_DEFINE([INCLUDE_LIBUTIL_H],[<libutil.h>],[libutil header file name])
    ])
    AC_CACHE_CHECK([for openpty et al], [ax_cv_ptyfuncs_libs], [
        for ax_cv_ptyfuncs_libs in -lutil "" NOT_FOUND; do
            if test "x$ax_cv_ptyfuncs_libs" = "xNOT_FOUND"; then
                AC_MSG_FAILURE([Unable to find library for openpty and login_tty])
            fi
            AX_SAVEVAR_SAVE(LIBS)
            LIBS="$LIBS $ax_cv_ptyfuncs_libs"
            AC_LINK_IFELSE([
#ifdef INCLUDE_LIBUTIL_H
#include INCLUDE_LIBUTIL_H
#endif
int main(void) {
  openpty(0,0,0,0,0);
  login_tty(0);
}
],[
                break
            ],[])
            AX_SAVEVAR_RESTORE(LIBS)
        done
    ])
    PTYFUNCS_LIBS="$ax_cv_ptyfuncs_libs"
    AC_SUBST(PTYFUNCS_LIBS)
])
