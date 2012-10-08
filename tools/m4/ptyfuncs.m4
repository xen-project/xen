AC_DEFUN([AX_CHECK_PTYFUNCS], [
    dnl This is a workaround for a bug in Debian package
    dnl libbsd-dev-0.3.0-1. Once we no longer support that
    dnl package we can remove the addition of -Werror to
    dnl CPPFLAGS.
    AX_SAVEVAR_SAVE(CPPFLAGS)
    CPPFLAGS="$CPPFLAGS -Werror"
    AC_CHECK_HEADER([libutil.h],[
      AC_DEFINE([INCLUDE_LIBUTIL_H],[<libutil.h>],[libutil header file name])
    ])
    AX_SAVEVAR_RESTORE(CPPFLAGS)
    AC_CACHE_CHECK([for openpty et al], [ax_cv_ptyfuncs_libs], [
        for ax_cv_ptyfuncs_libs in -lutil "" NOT_FOUND; do
            if test "x$ax_cv_ptyfuncs_libs" = "xNOT_FOUND"; then
                AC_MSG_FAILURE([Unable to find library for openpty and login_tty])
            fi
            AX_SAVEVAR_SAVE(LIBS)
            LIBS="$LIBS $ax_cv_ptyfuncs_libs"
            AC_LINK_IFELSE([AC_LANG_SOURCE([
#ifdef INCLUDE_LIBUTIL_H
#include INCLUDE_LIBUTIL_H
#endif
int main(void) {
  openpty(0,0,0,0,0);
  login_tty(0);
}
])],[
                break
            ],[])
            AX_SAVEVAR_RESTORE(LIBS)
        done
    ])
    PTYFUNCS_LIBS="$ax_cv_ptyfuncs_libs"
    AC_SUBST(PTYFUNCS_LIBS)
])
