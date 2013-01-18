# We define, separately, PTHREAD_CFLAGS, _LDFLAGS and _LIBS
# even though currently we don't set them very separately.
# This means that the makefiles will not need to change in
# the future if we make the test more sophisticated.

AC_DEFUN([AX_PTHREAD_CV2VARS],[
    PTHREAD_CFLAGS="$ax_cv_pthread_flags"
    PTHREAD_LDFLAGS="$ax_cv_pthread_flags"
    PTHREAD_LIBS=""
])

# We invoke AX_PTHREAD_VARS with the name of another macro
# which is then expanded once for each variable.
AC_DEFUN([AX_PTHREAD_VARS],[$1(CFLAGS) $1(LDFLAGS) $1(LIBS)])

AC_DEFUN([AX_PTHREAD_VAR_APPLY],[
    $1="$$1 $PTHREAD_$1"
])
AC_DEFUN([AX_PTHREAD_VAR_SUBST],[AC_SUBST(PTHREAD_$1)])

AC_DEFUN([AX_CHECK_PTHREAD],[
    AC_CACHE_CHECK([for pthread flag], [ax_cv_pthread_flags], [
        ax_cv_pthread_flags=-pthread
        AX_PTHREAD_CV2VARS
        AX_PTHREAD_VARS([AX_SAVEVAR_SAVE])
        AX_PTHREAD_VARS([AX_PTHREAD_VAR_APPLY])
        AC_LINK_IFELSE([AC_LANG_SOURCE([
#include <pthread.h>
int main(void) {
  pthread_atfork(0,0,0);
  pthread_create(0,0,0,0);
}
])],[],[ax_cv_pthread_flags=failed])
        AX_PTHREAD_VARS([AX_SAVEVAR_RESTORE])
    ])
    if test "x$ax_cv_pthread_flags" = xfailed; then
        AC_MSG_ERROR([-pthread does not work])
    fi
    AX_PTHREAD_CV2VARS
    AX_PTHREAD_VARS([AX_PTHREAD_VAR_SUBST])
])
