AC_DEFUN([AX_SET_FLAGS],
[for cflag in $PREPEND_INCLUDES
do
    PREPEND_CFLAGS+=" -I$cflag"
done
for ldflag in $PREPEND_LIB
do
    PREPEND_LDFLAGS+=" -L$ldflag"
done
for cflag in $APPEND_INCLUDES
do
    APPEND_CFLAGS+=" -I$cflag"
done
for ldflag in $APPEND_LIB
do
    APPEND_LDFLAGS+=" -L$ldflag"
done
CFLAGS="$PREPEND_CFLAGS $CFLAGS $APPEND_CFLAGS"
LDFLAGS="$PREPEND_LDFLAGS $LDFLAGS $APPEND_LDFLAGS"])

