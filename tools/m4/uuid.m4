AC_DEFUN([AX_CHECK_UUID], [
AC_CHECK_HEADER([uuid/uuid.h],[
    AC_CHECK_LIB([uuid], [uuid_clear], [libuuid="y"])
])
AC_CHECK_HEADER([uuid.h],[libuuid="y"])
AS_IF([test "$libuuid" != "y"], [
    AC_MSG_ERROR([cannot find a valid uuid library])
])
])
