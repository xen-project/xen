AC_DEFUN([AX_CHECK_UUID],
[if test "x$host_os" == "xlinux-gnu"
then
    AC_CHECK_HEADER([uuid/uuid.h],,
	    [AC_MSG_ERROR([cannot find uuid headers])])
else
    AC_CHECK_HEADER([uuid.h],,
	    [AC_MSG_ERROR([cannot find uuid headers])])
fi
])
