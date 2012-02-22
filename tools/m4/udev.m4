AC_DEFUN([AX_CHECK_UDEV],
[if test "x$host_os" == "xlinux-gnu"
then
    AC_PATH_PROG([UDEVADM], [udevadm], [no])
    if test x"${UDEVADM}" == x"no" 
    then
        AC_PATH_PROG([UDEVINFO], [udevinfo], [no])
        if test x"${UDEVINFO}" == x"no"
        then
            AC_MSG_ERROR(
                [Unable to find udevadm or udevinfo, please install udev])
        fi
        udevver=`${UDEVINFO} -V | awk '{print $NF}'`
    else
        udevver=`${UDEVADM} info -V | awk '{print $NF}'`
    fi
    if test ${udevver} -lt 59
    then
        AC_PATH_PROG([HOTPLUG], [hotplug], [no])
        if test x"${HOTPLUG}" == x"no"
        then
            AC_MSG_ERROR([udev is too old, upgrade to version 59 or later])
        fi
    fi
else
    AC_PATH_PROG([VNCONFIG], [vnconfig], [no])
    if test x"${VNCONFIG}" == x"no"
    then
        AC_MSG_ERROR([Not a Linux system and unable to find vnd])
    fi
fi
])
