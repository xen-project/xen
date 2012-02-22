AC_DEFUN([AX_CHECK_PYTHON_XML],
[AC_MSG_CHECKING([for python xml.dom.minidom])
`$PYTHON -c 'import xml.dom.minidom'`
if test "$?" != "0"
then
    AC_MSG_RESULT([no])
    AC_MSG_ERROR([Unable to find xml.dom.minidom module])
else
    AC_MSG_RESULT([yes])
fi])
