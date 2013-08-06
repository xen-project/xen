#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.67])
AC_INIT([Xen Hypervisor Stub Domains], m4_esyscmd([../version.sh ../xen/Makefile]),
    [xen-devel@lists.xen.org], [xen], [http://www.xen.org/])
AC_CONFIG_SRCDIR([../extras/mini-os/kernel.c])
AC_CONFIG_FILES([../config/Stubdom.mk])
AC_CONFIG_AUX_DIR([../])

AC_CANONICAL_HOST

# M4 Macro includes
m4_include([../m4/stubdom.m4])
m4_include([../m4/features.m4])
m4_include([../m4/path_or_fail.m4])
m4_include([../m4/depends.m4])
m4_include([../m4/fetcher.m4])

# Enable/disable stub domains
AX_STUBDOM_CONDITIONAL([ioemu-stubdom], [ioemu])
AX_STUBDOM_DEFAULT_DISABLE([c-stubdom], [c])
AX_STUBDOM_DEFAULT_DISABLE([caml-stubdom], [caml])
AX_STUBDOM_DEFAULT_ENABLE([pv-grub], [grub])
AX_STUBDOM_DEFAULT_ENABLE([xenstore-stubdom], [xenstore])
AX_STUBDOM_CONDITIONAL([vtpm-stubdom], [vtpm])
AX_STUBDOM_CONDITIONAL([vtpmmgr-stubdom], [vtpmmgr])

AC_ARG_ENABLE([qemu-traditional],,,[
    case "$host_cpu" in
        i[[3456]]86|x86_64)
           enable_qemu_traditional="yes";;
        *) enable_qemu_traditional="no";;
    esac
])
AS_IF([test "x$enable_qemu_traditional" = "xyes"], [
    qemu_traditional=y],[
    qemu_traditional=n
])
AS_IF([test "x$ioemu" = "x"], [
    ioemu=$qemu_traditional
])
echo "x$ioemu$qemu_traditional"
AS_IF([test "x$ioemu$qemu_traditional" = "xyn"], [
    AC_MSG_ERROR(IOEMU stubdomain requires qemu-traditional)
])

AX_ARG_DEFAULT_ENABLE([debug], [Disable debug build of stubdom])
AX_ARG_DEFAULT_ENABLE([extfiles], [Use xen extfiles repository for libraries])

AC_ARG_VAR([CMAKE], [Path to the cmake program])
AX_CHECK_FETCHER

# Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET
AC_PROG_INSTALL

# Checks for programs that depend on a feature
AX_DEPENDS_PATH_PROG([vtpm], [CMAKE], [cmake])

# Stubdom libraries version and url setup
AX_STUBDOM_LIB([ZLIB], [zlib], [1.2.3], [http://www.zlib.net])
AX_STUBDOM_LIB([LIBPCI], [libpci], [2.2.9], [http://www.kernel.org/pub/software/utils/pciutils])
AX_STUBDOM_LIB([NEWLIB], [newlib], [1.16.0], [ftp://sources.redhat.com/pub/newlib])
AX_STUBDOM_LIB([LWIP], [lwip], [1.3.0], [http://download.savannah.gnu.org/releases/lwip])
AX_STUBDOM_LIB([GRUB], [grub], [0.97], [http://alpha.gnu.org/gnu/grub])
AX_STUBDOM_LIB_NOEXT([OCAML], [ocaml], [3.11.0], [http://caml.inria.fr/pub/distrib/ocaml-3.11])
AX_STUBDOM_LIB([GMP], [libgmp], [4.3.2], [ftp://ftp.gmplib.org/pub/gmp-4.3.2])
AX_STUBDOM_LIB([POLARSSL], [polarssl], [1.1.4], [http://polarssl.org/code/releases])
AX_STUBDOM_LIB([TPMEMU], [berlios tpm emulator], [0.7.4], [http://download.berlios.de/tpm-emulator])

#These stubdoms should be enabled if the dependent one is
AX_STUBDOM_AUTO_DEPENDS([vtpmmgr], [vtpm])

#Conditionally enable these stubdoms based on the presense of dependencies
AX_STUBDOM_CONDITIONAL_FINISH([vtpm-stubdom], [vtpm])
AX_STUBDOM_CONDITIONAL_FINISH([vtpmmgr-stubdom], [vtpmmgr])
AX_STUBDOM_CONDITIONAL_FINISH([ioemu-stubdom], [ioemu])

AX_STUBDOM_FINISH
AC_OUTPUT()
