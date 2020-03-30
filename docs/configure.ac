#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.67])
AC_INIT([Xen Hypervisor Documentation], m4_esyscmd([../version.sh ../xen/Makefile]),
    [xen-devel@lists.xen.org], [xen], [https://www.xen.org/])
AC_CONFIG_SRCDIR([misc/xen-command-line.pandoc])
AC_CONFIG_FILES([
../config/Docs.mk
man/xl.cfg.5.pod
man/xl.1.pod
])
AC_CONFIG_AUX_DIR([../])

# M4 Macro includes
m4_include([../m4/docs_tool.m4])
m4_include([../m4/path_or_fail.m4])
m4_include([../m4/features.m4])
m4_include([../m4/paths.m4])

AX_XEN_EXPAND_CONFIG()

AX_DOCS_TOOL_PROG([FIG2DEV], [fig2dev])
AX_DOCS_TOOL_PROG([POD2MAN], [pod2man])
AX_DOCS_TOOL_PROG([POD2HTML], [pod2html])
AX_DOCS_TOOL_PROG([POD2TEXT], [pod2text])
AX_DOCS_TOOL_PROG([PANDOC], [pandoc])

AC_ARG_VAR([PERL], [Path to Perl parser])
AX_PATH_PROG_OR_FAIL([PERL], [perl])

AC_OUTPUT()
