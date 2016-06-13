#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.67])
AC_INIT([Xen Hypervisor Documentation], m4_esyscmd([../version.sh ../xen/Makefile]),
    [xen-devel@lists.xen.org], [xen], [http://www.xen.org/])
AC_CONFIG_SRCDIR([misc/xen-command-line.markdown])
AC_CONFIG_FILES([
../config/Docs.mk
man/xl.cfg.pod.5
man/xl.pod.1
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
AX_DOCS_TOOL_PROGS([MARKDOWN], [markdown], [markdown markdown_py])

AC_ARG_VAR([PERL], [Path to Perl parser])
AX_PATH_PROG_OR_FAIL([PERL], [perl])

AC_OUTPUT()
