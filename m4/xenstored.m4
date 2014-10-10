AC_DEFUN([AX_XEN_OCAML_XENSTORE_CHECK], [
	AS_IF([test "$ocamltools" = "n"], [
		AC_MSG_ERROR([Missing ocaml dependencies for oxenstored, try installing ocaml ocaml-compiler-libs ocaml-runtime ocaml-findlib])
	])
])

AC_DEFUN([AX_XEN_OCAML_XENSTORE_DEFAULTS], [
	xenstore="oxenstored"
	xenstored=$sbindir/oxenstored
	AS_IF([test "$ocamltools" = "n"], [
		xenstore="xenstored"
		xenstored=$sbindir/xenstored
	])
])

AC_DEFUN([AX_XENSTORE_OPTIONS], [
AS_IF([test "x$XENSTORE" = "x"], [
AC_ARG_WITH([xenstored],
	AS_HELP_STRING([--with-xenstored@<:@=oxenstored|xenstored@:>@],
		[This lets you choose which xenstore daemon you want, you have
		two options: the original xenstored written in C (xenstored)
		or the newer and robust one written in Ocaml (oxenstored).
		The oxenstored daemon is the default but can only
		be used if you have ocaml library / build dependencies solved,
		if you have not specified a preference and do not have ocaml
		dependencies resolved we'll enable the C xenstored for you. If
		you ask for oxenstored we'll complain until you resolve those
		dependencies]),
	[
		AS_IF([test "x$withval" = "xxenstored"], [
			xenstore=$withval
			xenstored=$sbindir/xenstored
		])
		AS_IF([test "x$withval" = "xoxenstored"], [
			xenstore=$withval
			xenstored=$sbindir/oxenstored
			AX_XEN_OCAML_XENSTORE_CHECK()
		])
		AS_IF([test "x$withval" != "xoxenstored" && test "x$withval" != "xxenstored"], [
			AC_MSG_ERROR([Unsupported xenstored specified, supported types: oxenstored xenstored])
		])
	],
	[
		AX_XEN_OCAML_XENSTORE_DEFAULTS()
	])
])
])

AC_DEFUN([AX_XENSTORE_SET], [
	XENSTORE=$xenstore

	AS_IF([test "x$XENSTORED" = "x"], [
		XENSTORED=$xenstored
	])
	AC_SUBST(XENSTORED)
])
