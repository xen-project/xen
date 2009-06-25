# has is the same as which, except it handles cross environments
has() {
	if [ -z "$CROSS_COMPILE" ]; then
		command which "$@"
		return $?
	fi

	check_sys_root || return 1

	# subshell to prevent pollution of caller's IFS
	(
	IFS=:
	for p in $PATH; do
		if [ -x "$CROSS_SYS_ROOT/$p/$1" ]; then
			echo "$CROSS_SYS_ROOT/$p/$1"
			return 0
		fi
	done
	return 1
	)
}

has_or_fail() {
	has "$1" >/dev/null || fail "can't find $1"
}

has_header() {
	case $1 in
		/*) ;;
		*) set -- "/usr/include/$1" ;;
	esac

	check_sys_root || return 1

	test -r "$CROSS_SYS_ROOT$1"
	return $?
}

has_lib() {
	check_sys_root || return 1

	# subshell to prevent pollution of caller's environment
	(
	PATH=/sbin:$PATH        # for ldconfig

	# This relatively common in a sys-root; libs are installed but
	# ldconfig hasn't run there, so ldconfig -p won't work.
	if [ "$OS" = Linux -a ! -f "$CROSS_SYS_ROOT/etc/ld.so.cache" ]; then
	    echo "Please run ldconfig -r \"$CROSS_SYS_ROOT\" to generate ld.so.cache"
	    # fall through; ldconfig test below should fail
	fi
	ldconfig -p ${CROSS_SYS_ROOT+-r "$CROSS_SYS_ROOT"} | grep -Fq "$1"
	return $?
	)
}

test_link() {
	# subshell to trap removal of tmpfile
	(
	unset tmpfile
	trap 'rm -f "$tmpfile"; exit' 0 1 2 15
	tmpfile=`mktemp` || return 1
	ld "$@" -o "$tmpfile" >/dev/null 2>&1
	return $?
	)
}

# this function is used commonly above
check_sys_root() {
	[ -z "$CROSS_COMPILE" ] && return 0
	if [ -z "$CROSS_SYS_ROOT" ]; then
		echo "please set CROSS_SYS_ROOT in the environment"
		return 1
	fi
	if [ ! -d "$CROSS_SYS_ROOT" ]; then
		echo "no sys-root found at $CROSS_SYS_ROOT"
		return 1
	fi
}

warning() {
	echo
	echo " *** `basename "$0"` FAILED${*+: $*}"
}

fail() {
	echo
	echo " *** `basename "$0"` FAILED${*+: $*}"
	exit 1
}
