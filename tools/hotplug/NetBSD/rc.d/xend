#!/bin/sh
#
# PROVIDE: xend
# REQUIRE: xencommons

. /etc/rc.subr

DIR=$(dirname "$0")
. "${DIR}/xen-hotplugpath.sh"

LD_LIBRARY_PATH="${LIBDIR}"
export LD_LIBRARY_PATH PYTHONPATH
PATH="${PATH}:${SBINDIR}"
export PATH

name="xend"
rcvar=$name
start_precmd="xend_precmd"
start_cmd="xend_startcmd"
stop_cmd="xend_stop"
status_cmd="xend_status"
extra_commands="status"
required_files="/kern/xen/privcmd"

XENBACKENDD_PIDFILE="/var/run/xenbackendd.pid"
#XENBACKENDD_DEBUG=1

xend_precmd()
{
	mkdir -p /var/run/xend || exit 1
	mkdir -p /var/run/xend/boot || exit 1
}

xend_startcmd()
{
	printf "Starting xenbackendd.\n"

	XENBACKENDD_ARGS=""
	if [ -n "${XENBACKENDD_DEBUG}" ]; then
		XENBACKENDD_ARGS="${XENBACKENDD_ARGS} -d"
	fi

	${SBINDIR}/xenbackendd ${XENBACKENDD_ARGS}

	printf "Starting xend.\n"
	${SBINDIR}/xend start >/dev/null 2>&1
}

xend_stop()
{
	printf "Stopping xenbackendd, xend\n"
	xb_pid=$(check_pidfile ${XENBACKENDD_PIDFILE} ${SBINDIR}/xenbackendd)
	if test -n "$xb_pid";
	then
		kill -${sig_stop:-TERM} $xb_pid
	fi
	while pgrep -f ${SBINDIR}/xend >/dev/null 2>&1; do
		pkill -${sig_stop:-KILL} -f ${SBINDIR}/xend
	done
	wait_for_pids $xb_pid
	rm -f /var/lock/subsys/xend /var/lock/xend /var/run/xenbackendd.pid
}

xend_status()
{
	${SBINDIR}/xend status
}

load_rc_config $name
run_rc_command "$1"

