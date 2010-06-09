#!/bin/sh
#
# PROVIDE: xen-watchdog
# REQUIRE: DAEMON
#
# description: Run domain watchdog daemon
#

. /etc/rc.subr

DIR=$(dirname "$0")
. "${DIR}/xen-hotplugpath.sh"

LD_LIBRARY_PATH="${LIBDIR}"
export LD_LIBRARY_PATH

name="xenwatchdog"
rcvar=$name
command="${SBINDIR}/xenwatchdogd"
start_cmd="echo Starting ${name}. && PATH=${PATH}:${SBINDIR} ${command} 30 15"

load_rc_config $name
run_rc_command "$1"
