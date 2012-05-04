#!/bin/bash
#
# xend		Script to start and stop the Xen control daemon.
#
# Author:       Keir Fraser <keir.fraser@cl.cam.ac.uk>
#
# chkconfig: 2345 98 01
# description: Starts and stops the Xen control daemon.
### BEGIN INIT INFO
# Provides:          xend
# Required-Start:    $syslog $remote_fs xenstored xenconsoled 
# Should-Start:
# Required-Stop:     $syslog $remote_fs xenstored xenconsoled 
# Should-Stop:
# Default-Start:     2 3 5
# Default-Stop:      0 1 6
# Short-Description: Start/stop xend
# Description:       Starts and stops the Xen control daemon.
### END INIT INFO

shopt -s extglob

# Wait for Xend to be up
function await_daemons_up
{
	i=1
	rets=10
	xend status
	while [ $? -ne 0 -a $i -lt $rets ]; do
	    sleep 1
	    echo -n .
	    i=$(($i + 1))
	    xend status
	done
}

case "$1" in
  start)
	if [ -z "`ps -C xenconsoled -o pid=`" ]; then
		echo "xencommons should be started first."
		exit 1
	fi
	# mkdir shouldn't be needed as most distros have this already created. Default to using subsys.
	# See docs/misc/distro_mapping.txt
	mkdir -p /var/lock
	if [ -d /var/lock/subsys ] ; then
		touch /var/lock/subsys/xend
	else
		touch /var/lock/xend
	fi
	xend start
	await_daemons_up
	;;
  stop)
	xend stop
	rm -f /var/lock/subsys/xend /var/lock/xend
	;;
  status)
	xend status
	;;
  reload)
        xend reload
        ;;
  restart|force-reload)
	xend restart
	await_daemons_up
	;;
  *)
	# do not advertise unreasonable commands that there is no reason
	# to use with this device
	echo $"Usage: $0 {start|stop|status|restart|reload|force-reload}"
	exit 1
esac

exit $?

