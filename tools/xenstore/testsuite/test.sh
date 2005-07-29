#! /bin/sh

set -e
set -m

run_test()
{
    rm -rf $XENSTORED_ROOTDIR
    mkdir $XENSTORED_ROOTDIR
# Weird failures with this.
    if type valgrind >/dev/null 2>&1; then
	valgrind -q --logfile-fd=3 ./xenstored_test --output-pid --trace-file=testsuite/tmp/trace --no-fork 3>testsuite/tmp/vgout > /tmp/pid 2> testsuite/tmp/xenstored_errors &
	while [ ! -s /tmp/pid ]; do sleep 0; done
	PID=`cat /tmp/pid`
	rm /tmp/pid
    else
	PID=`./xenstored_test --output-pid`
    fi
    if sh -e $2 $1; then
	if [ -s testsuite/tmp/vgout ]; then
	    kill $PID
	    echo VALGRIND errors:
	    cat testsuite/tmp/vgout
	    return 1
	fi
	echo shutdown | ./xs_test
	return 0
    else
	# In case daemon is wedged.
	kill $PID
	sleep 1
	return 1
    fi
}

MATCH=${1:-"*"}
for f in testsuite/[0-9]*.sh; do
    case `basename $f` in $MATCH) RUN=1;; esac
    [ -n "$RUN" ] || continue
    if run_test $f; then
	echo Test $f passed...
    else
	echo Test $f failed, running verbosely...
	run_test $f -x || true
	# That will have filled the screen, repeat message.
	echo Test $f failed
	exit 1
    fi
done
