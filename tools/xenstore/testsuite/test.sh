#! /bin/sh

set -e
set -m

run_test()
{
    rm -rf $XENSTORED_ROOTDIR
    mkdir $XENSTORED_ROOTDIR
    if [ $VALGRIND -eq 1 ]; then
	valgrind --suppressions=testsuite/vg-suppressions -q ./xenstored_test --output-pid --trace-file=testsuite/tmp/trace --no-fork > /tmp/pid 2> testsuite/tmp/xenstored_errors &
	while [ ! -s /tmp/pid ]; do sleep 0; done
	PID=`cat /tmp/pid`
	rm /tmp/pid
    else
	# We don't get error messages from this, though. 
	PID=`./xenstored_test --output-pid --trace-file=testsuite/tmp/trace`
    fi
    if ./xs_test $2 $1; then
	if [ -s testsuite/tmp/xenstored_errors ]; then
	    kill $PID
	    echo Errors:
	    cat testsuite/tmp/xenstored_errors
	    return 1
	fi
	kill $PID
	sleep 1
	return 0
    else
	# In case daemon is wedged.
	kill $PID
	sleep 1
	return 1
    fi
}

if [ x$1 = x--fast ]; then
    VALGRIND=0
    SLOWTESTS=""
    shift
else
    if type valgrind >/dev/null 2>&1; then
	VALGRIND=1
    else
	echo "WARNING: valgrind not available" >&2
	VALGRIND=0
    fi
    SLOWTESTS=testsuite/[0-9]*.slowtest
fi

MATCH=${1:-"*"}
for f in testsuite/[0-9]*.test $SLOWTESTS; do
    case `basename $f` in $MATCH) RUN=1;; esac
    [ -n "$RUN" ] || continue

    if run_test $f -x >/tmp/out; then
	echo -n .
    else
	cat /tmp/out
	# That will have filled the screen, repeat message.
	echo Test $f failed
	exit 1
    fi
done
