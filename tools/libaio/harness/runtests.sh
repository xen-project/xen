#!/bin/sh

passes=0
fails=0

echo "Test run starting at" `date`

while [ $# -ge 1 ] ; do
	this_test=$1
	shift
	echo "Starting $this_test"
	$this_test 2>&1
	res=$?
	if [ $res -eq 0 ] ; then str="" ; passes=$[passes + 1] ; else str=" -- FAILED" ; fails=$[fails + 1] ; fi
	echo "Completed $this_test with $res$str".
done

echo "Pass: $passes  Fail: $fails"
echo "Test run complete at" `date`
