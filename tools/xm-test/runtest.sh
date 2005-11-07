#!/bin/sh

usage() {
    echo "Usage: $0 [opts] <logfile>"
    echo "  Where opts are:"
    echo "  -d         : do not submit a report for this run"
    echo "  -b         : do not ask any questions (batch mode)"
    echo "  -e <email> : set email address for report"
}
##
## Test driver script
##

#
# Defaults
#
MAXFAIL=10
report=yes
batch=no

#
# Resolve options
#
while [ $# -gt 0 ]
do
    case "$1" in
    -d)
        echo "(Skipping report submission)"
        report=no
        ;;
    -b)
        echo "(Batch mode)"
        batch=yes
        ;;
    -e)
        shift
        echo $1 > contact_info
        echo "(Email set to $1)"
        ;;
    *)
        LOGFILE=$1
        break
        ;;
    esac
    shift
done

#
# Usage
#
if [ -z $LOGFILE ]; then
	usage
	exit 1
fi

#
# Output files
#
OSREPORTTEMP=${LOGFILE}.os.xml
PROGREPORTTEMP=${LOGFILE}.prog.xml
RESULTREPORTTEMP=${LOGFILE}.result.xml
OUTPUT=${LOGFILE}.output
SUMMARY=${LOGFILE}.summary
PASSFAIL=${LOGFILE}.passfail
REPORT=${LOGFILE}.report
FAILURES=${LOGFILE}.failures
		
#
# Make sure we're root
#
uid=$(id -u)
if [ $uid != 0 ]; then 
    echo "ERROR: I must be run as root!"
    exit 1
fi

#
# See if the ramdisk has been built
#
rdsize=$(stat -c %s ramdisk/initrd.img 2>/dev/null)
if [ -z "$rdsize" ] || [ $rdsize -le 16384 ]; then
    echo "Cannot find a valid ramdisk.  You need to run \"make\" or"
    echo "copy in a previously-built ramdisk to the ramdisk/ directory"
    exit 1
fi

#
# See if xend is running
#
if ! xm list >/dev/null 2>&1; then
    echo "'xm list' failed: is xend running?"
    exit 1
fi

#
#  Make sure permissions are correct
#
chmod a+x lib/XmTestReport/*
chmod a+x mkreport mergereport

#
# Get contact info if needed
#
if [ ! -f contact_info ]; then
    if [ "$batch" = "yes" ]; then
	echo "Unable to read contact_info!"
	echo "Please run me once interactively before using batch mode!"
	exit 1
    else
	echo "Please provide your email address so that we can "
	echo "contact you if we need further information concerning"
	echo "your results.  Any information provided will be"
	echo "kept private.  If you wish to remain anonymous, please"
	echo "hit [ENTER] now."
	
	while ! echo "$EMAIL" | grep -q '@'; do
	    echo
	    echo -n "Your email address: "
	    read EMAIL
	    if [ -z $EMAIL ]; then
		EMAIL="anonymous@somewhere.com"
	    fi
	done
	echo $EMAIL > contact_info
    fi
fi

#
# Collect environment information for XML report
#
if ! ./lib/XmTestReport/OSReport.py > $OSREPORTTEMP; then
    echo "Unable to generate clean OSReport"
    echo "Take a look at $OSREPORTTEMP"
    exit 1
fi
if ! ./lib/XmTestReport/ProgReport.py > $PROGREPORTTEMP; then
    echo "Unable to generate clean ProgReport"
    echo "Take a look at $PROGREPORTTEMP"
    exit 1
fi

#
# Run the tests
#
export TEST_VERBOSE=1
echo Running tests...
make -k check > $OUTPUT 2>&1

#
# Generate some plain-text reports
#
echo "Making PASS/FAIL report ($PASSFAIL)..."
cat $OUTPUT | egrep '(REASON|PASS|FAIL|XPASS|XFAIL|SKIP)' | perl -pe 's/^(PASS|FAIL|XPASS|XFAIL)(.+)$/$1$2\n/' > $PASSFAIL

echo "Making FAIL report ($FAILURES)..."
cat $PASSFAIL | egrep '(REASON|FAIL)' > $FAILURES

NUMPASS=`grep -c PASS $OUTPUT`
NUMFAIL=`grep -c FAIL $OUTPUT`
NUMXPASS=`grep -c XPASS $OUTPUT`
NUMXFAIL=`grep -c XFAIL $OUTPUT`
cat > $SUMMARY << EOF
Xm-test execution summary:
  PASS:  $NUMPASS
  FAIL:  $NUMFAIL
  XPASS: $NUMXPASS
  XFAIL: $NUMXFAIL
EOF

cat $SUMMARY > $REPORT

echo -e '\n\nDetails:\n' >> $REPORT
 
./mkreport $PASSFAIL >> $REPORT

#
# Check to see if it's worth reporting these results
#
#if  [ "$batch"  =   "no" ] && 
#    [ "$report" =   "yes" ] && 
#    [ $NUMFAIL  -gt $MAXFAIL ]; then
#    echo "NOTE: $NUMFAIL tests failed, which may be erroneous.  It may"
#    echo "be a good idea to review the report before sending.  If you"
#    echo "choose not to submit the report, it will be saved for your review"
#    echo "and later submission."
#    echo
#    echo -n "Submit anyway? [y/n] "
#    read ANSWER
#    if [ "$ANSWER" = "n" ]; then
#	report=no
#    fi
#fi

#
# Generate the XML result report
#
if ! ./lib/XmTestReport/ResultReport.py $OUTPUT > $RESULTREPORTTEMP; then
    echo "Unable to generate clean ResultReport"
    echo "Take a look at $RESULTREPORTTEMP"
    exit 1
fi

#
# Maybe submit report and save the combined XML file
#
if [ "$report" = "yes" ]; then
    echo "Sending report..."
    ./lib/XmTestReport/Report.py -D $OSREPORTTEMP $PROGREPORTTEMP \
                                    $RESULTREPORTTEMP > $1.xml
    echo "Report also saved in $1.xml"
else
    echo "Saving report to $1.xml..."
    ./lib/XmTestReport/Report.py -d $OSREPORTTEMP $PROGREPORTTEMP \
                                    $RESULTREPORTTEMP > $1.xml
fi
