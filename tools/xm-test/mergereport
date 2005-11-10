#!/bin/sh

# Dan Smith <danms@us.ibm.com> - 16-Sep-2005
#
# This script takes all the .report files in the current
# directory and generates a summary table, showing the 
# number of PASS, FAIL, XPASS, and XFAIL tests in each 
# report


echo "            Platform | PASS | FAIL | XPASS | XFAIL |"
echo "---------------------+------+------+-------+-------+"

for r in *.report; do
    
    mach=$(basename $r .report)
    pass=$(cat $r | grep '  PASS' | cut -d : -f 2 | sed 's/  *//')
    fail=$(cat $r | grep '  FAIL' | cut -d : -f 2 | sed 's/  *//')
    xpas=$(cat $r | grep ' XPASS' | cut -d : -f 2 | sed 's/  *//')
    xfal=$(cat $r | grep ' XFAIL' | cut -d : -f 2 | sed 's/  *//')

    printf "%20s | %4s | %4s | %5s | %5s |\n" "$mach" "$pass" \
           "$fail" "$xpas" "$xfal"

done
