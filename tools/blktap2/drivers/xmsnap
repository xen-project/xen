#!/bin/bash

usage () { echo "USAGE: xmsnap <VM ID> <Backing File>"; }

#
# Check Usage
#
if [ -n "$1" ]
then
	vmid=$1
else
	usage
	exit 1
fi

if [ -n "$2" ]
then
	target=$2
else
	usage
	exit 1
fi

if [ -e "$target" ]
then
    echo "Creating snapshot of file $target for VM $vmid."
else
    usage
    echo "File $target not found."
    exit 1
fi

#
# Find the snapshot name
#
directory=`dirname "$target"`
target=`basename "$target"`

let maxidx=0
if [ -e $directory/${target}.snap1 ]
then
	for idx in $(ls $directory/${target}.snap*)
	do
	    let idx=${idx#$directory/${target}.snap}
	    if [ "$idx" -gt "$maxidx" ]
	    then
		let maxidx=$idx
	    fi
	done
fi

snap=${target}.snap`expr $maxidx + 1`

#
# Pause VM
#
xm pause $vmid
if [ "$?" -ne "0" ]; then
  exit 1
fi


#
# Snap and reposition the files
#
mv $directory/$target $directory/$snap
if [ "$?" -ne "0" ]; then
  exit 1
fi

qcow-create 0 $directory/$target $directory/$snap

#
# Unpause
#
xm unpause $vmid

exit