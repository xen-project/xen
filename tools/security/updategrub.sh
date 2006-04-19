#!/bin/sh
# *
# * updategrub
# *
# * Copyright (C) 2005 IBM Corporation
# *
# * Authors:
# * Stefan Berger <stefanb@us.ibm.com>
# *
# * This program is free software; you can redistribute it and/or
# * modify it under the terms of the GNU General Public License as
# * published by the Free Software Foundation, version 2 of the
# * License.
# *
# *
#

if [ -z "$runbash" ]; then
	runbash="1"
	export runbash
	exec sh -c "bash $0 $*"
	exit
fi

dir=`dirname $0`
source $dir/labelfuncs.sh

acmroot=$ACM_DEFAULT_ROOT


# Show usage of this program
usage ()
{
	prg=`basename $0`
echo "Use this tool to add the binary policy to the Xen grub entry and
have Xen automatically enforce the policy when starting.

Usage: $prg [-d <policies root>] <policy name> [<kernel version>]

<policies root>  : The directory where the policies directory is located in;
                   default is $acmroot
<policy name>    : The name of the policy, i.e. xen_null
<kernel version> : The version of the kernel to apply the policy
                   against, i.e. 2.6.16-xen
                   If not specified, a kernel version ending with '-xen'
                   will be searched for in '/lib/modules'
"
}



if [ "$1" == "-h" ]; then
	usage
	exit 0
elif [ "$1" == "-d" ]; then
	shift
	acmroot=$1
	shift
fi

if [ "$1" == "" ]; then
	echo "Error: Not enough command line parameters."
	echo ""
	usage
	exit -1
fi


policy=$1
policyfile=$policy.bin

getLinuxVersion $2

findGrubConf
ret=$?
if [ $ret -eq 0 ]; then
	echo "Could not find grub.conf."
	exit -1
elif [ $ret -eq 2 ]; then
	echo "Need to have write-access to $grubconf. Exiting."
	exit -1
fi

cpBootPolicy /boot $acmroot $policy
ret=$?
if [ $ret -ne 1 ]; then
	echo "Error copying or generating the binary policy."
	exit -1
fi
updateGrub $grubconf $policyfile $linux
