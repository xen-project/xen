#!/bin/sh
# *
# * setlabel
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
# * 'setlabel' labels virtual machine (domain) configuration files with
# * security identifiers that can be enforced in Xen.
# *
# * 'setlabel -?' shows the usage of the program
# *
# * 'setlabel -l vmconfig-file' lists all available labels (only VM
# *            labels are used right now)
# *
# * 'setlabel vmconfig-file security-label map-file' inserts the 'ssidref'
# *                       that corresponds to the security-label under the
# *                       current policy (if policy changes, 'label'
# *                       must be re-run over the configuration files;
# *                       map-file is created during policy translation and
# *                       is found in the policy's directory
#

if [ -z "$runbash" ]; then
	runbash="1"
	export runbash
	exec sh -c "bash $0 $*"
fi

export PATH=$PATH:.
dir=`dirname $0`
source $dir/labelfuncs.sh

usage ()
{
	prg=`basename $0`
echo "Use this tool to put the ssidref corresponding to a label of a policy into
the VM configuration file, or use it to display all labels of a policy.

Usage: $prg [-r] <vmfile> <label> [<policy name> [<policy dir>]] or
       $prg -l [<policy name> [<policy dir>]]

-r          : to relabel a file without being prompted
-l          : to show the valid labels in a map file
vmfile      : XEN vm configuration file; give complete path
label       : the label to map to an ssidref
policy name : the name of the policy, i.e. 'chwall'
              If the policy name is omitted, it is attempted
              to find the current policy's name in grub.conf.
policy dir  : the directory where the <policy name> policy is located
              The default location is '/etc/xen/acm-security/policies'
"
}

if [ "$1" == "-r" ]; then
	mode="relabel"
	shift
elif [ "$1" == "-l" ]; then
	mode="show"
	shift
elif [ "$1" == "-h" ]; then
	mode="usage"
fi

if [ "$mode" == "usage" ]; then
	usage
elif [ "$mode" == "show" ]; then
	setPolicyVars $1 $2
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "Error when trying to find policy-related information."
		exit -1
	fi
	findMapFile $policy $policydir
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "Could not find map file for policy '$policy'."
		exit -1
	fi
	showLabels $mapfile
else
	if [ "$2" == "" ]; then
		usage
		exit -1
	fi
	setPolicyVars $3 $4
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "Error when trying to find policy-related information."
		exit -1
	fi
	findMapFile $policy $policydir
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "Could not find map file for policy '$policy'."
		exit -1
	fi
	relabel $1 $2 $mapfile $mode
fi
