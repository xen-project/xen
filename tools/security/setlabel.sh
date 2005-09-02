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
source labelfuncs.sh

usage ()
{
	echo "Usage: $0 [Option] <vmfile> <label> [<policy name>]"
	echo "    or $0 -l [<policy name>]"
	echo ""
	echo "Valid options are:"
	echo "-r          : to relabel a file without being prompted"
	echo ""
	echo "vmfile      : XEN vm configuration file"
	echo "label       : the label to map to an ssidref"
	echo "policy name : the name of the policy, i.e. 'chwall'"
	echo "              If the policy name is omitted, it is attempted"
	echo "              to find the current policy's name in grub.conf."
	echo ""
	echo "-l [<policy name>] is used to show valid labels in the map file of"
	echo "                   the given or current policy."
	echo ""
}


if [ "$1" == "-r" ]; then
	mode="relabel"
	shift
elif [ "$1" == "-l" ]; then
	mode="show"
	shift
elif [ "$1" == "-?" ]; then
	mode="usage"
fi

if [ "$mode" == "show" ]; then
	if [ "$1" == "" ]; then
		findGrubConf
		ret=$?
		if [ $ret -eq 0 ]; then
			echo "Could not find grub.conf"
			exit -1;
		fi
		findPolicyInGrub $grubconf
		if [ "$policy" != "" ]; then
			echo "Assuming policy to be '$policy'.";
		else
			echo "Could not find policy."
			exit -1;
		fi
	else
		policy=$3;
	fi


	findMapFile $policy
	res=$?
	if [ "$res" != "0" ]; then
		showLabels $mapfile
	else
		echo "Could not find map file for policy '$1'."
	fi
elif [ "$mode" == "usage" ]; then
	usage
else
	if [ "$2" == "" ]; then
		usage
		exit -1
	fi
	if [ "$3" == "" ]; then
		findGrubConf
		ret=$?
		if [ $ret -eq 0 ]; then
			echo "Could not find grub.conf"
			exit -1;
		fi
		findPolicyInGrub $grubconf
		if [ "$policy" != "" ]; then
			echo "Assuming policy to be '$policy'.";
		else
			echo "Could not find policy."
			exit -1;
		fi

	else
		policy=$3;
	fi
	findMapFile $policy
	res=$?
	if [ "$res" != "0" ]; then
		relabel $1 $2 $mapfile $mode
	else
		echo "Could not find map file for policy '$3'."
	fi

fi
