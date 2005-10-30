#!/bin/sh
# *
# * getlabel
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
# * 'getlabel' tries to find the labels corresponding to the ssidref
# *
# * 'getlabel -?' shows the usage of the program
# *
# * 'getlabel -sid <ssidref> [<policy name>]' lists the label corresponding
# *                              to the given ssidref.
# *
# * 'getlabel -dom <domain id> [<policy name>]' lists the label of the
# *                              domain with given id
# *
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
echo "Use this tool to display the label of a domain or the label that is
corresponding to an ssidref given the name of the running policy.

Usage: $0 -sid <ssidref> [<policy name>] or
       $0 -dom <domid>   [<policy name>]

policy name : the name of the policy, i.e. 'chwall'
              If the policy name is omitted, the grub.conf
              entry of the running system is tried to be read
              and the policy name determined from there.
ssidref     : an ssidref in hex or decimal format, i.e., '0x00010002'
              or '65538'
domid       : id of the domain, i.e., '1'; Use numbers from the 2nd
              column shown when invoking 'xm list'
"
}



if [ "$1" == "-?" ]; then
	mode="usage"
elif [ "$1" == "-dom" ]; then
	mode="domid"
	shift
elif [ "$1" == "-sid" ]; then
	mode="sid"
	shift
elif [ "$1" == "" ]; then
	usage
	exit -1
fi


if [ "$mode" == "usage" ]; then
	usage
elif [ "$mode" == "domid" ]; then
	if [ "$2" == "" ]; then
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
		policy=$2
	fi
	findMapFile $policy
	res=$?
	if [ "$res" != "0" ]; then
		getSSIDUsingSecpolTool $1
		res=$?
		if [ "$res" != "0" ]; then
			translateSSIDREF $ssid $mapfile
		else
			echo "Could not determine the SSID of the domain."
		fi
	else
		echo "Could not find map file for policy '$policy'."
	fi
elif [ "$mode" == "sid" ]; then
	if [ "$2" == "" ]; then
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
		policy=$2
	fi
	findMapFile $policy
	res=$?
	if [ "$res" != "0" ]; then
		translateSSIDREF $1 $mapfile
	else
		echo "Could not find map file for policy '$policy'."
	fi

else
    usage
fi
