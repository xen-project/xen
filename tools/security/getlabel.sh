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
dir=`dirname $0`
source $dir/labelfuncs.sh

usage ()
{
	prg=`basename $0`
echo "Use this tool to display the label of a domain or the label that is
corresponding to an ssidref given the name of the running policy.

Usage: $prg -sid <ssidref> [<policy name> [<policy dir>]] or
       $prg -dom <domid>   [<policy name> [<policy dir>]]

policy name : the name of the policy, i.e. 'chwall'
              If the policy name is omitted, the grub.conf
              entry of the running system is tried to be read
              and the policy name determined from there.
policy dir  : the directory where the <policy name> policy is located
              The default location is '/etc/xen/acm-security/policies'
ssidref     : an ssidref in hex or decimal format, i.e., '0x00010002'
              or '65538'
domid       : id of the domain, i.e., '1'; Use numbers from the 2nd
              column shown when invoking 'xm list'
"
}



if [ "$1" == "-h" ]; then
	usage
	exit 0
elif [ "$1" == "-dom" ]; then
	mode="domid"
	shift
elif [ "$1" == "-sid" ]; then
	mode="sid"
	shift
else
	usage
	exit -1
fi

setPolicyVars $2 $3
findMapFile $policy $policydir
ret=$?
if [ $ret -eq 0 ]; then
	echo "Could not find map file for policy '$policy'."
	exit -1
fi

if [ "$mode" == "domid" ]; then
	getSSIDUsingSecpolTool $1
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "Could not determine the SSID of the domain."
		exit -1
	fi
	translateSSIDREF $ssid $mapfile
else # mode == sid
	translateSSIDREF $1 $mapfile
fi
