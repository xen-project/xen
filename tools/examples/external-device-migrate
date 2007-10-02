#!/bin/bash

# Copyright (c) 2005 IBM Corporation
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of version 2.1 of the GNU Lesser General Public
# License as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

set -x

# This script is called by XenD for migration of external devices
# It does not handle the migration of those devices itself, but
# passes the requests on to further applications
# It handles the low-level command line parsing and some of the
# synchronization

dir=$(dirname "$0")
. "$dir/logging.sh"


function ext_dev_migrate_usage() {
cat <<EOF
Pass the following command line parameters to the script:

-step <n>              : n-th migration step
-host <host>           : the destination host
-domname <domain name> : name of the domain that is migrating
-type <device type>    : the type of device that is migrating
-subtype <dev. subtype>: the subtype of the device
-recover               : indicates recovery request; an error
                         occurred during migration
-help                  : display this help screen
EOF
}

# Parse the command line paramters. The following parameters must be
# passed as the first ones in the sequence:
#  -step       [required]
#  -host       [required]
#  -domname    [required]
#  -type       [required]
#  -subtype    [optional]
#  -recover    [optional]
# The remaining ones will be passed to the called function.
function evaluate_params()
{
	local step host domname typ recover filename func stype
	stype=""
	while [ $# -ge 1 ]; do
		case "$1" in
		-step)		step=$2; shift; shift;;
		-host)		host=$2; shift; shift;;
		-domname)	domname=$2; shift; shift;;
		-type)		typ=$2; shift; shift;;
		-subtype)	stype=$2; shift; shift;;
		-recover)	recover=1; shift;;
		-help)		ext_dev_migrate_usage; exit 0;;
		*)		break;;
		esac
	done

	if [ "$step"    = "" -o \
	     "$host"    = "" -o \
	     "$typ"     = "" -o \
	     "$domname" = "" ]; then
	 	echo "Error: Parameter(s) missing (-step/-host/-type/-domname)" 1>&2
		echo "" 1>&2
		echo "$0 -help for usage." 1>&2
		exit 1
	fi

	filename="$dir/$typ$stype-migration.sh"
	if [ ! -r $filename ]; then
		echo "Error: Could not find script '$filename'"
		return
	fi
	. "$filename"

	if [ "$recover" = "1" ]; then
		func="$typ"_recover
		eval $func $host $domname $step $*
	else
		func="$typ"_migration_step
		eval $func $host $domname $step $*
	fi
}

evaluate_params "$@"
